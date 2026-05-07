"""
mcp_policy.py
-------------
MCP Security Policy Layer for ai-security-gateway.

Updated for @modelcontextprotocol/server-filesystem tools.
The filesystem server exposes these tools:
  read_file        — reads a file's content
  write_file       — creates or overwrites a file
  create_directory — makes a new directory
  list_directory   — lists directory contents
  move_file        — moves or renames a file
  search_files     — searches for files by name pattern
  get_file_info    — returns file metadata
  delete_file      — deletes a file (if server exposes it)
  directory_tree   — recursive directory listing

Threat model:
  The danger is NOT bash execution (server-filesystem can't run commands).
  The danger IS what files Claude reads and writes:
    - Reading .env, id_rsa, .aws/credentials → credential theft
    - Writing to system paths               → system compromise
    - Reading outside allowed directory     → data exfiltration
    - Deleting files                        → data destruction
    - Path traversal in any argument        → sandbox escape

Policy evaluation order:
  1. Tool allowlist       — only server-filesystem tools allowed
  2. Destructive tools    — write_file / delete_file need extra scrutiny
  3. Path traversal       — block ../../ in any argument
  4. Restricted paths     — sensitive files always blocked regardless of tool
  5. Write path rules     — restrict where Claude can write
  6. Risk scoring         — LOW / MEDIUM / HIGH / CRITICAL on allowed ops

Each decision is logged with full context for the MCP Security tab.
"""

import re
import json
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

# ── Enums ──────────────────────────────────────────────────────────────

class Decision(str, Enum):
    ALLOW    = "ALLOW"
    BLOCK    = "BLOCK"

class RiskLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

class BlockReason(str, Enum):
    TOOL_NOT_ALLOWED      = "Tool not in allowlist"
    DESTRUCTIVE_OPERATION = "Destructive file operation"
    PATH_TRAVERSAL        = "Path traversal detected"
    RESTRICTED_PATH       = "Access to restricted path"
    SENSITIVE_FILE        = "Sensitive file access"
    RESTRICTED_WRITE_PATH = "Write to restricted path"
    WRITE_SYSTEM_FILE     = "Write to system file"
    CREDENTIAL_FILE       = "Credential file access"

# ── Policy decision result ─────────────────────────────────────────────

@dataclass
class PolicyResult:
    decision:     Decision
    risk_level:   RiskLevel
    tool_name:    str
    command:      str          # human-readable representation of the operation
    reason:       str
    block_reason: Optional[BlockReason] = None
    matched_rule: Optional[str]         = None
    timestamp:    str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decision"]     = self.decision.value
        d["risk_level"]   = self.risk_level.value
        d["block_reason"] = self.block_reason.value if self.block_reason else None
        return d

# ══════════════════════════════════════════════════════════════════════
# POLICY CONFIGURATION
# ══════════════════════════════════════════════════════════════════════

# ── Tool allowlist ─────────────────────────────────────────────────────
# Exact tool names exposed by @modelcontextprotocol/server-filesystem.
# Any tool not in this set is blocked immediately — including any future
# tools added to the server that we haven't reviewed yet.

ALLOWED_TOOLS = {
    # ── Read operations ────────────────────────────────────────────────
    "read_file",                  # read any file — path-restricted below
    "read_text_file",             # read text file explicitly
    "read_media_file",            # read image/audio/video file
    "read_multiple_files",        # read several files at once

    # ── Write operations ───────────────────────────────────────────────
    "write_file",                 # create or overwrite a file
    "edit_file",                  # partial edit / find-replace in file

    # ── Directory operations ───────────────────────────────────────────
    "create_directory",           # make a new directory
    "list_directory",             # list directory contents
    "list_directory_with_sizes",  # list with file sizes
    "directory_tree",             # recursive listing — read-only

    # ── File management ────────────────────────────────────────────────
    "move_file",                  # move or rename
    "search_files",               # search by name pattern
    "get_file_info",              # metadata only — read-only, safe
    "list_allowed_directories",   # shows sandbox root — always safe
    "delete_file",                # delete a file — path-restricted below
}

# ── Destructive tools — require extra path checks ──────────────────────
# These tools can cause irreversible damage. Any path argument is checked
# against RESTRICTED_PATHS and WRITE_RESTRICTED_PATHS before allowing.
DESTRUCTIVE_TOOLS = {
    "write_file",    # overwrites files
    "edit_file",     # modifies file content
    "move_file",     # can overwrite destination
    "delete_file",   # permanent deletion
}

# ── Restricted paths — BLOCK for ALL tools ────────────────────────────
# Reading OR writing any of these paths is always denied.
# These are files that contain credentials or system configuration.
# Checked as substring match (case-insensitive) against full path.

RESTRICTED_PATHS = [
    # Credentials
    ".env",
    ".env.local",
    ".env.production",
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/authorized_keys",
    "credentials.json",
    "secrets.json",
    "service_account.json",

    # system paths — block reads AND writes
    "/etc/",               # Linux: /etc/hosts, /etc/passwd, /etc/crontab etc.
    "/private/etc/",       # macOS equivalent of /etc/
    "/private/var/db",
    "/library/keychains",
    "/System/",            # macOS system files

    # Private key files (by extension)
    ".pem",
    ".p12",
    ".pfx",
    ".key",
    ".keystore",

    # Common config files with secrets
    "wp-config.php",
    "database.yml",
    "secrets.yml",
    "config/master.key",    # Rails master key
    ".netrc",
    ".pgpass",
    "htpasswd",
]

# ── Write-restricted paths — BLOCK for write_file / move_file ─────────
# These paths are safe to READ but must never be written to.
# Prevents Claude from modifying system or application config.

WRITE_RESTRICTED_PATHS = [
    "/etc/",
    "/System/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/private/",
    "/Library/",
    "/Applications/",
    "~/.ssh/",
    "~/.aws/",
    "/var/",
    "/tmp/",          # prevent temp file staging for exfiltration
]

# ── Path traversal patterns ────────────────────────────────────────────
# These bypass the allowed directory sandbox.

TRAVERSAL_PATTERNS = [
    r"\.\./\.\./",          # ../../
    r"\.\.[/\\]",           # ../ or ..\
    r"%2e%2e[%2f%5c]",     # URL encoded
    r"\.\.%2f",             # mixed encoding
]

# ── Sensitive filename patterns ────────────────────────────────────────
# Filenames that suggest credential content — blocked for read_file.
# Checked against the filename portion of the path only.

SENSITIVE_FILENAME_PATTERNS = [
    r"^\.env",                    # .env, .env.local etc
    r"id_(rsa|dsa|ecdsa|ed25519)",# SSH keys
    r".*\.pem$",                  # PEM certificates
    r".*\.key$",                  # private keys
    r"credentials",               # any credentials file
    r"secrets?",                  # any secrets file
    r".*password.*",              # any password file
    r".*token.*",                 # any token file
    r".*api.?key.*",              # any api key file
    r".*\.p12$|.*\.pfx$",        # certificate bundles
    r"keystore",                  # Java keystores
    r"master\.key",               # Rails master key
]


# ── In-memory event log ────────────────────────────────────────────────

_event_log: list[dict] = []
MAX_LOG_ENTRIES = 200


def _log_event(result: PolicyResult) -> None:
    global _event_log
    _event_log.append(result.to_dict())
    if len(_event_log) > MAX_LOG_ENTRIES:
        _event_log = _event_log[-MAX_LOG_ENTRIES:]


def get_event_log() -> list[dict]:
    """Return all logged policy decisions, newest first."""
    return list(reversed(_event_log))


def clear_event_log() -> None:
    global _event_log
    _event_log = []


# ── Helpers ────────────────────────────────────────────────────────────

def _all_paths(tool_input: dict) -> list[str]:
    """
    Extract all path values from a tool input.
    Handles single path keys and read_multiple_files paths list.
    """
    keys = ["path", "source", "destination", "directory"]
    paths = []
    for k in keys:
        v = tool_input.get(k, "")
        if v:
            paths.append(str(v))
    # read_multiple_files passes a list of paths
    for p in tool_input.get("paths", []):
        if p:
            paths.append(str(p))
    return paths


def _filename(path: str) -> str:
    """Return just the filename from a path."""
    return os.path.basename(path).lower()


def _human_readable(tool_name: str, tool_input: dict) -> str:
    """
    Build a human-readable string for the MCP Security tab display.
    Shows what the tool is actually doing.
    """
    p    = tool_input.get("path", "")
    src  = tool_input.get("source", "")
    dst  = tool_input.get("destination", "")
    pat  = tool_input.get("pattern", "")
    content_preview = str(tool_input.get("content", ""))[:40]

    mapping = {
        "read_file":                 f"read_file({p})",
        "read_text_file":            f"read_text_file({p})",
        "read_media_file":           f"read_media_file({p})",
        "read_multiple_files":       f"read_multiple_files({tool_input.get('paths', [])})",
        "write_file":                f"write_file({p}, content='{content_preview}...')" if content_preview else f"write_file({p})",
        "edit_file":                 f"edit_file({p})",
        "create_directory":          f"create_directory({p})",
        "list_directory":            f"list_directory({p})",
        "list_directory_with_sizes": f"list_directory_with_sizes({p})",
        "move_file":                 f"move_file({src} → {dst})",
        "search_files":              f"search_files({p}, pattern='{pat}')",
        "get_file_info":             f"get_file_info({p})",
        "directory_tree":            f"directory_tree({p})",
        "delete_file":               f"delete_file({p})",
        "list_allowed_directories":  "list_allowed_directories()",
    }
    return mapping.get(tool_name, f"{tool_name}({json.dumps(tool_input)})")


def _score_risk(tool_name: str, tool_input: dict) -> RiskLevel:
    """
    Score risk of tool calls that passed all block rules.
    Based on tool type and path characteristics.
    """
    # Destructive tools are always at least HIGH
    if tool_name in DESTRUCTIVE_TOOLS:
        return RiskLevel.HIGH

    paths = _all_paths(tool_input)
    for path in paths:
        path_lower = path.lower()
        # Reading from home directory subdirs — medium
        if any(p in path_lower for p in ["~/.", "/.", "config", "local"]):
            return RiskLevel.MEDIUM

    # Read-only ops on normal paths
    if tool_name in {"read_file", "read_text_file", "read_media_file", "read_multiple_files"}:
        return RiskLevel.MEDIUM

    # Listings and metadata — low risk
    return RiskLevel.LOW


# ══════════════════════════════════════════════════════════════════════
# CORE POLICY EVALUATION
# ══════════════════════════════════════════════════════════════════════

def evaluate(tool_name: str, tool_input: dict) -> PolicyResult:
    """
    Evaluate a filesystem tool call against the security policy.

    Args:
        tool_name:  MCP tool name (e.g. "read_file", "write_file")
        tool_input: Tool arguments dict (e.g. {"path": "/Desktop/file.txt"})

    Returns:
        PolicyResult — logged automatically for MCP Security tab.
    """
    command_str = _human_readable(tool_name, tool_input)
    paths       = _all_paths(tool_input)

    def block(reason: str, br: BlockReason, rule: str, risk: RiskLevel = RiskLevel.HIGH) -> PolicyResult:
        result = PolicyResult(
            decision     = Decision.BLOCK,
            risk_level   = risk,
            tool_name    = tool_name,
            command      = command_str,
            reason       = reason,
            block_reason = br,
            matched_rule = rule,
        )
        _log_event(result)
        return result

    # ── Rule 1: Tool allowlist ─────────────────────────────────────────
    if tool_name not in ALLOWED_TOOLS:
        return block(
            f"Tool '{tool_name}' is not in the allowed tools list",
            BlockReason.TOOL_NOT_ALLOWED,
            "ALLOWLIST",
        )

    # ── Rule 2: Path traversal in any argument ─────────────────────────
    # Check all path arguments — an attacker might put ../../ in any field
    all_args_str = json.dumps(tool_input).lower()
    for pattern in TRAVERSAL_PATTERNS:
        if re.search(pattern, all_args_str, re.IGNORECASE):
            return block(
                "Path traversal sequence detected in tool arguments",
                BlockReason.PATH_TRAVERSAL,
                "TRAVERSAL",
                RiskLevel.CRITICAL,
            )

    # ── Rule 3: Restricted paths — block all tools ─────────────────────
    for path in paths:
        path_lower = path.lower()
        for restricted in RESTRICTED_PATHS:
            if restricted.lower() in path_lower:
                return block(
                    f"Access to restricted path: {restricted}",
                    BlockReason.RESTRICTED_PATH,
                    "PATH_POLICY",
                )

    # ── Rule 4: Sensitive filename patterns — block read_file ──────────
    # Even if the path isn't in RESTRICTED_PATHS, flag suspicious filenames
    if tool_name in {"read_file", "read_text_file", "read_media_file", "read_multiple_files"}:
        for path in paths:
            fname = _filename(path)
            for pattern in SENSITIVE_FILENAME_PATTERNS:
                if re.search(pattern, fname, re.IGNORECASE):
                    return block(
                        f"Sensitive filename pattern: {fname}",
                        BlockReason.SENSITIVE_FILE,
                        "FILENAME_POLICY",
                    )

    # ── Rule 5: Write-restricted paths — block write/move/delete ───────
    if tool_name in DESTRUCTIVE_TOOLS:
        for path in paths:
            path_lower = path.lower()

            # Expand ~ for comparison
            expanded = os.path.expanduser(path_lower)

            for restricted in WRITE_RESTRICTED_PATHS:
                expanded_restricted = os.path.expanduser(restricted.lower())
                if expanded.startswith(expanded_restricted) or restricted.lower() in path_lower:
                    return block(
                        f"Write/delete operation on restricted path: {restricted}",
                        BlockReason.RESTRICTED_WRITE_PATH,
                        "WRITE_POLICY",
                    )

    # ── Rule 6: delete_file is always HIGH risk — require explicit path ─
    if tool_name == "delete_file":
        path = tool_input.get("path", "")
        if not path or path.strip() in ["", ".", "*", "/"]:
            return block(
                "delete_file called with empty or wildcard path",
                BlockReason.DESTRUCTIVE_OPERATION,
                "DELETE_POLICY",
                RiskLevel.CRITICAL,
            )

    # ── All rules passed — ALLOW with risk score ───────────────────────
    risk = _score_risk(tool_name, tool_input)
    result = PolicyResult(
        decision   = Decision.ALLOW,
        risk_level = risk,
        tool_name  = tool_name,
        command    = command_str,
        reason     = "Passed all policy rules",
    )
    _log_event(result)
    return result


# ── Policy summary stats ───────────────────────────────────────────────

def get_stats() -> dict:
    log     = _event_log
    total   = len(log)
    blocked = sum(1 for e in log if e["decision"] == "BLOCK")
    allowed = total - blocked

    by_risk: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    by_rule: dict[str, int] = {}

    for e in log:
        by_risk[e["risk_level"]] = by_risk.get(e["risk_level"], 0) + 1
        if e.get("matched_rule"):
            r = e["matched_rule"]
            by_rule[r] = by_rule.get(r, 0) + 1

    top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total":      total,
        "blocked":    blocked,
        "allowed":    allowed,
        "block_rate": f"{blocked/total*100:.0f}%" if total else "0%",
        "by_risk":    by_risk,
        "top_rules":  top_rules,
    }
