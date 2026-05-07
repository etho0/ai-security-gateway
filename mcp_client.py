"""
mcp_client.py
-------------
Connects Claude API to @modelcontextprotocol/server-filesystem
via real MCP JSON-RPC over stdio, with our security policy intercepting
every tool call before it reaches the filesystem.

Real MCP flow:
  1. Spawn server-filesystem as stdio subprocess
  2. MCP initialize handshake (required by spec)
  3. tools/list — discover what tools the server exposes
  4. For each user message:
       a. Send to Claude API with discovered tool definitions
       b. If Claude calls a tool → mcp_policy.evaluate() first
       c. BLOCK → denial returned to Claude, filesystem never called
       d. ALLOW → tools/call sent to MCP server over stdio
       e. Result returned to Claude
  5. Continue until Claude produces final text response

This reproduces the vulnerable pattern from CVE-2025-49596 and the
OX Security MCP STDIO advisory — public web UI connected to a local
MCP stdio server — except our policy layer intercepts every tool call.
"""

import json
import subprocess
import threading
import requests
import os
import time
from typing import Optional
from dotenv import load_dotenv

from mcp_policy import evaluate, Decision

load_dotenv()

# ── Config ─────────────────────────────────────────────────────────────

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"
GEN_MODEL          = "anthropic/claude-3.5-haiku"

HEADERS = {
    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
    "Content-Type":  "application/json",
    "HTTP-Referer":  "https://mcp-security-gateway.local",
    "X-Title":       "MCP Security Gateway",
}

# Directory the filesystem MCP server is allowed to access
# Adjust this to whatever directory you want Claude to work in
MCP_ALLOWED_DIR = os.path.expanduser("~/Desktop")


# ══════════════════════════════════════════════════════════════════════
# Real MCP stdio client
# Speaks JSON-RPC 2.0 over stdin/stdout to server-filesystem
# ══════════════════════════════════════════════════════════════════════

class MCPFilesystemClient:
    """
    Spawns @modelcontextprotocol/server-filesystem as a stdio subprocess
    and communicates with it using the MCP JSON-RPC protocol.

    The MCP protocol requires:
      1. initialize request  → server responds with capabilities
      2. initialized notification → client confirms ready
      3. tools/list          → get available tools
      4. tools/call          → execute a tool

    All tools/call requests pass through mcp_policy.evaluate() first.
    """

    def __init__(self, allowed_dir: str = MCP_ALLOWED_DIR):
        self.allowed_dir  = allowed_dir
        self.process:     Optional[subprocess.Popen] = None
        self.lock         = threading.Lock()
        self._req_id      = 0
        self._tools:      list[dict] = []
        self._ready       = False

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _send(self, obj: dict) -> None:
        """Write a JSON-RPC message to the server's stdin."""
        line = json.dumps(obj) + "\n"
        self.process.stdin.write(line)
        self.process.stdin.flush()

    def _recv(self, timeout: float = 10.0) -> Optional[dict]:
        """
        Read one JSON-RPC message from the server's stdout.
        The server writes one JSON object per line.
        """
        self.process.stdout._sock = None if hasattr(self.process.stdout, '_sock') else None
        try:
            # Use readline with a manual timeout via select
            import select
            ready, _, _ = select.select([self.process.stdout], [], [], timeout)
            if ready:
                line = self.process.stdout.readline()
                if line:
                    return json.loads(line.strip())
        except Exception as e:
            print(f"[MCP RECV ERROR] {e}")
        return None

    def start(self) -> bool:
        """
        Spawn the MCP filesystem server and complete the initialize handshake.
        Returns True if ready, False if startup failed.
        """
        try:
            self.process = subprocess.Popen(
                ["npx", "-y", "@modelcontextprotocol/server-filesystem", self.allowed_dir],
                stdin  = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                text   = True,
                bufsize = 1,
            )

            # Give the server a moment to start
            time.sleep(1.5)

            if self.process.poll() is not None:
                print("[MCP] Server process exited early")
                return False

            # ── Step 1: initialize request ─────────────────────────────
            self._send({
                "jsonrpc": "2.0",
                "id":      self._next_id(),
                "method":  "initialize",
                "params":  {
                    "protocolVersion": "2024-11-05",
                    "capabilities":    {"tools": {}},
                    "clientInfo":      {
                        "name":    "mcp-security-gateway",
                        "version": "1.0.0",
                    },
                },
            })

            init_response = self._recv(timeout=10.0)
            if not init_response:
                print("[MCP] No initialize response")
                return False

            # ── Step 2: initialized notification ──────────────────────
            # This is a notification (no id) — required by MCP spec
            self._send({
                "jsonrpc": "2.0",
                "method":  "notifications/initialized",
            })

            # ── Step 3: discover tools ─────────────────────────────────
            self._send({
                "jsonrpc": "2.0",
                "id":      self._next_id(),
                "method":  "tools/list",
                "params":  {},
            })

            tools_response = self._recv(timeout=10.0)
            if tools_response and "result" in tools_response:
                self._tools = tools_response["result"].get("tools", [])
                print(f"[MCP] Server ready — {len(self._tools)} tools discovered:")
                for t in self._tools:
                    print(f"       • {t['name']}")
            else:
                print("[MCP] Could not discover tools")
                return False

            self._ready = True
            return True

        except FileNotFoundError:
            print("[MCP] npx not found — install Node.js first")
            return False
        except Exception as e:
            print(f"[MCP] Startup error: {e}")
            return False

    def get_tool_definitions(self) -> list[dict]:
        """
        Convert MCP tool schemas to OpenAI-compatible tool definitions
        for Claude API. Claude uses these to decide which tools to call.
        """
        definitions = []
        for tool in self._tools:
            definitions.append({
                "type": "function",
                "function": {
                    "name":        tool["name"],
                    "description": tool.get("description", ""),
                    "parameters":  tool.get("inputSchema", {
                        "type":       "object",
                        "properties": {},
                    }),
                },
            })
        return definitions

    def call_tool(self, tool_name: str, tool_input: dict) -> str:
        """
        Send a tools/call request to the MCP server.
        Only called after mcp_policy.evaluate() returns ALLOW.
        Returns the tool result as a string.
        """
        if not self._ready:
            return "MCP server not ready"

        with self.lock:
            req_id = self._next_id()
            self._send({
                "jsonrpc": "2.0",
                "id":      req_id,
                "method":  "tools/call",
                "params":  {
                    "name":      tool_name,
                    "arguments": tool_input,
                },
            })

            response = self._recv(timeout=30.0)

            if not response:
                return "No response from MCP server"

            if "error" in response:
                err = response["error"]
                return f"MCP error {err.get('code', '')}: {err.get('message', 'Unknown error')}"

            result  = response.get("result", {})
            content = result.get("content", [])

            # MCP content is a list of typed blocks
            # Extract all text blocks and join them
            parts = []
            for block in content:
                if block.get("type") == "text":
                    parts.append(block.get("text", ""))
                elif block.get("type") == "resource":
                    # File content returned as resource
                    resource = block.get("resource", {})
                    parts.append(resource.get("text", ""))

            return "\n".join(parts) if parts else "(no output)"

    def stop(self):
        if self.process:
            self.process.terminate()
            self._ready = False
            self.process = None


# ── Singleton client instance ──────────────────────────────────────────
_mcp = MCPFilesystemClient()


def init_server() -> bool:
    """Call once at Streamlit app startup."""
    return _mcp.start()


# ── Claude API call ────────────────────────────────────────────────────

def _call_claude(messages: list, tools: list = None) -> dict:
    body = {
        "model":       GEN_MODEL,
        "messages":    messages,
        "temperature": 0.3,
    }
    if tools:
        body["tools"] = tools

    try:
        resp = requests.post(
            OPENROUTER_URL,
            headers = HEADERS,
            json    = body,
            timeout = 60,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e}"}
    except Exception as e:
        return {"error": str(e)}


# ── Main entry point ───────────────────────────────────────────────────

def run_with_tools(
    user_message:         str,
    conversation_history: list,
    system_prompt:        str = None,
) -> dict:
    """
    Send a user message to Claude with MCP filesystem tools available.
    Every tool call is intercepted by mcp_policy before reaching the server.

    Returns:
        {
            "response":   str,   Claude's final text response
            "tool_calls": list,  all attempted tool calls with policy decisions
            "error":      str,   error message if something failed
        }
    """
    if not OPENROUTER_API_KEY:
        return {"response": "", "tool_calls": [], "error": "OPENROUTER_API_KEY not set"}

    if not _mcp._ready:
        return {
            "response":   "",
            "tool_calls": [],
            "error":      "MCP server not ready. Check that Node.js is installed and try restarting.",
        }

    sp = system_prompt or (
        f"You are a helpful assistant with access to filesystem tools. "
        f"You can read, list, and search files in: {MCP_ALLOWED_DIR}. "
        f"Always tell the user what you're about to do before doing it. "
        f"Never attempt to access files outside your allowed directory."
    )

    messages = [{"role": "system", "content": sp}]
    messages += conversation_history
    messages.append({"role": "user", "content": user_message})

    # Get current tool definitions from MCP server
    tool_definitions = _mcp.get_tool_definitions()
    tool_calls_log   = []
    max_iterations   = 8

    for iteration in range(max_iterations):

        data = _call_claude(messages, tools=tool_definitions)

        if "error" in data:
            return {"response": "", "tool_calls": tool_calls_log, "error": data["error"]}

        choices = data.get("choices", [])
        if not choices:
            return {"response": "", "tool_calls": tool_calls_log, "error": "No response from Claude"}

        message    = choices[0].get("message", {})
        finish     = choices[0].get("finish_reason", "")
        content    = message.get("content", "") or ""
        tool_calls = message.get("tool_calls", [])

        # ── Claude finished — return text ──────────────────────────────
        if finish == "stop" or not tool_calls:
            return {
                "response":   content,
                "tool_calls": tool_calls_log,
                "error":      "",
            }

        # ── Claude wants to call tools ─────────────────────────────────
        messages.append({
            "role":       "assistant",
            "content":    content,
            "tool_calls": tool_calls,
        })

        for tc in tool_calls:
            fn        = tc.get("function", {})
            tool_name = fn.get("name", "")
            tool_id   = tc.get("id", "")

            try:
                tool_input = json.loads(fn.get("arguments", "{}"))
            except json.JSONDecodeError:
                tool_input = {}

            # ── Build a human-readable command string for the policy ───
            # mcp_policy expects a "command" that represents what's being done
            # For filesystem tools we reconstruct a readable representation
            command_str = _tool_to_command(tool_name, tool_input)

            # ── POLICY CHECK ───────────────────────────────────────────
            policy_result = evaluate(tool_name, {
                "command": command_str,
                **tool_input,
            })

            call_record = {
                "tool_name":    tool_name,
                "command":      command_str,
                "tool_input":   tool_input,
                "decision":     policy_result.decision.value,
                "risk_level":   policy_result.risk_level.value,
                "reason":       policy_result.reason,
                "block_reason": policy_result.block_reason.value if policy_result.block_reason else None,
                "matched_rule": policy_result.matched_rule,
                "timestamp":    policy_result.timestamp,
            }
            tool_calls_log.append(call_record)

            if policy_result.decision == Decision.BLOCK:
                # ── BLOCKED — MCP server never called ─────────────────
                tool_result_content = (
                    f"[MCP SECURITY GATEWAY — BLOCKED]\n"
                    f"Tool: {tool_name}\n"
                    f"Reason: {policy_result.reason}\n"
                    f"Rule: {policy_result.matched_rule or 'policy'}\n"
                    f"Risk level: {policy_result.risk_level.value}\n"
                    f"The operation was NOT executed."
                )
            else:
                # ── ALLOWED — forward to MCP server over stdio ─────────
                tool_result_content = _mcp.call_tool(tool_name, tool_input)

            # Add tool result to history so Claude can continue
            messages.append({
                "role":         "tool",
                "tool_call_id": tool_id,
                "content":      tool_result_content,
            })

    return {
        "response":   "I reached the maximum number of tool calls for this request.",
        "tool_calls": tool_calls_log,
        "error":      "",
    }


def _tool_to_command(tool_name: str, tool_input: dict) -> str:
    """
    Convert an MCP filesystem tool call to a human-readable command string.
    This is what mcp_policy evaluates — it needs to look like a shell command
    so the policy rules (which check for dangerous patterns) work correctly.
    """
    path = (
        tool_input.get("path")
        or tool_input.get("source")
        or tool_input.get("destination")
        or ""
    )

    mapping = {
        "read_file":        f"cat {path}",
        "write_file":       f"write to {path}",
        "create_directory": f"mkdir {path}",
        "list_directory":   f"ls -la {path}",
        "move_file":        f"mv {tool_input.get('source','')} {tool_input.get('destination','')}",
        "search_files":     f"find {path} -name {tool_input.get('pattern','')}",
        "get_file_info":    f"stat {path}",
        "delete_file":      f"rm {path}",
        "directory_tree":   f"ls -R {path}",
    }

    return mapping.get(tool_name, f"{tool_name} {path}")
