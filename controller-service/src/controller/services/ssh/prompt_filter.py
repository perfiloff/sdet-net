"""Detect and drop vtysh-style prompt-only lines from ``terminal monitor`` streams."""

from __future__ import annotations

import re

# ECMA-48 CSI: ESC [ params intermediates final (covers 256-color, truecolor, : subparams, [K, etc.)
_CSI = re.compile(r"\x1b\[[\x30-\x3F]*[\x20-\x2F]*[\x40-\x7E]")
_OSC = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")
_SINGLE = re.compile(r"\x1b[@-_]")


def _strip_ansi_for_match(s: str) -> str:
    """Remove ANSI escapes; repeat until stable (nested/overlapping patterns)."""
    out = s
    for _ in range(64):
        n = out
        n = _CSI.sub("", n)
        n = _OSC.sub("", n)
        n = _SINGLE.sub("", n)
        if n == out:
            break
        out = n
    return out


# Exec / config context: "host#", "host(config)#", "host(config-if)#"
_VTYSH_PROMPT_ONLY = re.compile(r"^[\w.:-]+(?:\([^)]*\))*[#>]\s*$")


def is_vtysh_prompt_only_line(line: str) -> bool:
    """True if *line* is only a vtysh CLI prompt (optionally with ANSI styling)."""
    plain = _strip_ansi_for_match(line).strip()
    if not plain:
        return False
    return bool(_VTYSH_PROMPT_ONLY.match(plain))


class VtyshMonitorLineFilter:
    """Buffer stdout chunks into lines; omit prompt-only lines."""

    def __init__(self) -> None:
        self._buf = ""

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        # vtysh often uses CR without LF for redraws; normalize so prompts become full lines.
        self._buf = self._buf.replace("\r\n", "\n").replace("\r", "\n")
        out: list[str] = []
        while "\n" in self._buf:
            i = self._buf.index("\n")
            raw_line = self._buf[:i]
            self._buf = self._buf[i + 1 :]
            line = raw_line.rstrip("\r\n")
            if not is_vtysh_prompt_only_line(line):
                out.append(line + "\n")
        return "".join(out)

    def flush(self) -> str:
        """Flush trailing data without a final newline (EOF)."""
        if not self._buf:
            return ""
        self._buf = self._buf.replace("\r\n", "\n").replace("\r", "\n")
        rest = self._buf.rstrip("\n")
        self._buf = ""
        if not rest:
            return ""
        if is_vtysh_prompt_only_line(rest):
            return ""
        return rest + "\n"
