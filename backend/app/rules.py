"""Suspicious-process rules: command-line patterns that look like attacker technique."""

import re

# (pattern, reason). First match wins.
RULES = [
    (re.compile(r"base64\s+(-d|--decode)\b.*\|\s*(ba|da|z)?sh\b"), "Encoded shell command (base64 -d | sh)"),
    (re.compile(r"/dev/tcp/"), "Reverse-shell pattern (/dev/tcp)"),
    (re.compile(r"\b(curl|wget)\b.*(\|\s*(ba|da|z)?sh\b|-[oO]\s*/tmp/|>\s*/tmp/|\s/tmp/\S+)"), "Download-and-run from /tmp or pipe to shell"),
    (re.compile(r"\b(python[\d.]*|perl|ruby)\s+-[ce]\s"), "Scripted one-liner (python -c / perl -e)"),
    (re.compile(r"powershell(\.exe)?\s+.*-enc", re.I), "Encoded PowerShell command"),
    (re.compile(r"certutil(\.exe)?\s+.*-urlcache", re.I), "certutil used to download a file"),
    (re.compile(r"wmic(\.exe)?\s+process\s+call\s+create", re.I), "WMI used to start a process"),
    (re.compile(r"rundll32(\.exe)?\s+javascript:", re.I), "rundll32 running script code"),
]


def match_rule(command_line: str) -> str | None:
    """Return the reason this command line is suspicious, or None."""
    for pattern, reason in RULES:
        if pattern.search(command_line):
            return reason
    return None
