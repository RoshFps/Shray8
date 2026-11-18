import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import collector  # noqa: E402

APT = """Reading package lists...
Inst libssl3 [3.0.1] (3.0.2 Debian-Security:12/stable-security [amd64])
Inst curl [7.88] (7.89 Debian:12.5/stable [amd64])
Inst vim [9.0] (9.1 Debian:12.5/stable [amd64])
Conf curl (7.89 Debian:12.5/stable [amd64])
"""


def test_parse_apt_simulation():
    assert collector.parse_apt_simulation(APT) == (1, 1, 2)
    assert collector.parse_apt_simulation("") == (0, 0, 0)


def test_os_name(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('NAME="Debian"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    assert collector.os_name(str(f)) == "Debian GNU/Linux 12 (bookworm)"
    assert collector.os_name(str(tmp_path / "missing")) == "Linux"


def test_read_processes_sees_itself():
    procs = collector.read_processes()
    assert any(pid == str(os.getpid()) for pid, _ in procs)
    assert all(cmd for _, cmd in procs.values())


def test_hostname_uses_department(monkeypatch):
    monkeypatch.delenv("COLLECTOR_HOSTNAME", raising=False)
    monkeypatch.setattr(collector, "DEPARTMENT", "Sales")
    assert collector.hostname().startswith("LNX-SALES-")
