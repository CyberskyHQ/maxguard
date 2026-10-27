from pathlib import Path
from maxguard.zeek.runner import run_zeek

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",   # pcap
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",   # pcap (ns)
    b"\x0a\x0d\x0d\x0a"                         # pcapng
}

class PcapAdapter:
    name = "pcap"

    def accepts(self, path: Path) -> bool:
        if not path.is_file():
            return False
        with path.open("rb") as f:
            return f.read(4) in PCAP_MAGIC

    def to_zeek_logs(self, path: Path, workdir: Path) -> Path:
        return run_zeek(path, workdir / "zeek_logs")
