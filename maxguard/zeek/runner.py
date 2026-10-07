import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent / "scripts"

class ZeekError(RuntimeError):
    pass

def run_zeek(pcap: Path, out_dir: Path, timeout: int = 1800) -> Path:
    """Run Zeek on one capture file and write JSON logs into out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    extra = sorted(str(p) for p in SCRIPTS_DIR.glob("*.zeek"))  # Jakub's scripts
    cmd = ["zeek", "-C", "-r", str(pcap.resolve()), "local",
           "LogAscii::use_json=T", *extra]
    res = subprocess.run(cmd, cwd=out_dir, capture_output=True,
                         text=True, timeout=timeout)
    if res.returncode != 0:
        raise ZeekError(res.stderr.strip() or "zeek failed")
    if not (out_dir / "conn.log").exists():
        raise ZeekError("Zeek produced no conn.log: is this a valid capture?")
    return out_dir
