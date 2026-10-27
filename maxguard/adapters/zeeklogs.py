import json
import shutil
import tarfile
import zipfile
from pathlib import Path

def _tsv_to_json(src: Path, dst: Path) -> None:
    fields, sep = None, "\t"
    with src.open() as fin, dst.open("w") as fout:
        for line in fin:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#") or not line:
                continue
            elif fields:
                vals = [None if v in ("-", "(empty)") else v for v in line.split(sep)]
                fout.write(json.dumps(dict(zip(fields, vals))) + "\n")

class ZeekLogAdapter:
    name = "zeek-logs"

    def accepts(self, path: Path) -> bool:
        return (path.is_dir() and (path / "conn.log").exists()) or \
               path.suffix == ".zip" or \
               path.name.endswith(".tar.gz")

    def to_zeek_logs(self, path: Path, workdir: Path) -> Path:
        src = workdir / "imported"
        if path.is_dir():
            shutil.copytree(path, src, dirs_exist_ok=True)
        elif path.suffix == ".zip":
            zipfile.ZipFile(path).extractall(src)
        else:
            try:
                tarfile.open(path).extractall(src, filter="data")
            except TypeError:
                tarfile.open(path).extractall(src)

        out = workdir / "zeek_logs"
        out.mkdir(parents=True, exist_ok=True)
        for log in src.rglob("*.log"):
            first = log.open().readline()
            if first.startswith("{"):
                shutil.copy(log, out / log.name)
            else:
                _tsv_to_json(log, out / log.name)
        return out
