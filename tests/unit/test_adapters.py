import json
from pathlib import Path
from maxguard.adapters.pcap import PcapAdapter
from maxguard.adapters.zeeklogs import ZeekLogAdapter

def test_pcap_adapter_accepts_and_rejects(tmp_path: Path):
    adapter = PcapAdapter()

    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1extra_dummy_bytes")

    pcapng_file = tmp_path / "test.pcapng"
    pcapng_file.write_bytes(b"\x0a\x0d\x0d\x0aextra_dummy_bytes")

    txt_file = tmp_path / "test.txt"
    txt_file.write_text("plain text file")

    assert adapter.accepts(pcap_file) is True
    assert adapter.accepts(pcapng_file) is True
    assert adapter.accepts(txt_file) is False
def test_zeek_log_adapter_converts_tsv_to_json(tmp_path: Path):
    adapter = ZeekLogAdapter()
    input_dir = tmp_path / "tsv_dir"
    input_dir.mkdir()

    tsv_content = (
        "#separator \\x09\n"
        "#set_separator ,\n"
        "#empty_field (empty)\n"
        "#unset_field -\n"
        "#fields\tts\tuid\tid.orig_h\tid.resp_p\n"
        "100.0\tC1\t192.168.1.1\t80\n"
        "101.0\tC2\t192.168.1.2\t443\n"
        "102.0\tC3\t192.168.1.3\t-\n"
    )
    conn_log = input_dir / "conn.log"
    conn_log.write_text(tsv_content)

    assert adapter.accepts(input_dir) is True

    workdir = tmp_path / "work"
    out_dir = adapter.to_zeek_logs(input_dir, workdir)

    result_log = out_dir / "conn.log"
    assert result_log.exists()

    lines = [line.strip() for line in result_log.read_text().strip().split("\n") if line.strip()]
    assert len(lines) == 3

    row1 = json.loads(lines[0])
    assert row1["uid"] == "C1"
    assert row1["id.resp_p"] == "80"

    row3 = json.loads(lines[2])
    assert row3["uid"] == "C3"
    assert row3["id.resp_p"] is None
