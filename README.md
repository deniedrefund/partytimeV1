# ASIC Network Traffic Parser — Starter

This starter project inventories a PCAP/PCAPNG file and looks for a small set of
readable mining-related strings. It is a starting point, **not a completed ASIC
detector**. Mining strings can indicate mining-related traffic but do not prove
that the endpoint is dedicated ASIC hardware.

## 1. Requirements
- Python 3.10 or newer
- Dependencies in `requirements.txt`

## 2. Install
Open a terminal in this folder and run:

```bash
python -m pip install -r requirements.txt
```

On some Windows systems, use `py` instead of `python`:

```powershell
py -m pip install -r requirements.txt
```

## 3. Run
```bash
python parser.py "captures/example.pcapng" -o analysis.json
```

Windows alternative:
```powershell
py parser.py "captures\example.pcapng" -o analysis.json
```

Replace the example path with an actual capture file. The report is written to
`analysis.json`.

## 4. What the starter extracts
- Packet count and approximate capture duration
- IPv4/IPv6 packet appearances
- Common transport protocol counts
- Frequently observed IP addresses and ports
- A small number of readable mining-related payload strings
- Packet-level evidence for matched strings

## 5. Important limitations
- A mining-related string does not prove ASIC hardware.
- Port numbers alone are not proof.
- Encrypted, truncated, or partial captures can hide evidence.
- This starter has not been validated against the supplied training or validation
  sets. Do not report performance metrics until the complete validation set has
  actually been run.
- The first 20 packet summaries are examples only; findings retain their own
  evidence frames.

## 6. Next project steps
1. Read the supplied Dataset Guide.
2. Inspect representative training captures in Wireshark.
3. Build an evidence inventory from observed packet contents.
4. Develop and document evidence-based rules.
5. Evaluate all 35 validation captures and document false positives and false negatives.
6. Revise this README and write the final technical report based on actual results.
