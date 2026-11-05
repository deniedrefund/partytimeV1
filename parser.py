#!/usr/bin/env python3
"""Starter PCAP/PCAPNG inventory and mining-indicator parser.

This starter reports observable traffic clues. It does NOT claim that a mining
indicator alone proves the presence of dedicated ASIC hardware.
"""
import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, Ether
except ImportError:
    print("Missing dependency. Install it with: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)

MINING_TERMS = (
    "mining.subscribe",
    "mining.authorize",
    "mining.submit",
    "mining.notify",
    "mining.set_difficulty",
    "getwork",
    "getblocktemplate",
    "stratum",
)

def safe_text(payload):
    """Return readable ASCII portions of payload, without assuming it is text."""
    if not payload:
        return ""
    return "".join(chr(b) if 32 <= b < 127 else " " for b in bytes(payload))

def analyze_capture(path: Path):
    protocol_counts = Counter()
    ip_counts = Counter()
    port_counts = Counter()
    findings = []
    packet_summaries = []
    total_packets = 0
    first_timestamp = None
    last_timestamp = None
    parse_errors = 0

    try:
        reader = PcapReader(str(path))
    except Exception as exc:
        raise ValueError(f"Could not open capture: {exc}") from exc

    with reader:
        for frame_no, packet in enumerate(reader, start=1):
            total_packets += 1
            try:
                timestamp = float(packet.time) if getattr(packet, "time", None) is not None else None
                if timestamp is not None:
                    first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
                    last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)

                src = dst = None
                if IP in packet:
                    src, dst = packet[IP].src, packet[IP].dst
                    protocol_counts["IPv4"] += 1
                elif IPv6 in packet:
                    src, dst = packet[IPv6].src, packet[IPv6].dst
                    protocol_counts["IPv6"] += 1

                if src:
                    ip_counts[src] += 1
                if dst:
                    ip_counts[dst] += 1

                proto = "Other"
                sport = dport = None
                payload = b""
                if TCP in packet:
                    proto = "TCP"
                    sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
                    payload = bytes(packet[TCP].payload)
                elif UDP in packet:
                    proto = "UDP"
                    sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
                    payload = bytes(packet[UDP].payload)
                elif DNS in packet:
                    proto = "DNS"
                protocol_counts[proto] += 1

                if sport is not None:
                    port_counts[str(sport)] += 1
                    port_counts[str(dport)] += 1

                if len(packet_summaries) < 20:
                    packet_summaries.append({
                        "frame": frame_no,
                        "timestamp_epoch": timestamp,
                        "source": src,
                        "destination": dst,
                        "transport": proto,
                        "source_port": sport,
                        "destination_port": dport,
                        "payload_bytes": len(payload),
                    })

                text = safe_text(payload).lower()
                matched = [term for term in MINING_TERMS if term in text]
                for term in matched:
                    findings.append({
                        "finding": "Mining-related protocol string observed",
                        "value": term,
                        "confidence": "low",
                        "evidence": [{
                            "frame": frame_no,
                            "timestamp_epoch": timestamp,
                            "source": src,
                            "destination": dst,
                            "transport": proto,
                            "source_port": sport,
                            "destination_port": dport,
                            "matched_text": term,
                        }],
                        "interpretation": (
                            "This string may indicate mining-related protocol activity. "
                            "It does not by itself identify an ASIC device."
                        ),
                    })
            except Exception:
                parse_errors += 1

    duration = None
    if first_timestamp is not None and last_timestamp is not None:
        duration = max(0.0, last_timestamp - first_timestamp)

    # Summarize repeated indicators while preserving the packet evidence.
    grouped = {}
    for item in findings:
        key = item["value"]
        if key not in grouped:
            grouped[key] = item
        else:
            grouped[key]["evidence"].extend(item["evidence"])

    if grouped:
        mining_observation = (
            "Mining-related strings were observed. Additional protocol and device "
            "evidence is needed before concluding that dedicated ASIC hardware is present."
        )
    else:
        mining_observation = (
            "No configured mining-related strings were detected in inspected transport payloads. "
            "This does not prove mining activity or ASIC hardware is absent; traffic may be encrypted, "
            "partial, or use different protocol messages."
        )

    return {
        "input_file": path.name,
        "capture_summary": {
            "packet_count": total_packets,
            "parse_error_count": parse_errors,
            "duration_seconds": duration,
            "first_timestamp_utc": datetime.fromtimestamp(first_timestamp, timezone.utc).isoformat() if first_timestamp is not None else None,
            "last_timestamp_utc": datetime.fromtimestamp(last_timestamp, timezone.utc).isoformat() if last_timestamp is not None else None,
        },
        "protocol_counts": dict(protocol_counts.most_common()),
        "top_ip_addresses_by_packet_appearance": [
            {"address": ip, "count": count} for ip, count in ip_counts.most_common(20)
        ],
        "top_ports_by_packet_appearance": [
            {"port": port, "count": count} for port, count in port_counts.most_common(20)
        ],
        "asic_assessment": {
            "status": "inconclusive",
            "summary": mining_observation,
            "reason": "This starter performs inventory and basic string checks, not validated ASIC classification.",
        },
        "findings": list(grouped.values()),
        "sample_packet_summaries_first_20": packet_summaries,
        "notes": [
            "This is a baseline parser, not a final validated detector.",
            "Port numbers and mining-related strings are clues, not proof of ASIC hardware.",
            "Encrypted traffic and missing packets can hide relevant evidence.",
            "Frame numbers refer to the input capture as read by this program.",
        ],
    }

def main():
    ap = argparse.ArgumentParser(description="Inventory a PCAP/PCAPNG and report basic mining-related clues.")
    ap.add_argument("capture", help="Path to a .pcap or .pcapng file")
    ap.add_argument("-o", "--output", help="JSON output path (default: analysis.json)")
    args = ap.parse_args()

    capture = Path(args.capture)
    if not capture.is_file():
        print(f"Input file not found: {capture}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else Path("analysis.json")
    try:
        result = analyze_capture(capture)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 1

    print(f"Analyzed {result['capture_summary']['packet_count']} packets.")
    print(f"JSON report written to: {output}")
    print("ASIC assessment: inconclusive (expected for this starter version).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
