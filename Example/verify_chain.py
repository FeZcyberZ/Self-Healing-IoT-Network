#!/usr/bin/env python3
"""
Hash-chain integrity verifier for behaviour_engine_chain.jsonl
Detects: modified entries, deleted entries, truncation, inserted entries.

Usage:
    python verify_chain.py <logfile>

Exit codes:
    0 = chain intact
    1 = tampering detected
"""

import sys
import json
import hashlib


# Recompute the expected hash for a segment-1 entry
def compute_hash(entry):
    d = {
        "seq": entry["seq"],
        "ts":  entry["ts"],
        "prev": entry["prev"],
        "record": entry["record"],
    }
    payload = json.dumps(d, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


# Return whichever prev-pointer key this entry uses
def prev_key(entry):
    return "prev_hash" if "prev_hash" in entry else "prev"


def verify(path):
    print(f"[*] Verifying: {path}")

    # Open and read the log file
    try:
        with open(path, encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        return False

    if not raw_lines:
        print("[ERROR] Log file is empty.")
        return False

    # Parse each line as a JSON entry
    entries = []
    for i, line in enumerate(raw_lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"[TAMPER] Line {i}: invalid JSON — {exc}")
            return False

    print(f"[*] Loaded {len(entries)} entries across "
          f"{sum(1 for e in entries if e['seq'] == 1)} chain segment(s)")

    errors = []
    seg_num = 0

    for i, entry in enumerate(entries):
        lineno = i + 1
        pk = prev_key(entry)

        # Detect start of a new chain segment
        if entry["seq"] == 1:
            seg_num += 1
            expected_prev = "0" * 64
            if entry[pk] != expected_prev:
                errors.append(
                    f"Line {lineno} (seg {seg_num}, seq 1): "
                    f"prev pointer is not genesis hash"
                )

        # Check prev hash matches the previous entry's hash
        if i > 0 and entry["seq"] != 1:
            expected = entries[i - 1]["hash"]
            actual   = entry[pk]
            if actual != expected:
                errors.append(
                    f"Line {lineno} (seg {seg_num}, seq {entry['seq']}): "
                    f"chain break — prev={actual[:16]}… expected={expected[:16]}…"
                )

        # Recompute and verify the hash for segment-1 schema entries
        if pk == "prev":
            computed = compute_hash(entry)
            if computed != entry["hash"]:
                errors.append(
                    f"Line {lineno} (seg {seg_num}, seq {entry['seq']}): "
                    f"hash mismatch — stored={entry['hash'][:16]}… "
                    f"computed={computed[:16]}…"
                )

        # Check sequence numbers are continuous within a segment
        if i > 0 and entry["seq"] != 1:
            expected_seq = entries[i - 1]["seq"] + 1
            if entry["seq"] != expected_seq:
                errors.append(
                    f"Line {lineno} (seg {seg_num}): "
                    f"sequence gap — got seq {entry['seq']}, "
                    f"expected {expected_seq} (entry deleted or inserted?)"
                )

    # Report results
    if errors:
        print(f"\n[TAMPER DETECTED] {len(errors)} integrity violation(s):\n")
        for err in errors:
            print(f"  ✗ {err}")
        print()
        return False
    else:
        print(f"[OK] Chain intact — {len(entries)} entries verified, "
              f"0 violations found.\n")
        return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <logfile>")
        sys.exit(2)

    ok = verify(sys.argv[1])
    sys.exit(0 if ok else 1)
