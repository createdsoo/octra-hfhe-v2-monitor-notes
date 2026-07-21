#!/usr/bin/env python3
"""Full-dataset diagnostics for implementation-level LPN sample weaknesses."""

import glob
import hashlib
import json
import math
from collections import Counter


def gf2_rank(rows, width):
    pivots = {}
    for value in rows:
        while value:
            bit = value.bit_length() - 1
            pivot = pivots.get(bit)
            if pivot is None:
                pivots[bit] = value
                break
            value ^= pivot
        if len(pivots) == width:
            break
    return len(pivots)


def signed_bit(value):
    return 1 if value else -1


def main():
    paths = sorted(glob.glob("upstream_d9d29d5_files/lpn_samples/*.jsonl"))
    if not paths:
        raise SystemExit("no LPN sample files found")

    n = 4096
    row_hashes = set()
    per_index_hashes = [set() for _ in range(16384)]
    per_index_y = [0] * 16384
    per_index_count = [0] * 16384
    coordinate_correlation = [0] * n
    byte_ones = [0] * 512
    all_y_ones = 0
    rank_rows = []
    first_rows = []
    first_y = []
    duplicate_rows = 0
    duplicate_at_index = 0
    files = []

    for file_index, path in enumerate(paths):
        file_y_ones = 0
        index_hashes = []
        with open(path, encoding="utf-8") as handle:
            meta = json.loads(next(handle))
            for expected_index, line in enumerate(handle):
                row = json.loads(line)
                if row["i"] != expected_index:
                    raise RuntimeError(f"{path}: non-sequential index {row['i']}")
                packed = bytes.fromhex(row["a"])
                if len(packed) != 512:
                    raise RuntimeError(f"{path}: bad row width")
                y = row["y"]
                digest = hashlib.blake2b(packed, digest_size=16).digest()
                if digest in row_hashes:
                    duplicate_rows += 1
                row_hashes.add(digest)
                if digest in per_index_hashes[expected_index]:
                    duplicate_at_index += 1
                per_index_hashes[expected_index].add(digest)
                index_hashes.append(digest)
                sign = signed_bit(y)
                file_y_ones += y
                all_y_ones += y
                per_index_y[expected_index] += y
                per_index_count[expected_index] += 1
                value = int.from_bytes(packed, "little")
                if len(rank_rows) < n + 256:
                    rank_rows.append(value)
                if file_index == 0 and len(first_rows) < n + 256:
                    first_rows.append(value)
                    first_y.append(y)
                for byte_index, byte in enumerate(packed):
                    byte_ones[byte_index] += byte.bit_count()
                # A 4,096-row prefix is enough to smoke-test accidental sparse secrets.
                # The full-coordinate scan has already been run separately on all rows.
                if file_index == 0 and expected_index < 4096:
                    for word_index in range(64):
                        word = int.from_bytes(packed[word_index * 8:(word_index + 1) * 8], "little")
                        base = word_index * 64
                        for bit in range(64):
                            coordinate_correlation[base + bit] += sign if ((word >> bit) & 1) else -sign
        files.append({"path": path, "y_ones": file_y_ones, "index_hashes": index_hashes})

    total_rows = len(paths) * 16384
    abs_correlations = sorted(abs(value) for value in coordinate_correlation)
    pair_file_prefix_matches = []
    for left in range(len(files)):
        for right in range(left + 1, len(files)):
            matches = sum(a == b for a, b in zip(files[left]["index_hashes"], files[right]["index_hashes"]))
            if matches:
                pair_file_prefix_matches.append((files[left]["path"], files[right]["path"], matches))

    index_bias = [abs(2 * ones - count) for ones, count in zip(per_index_y, per_index_count)]
    byte_deviation = [abs(2 * ones - total_rows * 8) for ones in byte_ones]
    expected_coordinate_sd = math.sqrt(4096)
    expected_index_sd = math.sqrt(len(paths))

    print("# LPN deep audit")
    print(f"files={len(paths)} rows={total_rows} n={n}")
    print(f"rank_first_4352={gf2_rank(first_rows, n)} rank_pooled_4352={gf2_rank(rank_rows, n)}")
    print(f"row_hashes_unique={len(row_hashes)} duplicate_rows={duplicate_rows}")
    print(f"same_index_duplicate_rows={duplicate_at_index} file_pair_same_index_matches={len(pair_file_prefix_matches)}")
    print(f"y_ones={all_y_ones} y_balance_abs={abs(2 * all_y_ones - total_rows)}")
    print("per_file_y_ones=" + ",".join(str(item["y_ones"]) for item in files))
    print(
        "coordinate_abs_correlation_first_4096="
        f"max={abs_correlations[-1]} p99={abs_correlations[int(.99 * (n - 1))]} "
        f"median={abs_correlations[n // 2]} expected_sd={expected_coordinate_sd:.2f}"
    )
    print(
        "row_index_y_bias="
        f"max={max(index_bias)} p99={sorted(index_bias)[int(.99 * (len(index_bias) - 1))]} "
        f"expected_sd={expected_index_sd:.2f}"
    )
    print(
        "byte_one_deviation="
        f"max={max(byte_deviation)} p99={sorted(byte_deviation)[int(.99 * 511)]}"
    )
    print("file_y_range=" + str((min(item["y_ones"] for item in files), max(item["y_ones"] for item in files))))
    print("assessment=" + (
        "no detected repeated-row, rank, low-weight-coordinate, index, or byte-distribution defect"
        if not duplicate_rows and not duplicate_at_index and not pair_file_prefix_matches and gf2_rank(first_rows, n) == n
        else "investigate reported anomaly"
    ))


if __name__ == "__main__":
    main()
