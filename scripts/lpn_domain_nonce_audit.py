#!/usr/bin/env python3
"""Audit public LPN sample metadata for domain/nonce coverage anomalies.

This does not solve LPN; it checks for implementation mistakes that would make
different PRF domains or target layers accidentally reuse a public AES-CTR nonce
or expose inconsistent bindings.
"""

from __future__ import annotations

import glob
import hashlib
import json
import pathlib
import re
from collections import Counter, defaultdict


ROOT = pathlib.Path(__file__).resolve().parent
SAMPLE_DIR = ROOT / "upstream_d9d29d5_files" / "lpn_samples"
DOMAINS = [
    "pvac.prf.r.1",
    "pvac.prf.r.2",
    "pvac.prf.r.3",
    "pvac.dom.toeplitz",
    "pvac.prf.noise.1",
    "pvac.prf.noise.2",
    "pvac.prf.noise.3",
]


def fnv1a_domain(dom: str) -> int:
    h = 0xCBF29CE484222325
    for b in dom.encode():
        h ^= b
        h = (h * 0x100000001B3) & ((1 << 64) - 1)
    return h


def parse_name(path: pathlib.Path) -> tuple[int, int, int, str]:
    m = re.fullmatch(r"ct(\d+)_l(\d+)_s(\d+)_pvac_prf_r_1\.jsonl", path.name)
    if not m:
        raise ValueError(f"unexpected filename {path.name}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), "pvac.prf.r.1"


def main() -> None:
    metas = []
    for path in sorted(SAMPLE_DIR.glob("*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            meta = json.loads(handle.readline())
        ci, li, slot, dom_from_name = parse_name(path)
        metas.append({"path": path, "ci": ci, "li": li, "slot": slot, "name_dom": dom_from_name, **meta})

    target_keys = [(m["ci"], m["li"], m["slot"]) for m in metas]
    target_counter = Counter(target_keys)
    missing = [(ci, li, 0) for ci in range(22) for li in range(2) if (ci, li, 0) not in target_counter]
    duplicates = [k for k, v in target_counter.items() if v != 1]

    seed_keys = [(m["seed_ztag"], m["nonce_lo_hex"], m["nonce_hi_hex"], m["public_T_hex"]) for m in metas]
    seed_duplicates = [k for k, v in Counter(seed_keys).items() if v != 1]

    row0_hashes = []
    for m in metas:
        with m["path"].open(encoding="utf-8") as handle:
            next(handle)
            first = json.loads(next(handle))
        row0_hashes.append(hashlib.blake2b(bytes.fromhex(first["a"]), digest_size=16).hexdigest())
    row0_dups = [k for k, v in Counter(row0_hashes).items() if v != 1]

    domain_hashes = {dom: fnv1a_domain(dom) for dom in DOMAINS}
    hash_dups = defaultdict(list)
    for dom, value in domain_hashes.items():
        hash_dups[value].append(dom)
    hash_collisions = {hex(k): v for k, v in hash_dups.items() if len(v) > 1}

    # derive_aes_key sets out_nonce = fnv(domain) xor seed.nonce.lo.
    # prf_R_core's Toeplitz stream then uses nonce = fnv(TOEP) xor seed.nonce.lo xor fnv(PRF_Rx).
    stream_nonce = defaultdict(list)
    for m in metas:
        lo = int(m["nonce_lo_hex"], 16)
        for dom in DOMAINS:
            base_nonce = domain_hashes[dom] ^ lo
            stream_nonce[("lpn", base_nonce)].append((m["path"].name, dom))
        for dom in ["pvac.prf.r.1", "pvac.prf.r.2", "pvac.prf.r.3"]:
            toep_nonce = domain_hashes["pvac.dom.toeplitz"] ^ lo ^ domain_hashes[dom]
            stream_nonce[("toep_for", toep_nonce)].append((m["path"].name, dom))
    nonce_collisions = {
        f"{kind}:{nonce:016x}": vals
        for (kind, nonce), vals in stream_nonce.items()
        if len(vals) > 1
    }

    y_ones = []
    for m in metas:
        ones = 0
        rows = 0
        with m["path"].open(encoding="utf-8") as handle:
            next(handle)
            for line in handle:
                row = json.loads(line)
                ones += int(row["y"])
                rows += 1
        y_ones.append((m["path"].name, rows, ones))

    print("# LPN domain/nonce metadata audit")
    print(f"samples={len(metas)} expected=44")
    print(f"targets_unique={len(target_counter)} missing={len(missing)} duplicates={len(duplicates)}")
    print(f"seed_bindings_unique={len(set(seed_keys))} seed_duplicates={len(seed_duplicates)}")
    print(f"domain_hashes=" + json.dumps({k: f"{v:016x}" for k, v in domain_hashes.items()}, sort_keys=True))
    print(f"domain_hash_collisions={len(hash_collisions)}")
    print(f"row0_duplicate_hashes={len(row0_dups)}")
    print(f"derived_stream_nonce_collisions={len(nonce_collisions)}")
    if nonce_collisions:
        for key, vals in list(nonce_collisions.items())[:20]:
            print("collision", key, vals[:6])
    print("y_range=" + str((min(v[2] for v in y_ones), max(v[2] for v in y_ones))))
    print("assessment=" + (
        "no filename coverage, domain-hash, seed-binding, row0, or derived-nonce anomaly detected"
        if len(metas) == 44 and not missing and not duplicates and not seed_duplicates and not hash_collisions and not row0_dups and not nonce_collisions
        else "investigate anomaly above"
    ))


if __name__ == "__main__":
    main()
