#!/usr/bin/env python3
import json, sys, hashlib, pathlib, statistics, time
from collections import Counter
files=[pathlib.Path(p) for p in sys.argv[1:]]
if not files:
    files=sorted(pathlib.Path('upstream_d9d29d5_files/lpn_samples').glob('*.jsonl'))[:4]
seen=set(); dup=0
for fp in files:
    t0=time.time(); ys=[]; weights=[]; first_hash=[]; meta=None; rows=0
    with fp.open('r',encoding='utf-8') as f:
        meta=json.loads(next(f));
        for line in f:
            o=json.loads(line)
            y=o['y']; ahex=o['a']; b=bytes.fromhex(ahex)
            h=hashlib.blake2b(b,digest_size=16).digest()
            if h in seen: dup+=1
            seen.add(h)
            if len(first_hash)<3: first_hash.append(h.hex())
            ys.append(y); weights.append(int.from_bytes(b,'little').bit_count())
            rows+=1
    print(fp.name, 'rows',rows,'n',meta.get('n'),'t',meta.get('t'),'tau',f"{meta.get('tau_num')}/{meta.get('tau_den')}", 'y1',sum(ys),'y0',len(ys)-sum(ys), 'w_avg',round(statistics.mean(weights),2),'w_minmax',(min(weights),max(weights)),'meta_seed',meta.get('seed_ztag'),'T',meta.get('public_T_hex')[:12]+'...', 'hash0',first_hash, 'sec',round(time.time()-t0,2))
print('files',len(files),'unique_row_hashes',len(seen),'dups',dup)
