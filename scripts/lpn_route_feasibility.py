#!/usr/bin/env python3
import math, json, time, glob, pathlib
n=4096
m=720896
tau=1/8
beta=1-2*tau
print(f'# LPN route feasibility {time.strftime("%Y-%m-%d %H:%M:%S %Z")}')
print(f'n={n} m={m} tau={tau:.6f} beta=1-2*tau={beta:.6f}')
print('\n## Pairwise-XOR/BKW signal budget')
print('stage r combines 2^r original rows; noise bias becomes beta^(2^r); sample count upper bound m/2^r; SNR proxy = sqrt(samples)*bias')
for r in range(0,13):
    k=2**r
    mr=m/(2**r)
    bias=beta**k
    snr=math.sqrt(mr)*bias
    print(f'r={r:2d} originals={k:5d} samples<= {mr:10.1f} bias={bias:.3e} snr_proxy={snr:.3e}')
print('\n## Collision block sizes')
print('For a BKW table on b eliminated coordinates, expected bucket load is m/2^b before pairing.')
for b in [12,14,16,18,19,20,22,24,32,64,128,256,512,1024]:
    load=m/(2**b) if b<1024 else 0.0
    print(f'b={b:4d} expected_load={load:.6g}')
print('\n## Interpretation')
# max stages with snr proxy >=5
max_r=-1
for r in range(0,30):
    k=2**r; mr=m/(2**r); bias=beta**k; snr=math.sqrt(mr)*bias
    if snr>=5: max_r=r
print(f'- Usable pairwise stages by a generous SNR>=5 rule: r <= {max_r}.')
print('- With m about 2^19.46, practical collision block size is below ~19 bits per stage; even four useful stages eliminate <80 coordinates, far from n=4096.')
print('- To eliminate all 4096 coordinates in <=4 useful stages would require ~1024-bit collision buckets, whose expected load is effectively zero.')
print('- Continuing with generic BKW/LF1 on this dense random instance is therefore not a local-Mac route; useful progress requires a structural bug, leaked additional material, or a non-generic LPN breakthrough.')
