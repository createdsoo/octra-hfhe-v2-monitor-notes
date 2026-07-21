#!/usr/bin/env python3
import os, subprocess, json, re, string, sys
repo='/Users/koala/hfhe_challenge_v2'
patterns=[
 'octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ',
 'master_seed','hd_version','hd_index','octra-wallet','mnemonic','priv','secret.ct','Love.ct',
 'hfhe','challenge','solve','plaintext','private key','octra.network/rpc','octrascan.io'
]
# scan all reachable git blobs, text-ish and <=200KB
os.chdir(repo)
blobs=subprocess.check_output(['git','rev-list','--objects','--all'],text=True,errors='ignore').splitlines()
seen={}
for line in blobs:
    parts=line.split(maxsplit=1)
    if not parts: continue
    oid=parts[0]; path=parts[1] if len(parts)>1 else ''
    if oid in seen: continue
    seen[oid]=path
hits=[]
for oid,path in seen.items():
    try:
        typ=subprocess.check_output(['git','cat-file','-t',oid],text=True).strip()
        if typ!='blob': continue
        size=int(subprocess.check_output(['git','cat-file','-s',oid],text=True).strip())
        if size>200000: continue
        data=subprocess.check_output(['git','cat-file','blob',oid])
    except Exception: continue
    if b'\x00' in data[:4096]:
        continue
    try: txt=data.decode('utf-8')
    except UnicodeDecodeError:
        try: txt=data.decode('latin1')
        except Exception: continue
    low=txt.lower()
    for pat in patterns:
        if pat.lower() in low:
            # collect context lines
            for i,l in enumerate(txt.splitlines(),1):
                if pat.lower() in l.lower():
                    hits.append((oid[:12],path,size,pat,i,l[:240]))
            break
print('blob_hits',len(hits))
for h in hits[:300]:
    print(json.dumps({'oid':h[0],'path':h[1],'size':h[2],'pat':h[3],'line':h[4],'text':h[5]},ensure_ascii=False))
