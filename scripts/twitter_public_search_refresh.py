#!/usr/bin/env python3
import re, html, urllib.parse, urllib.request, datetime, json
queries = [
  'site:x.com octra HFHE challenge v2',
  'site:x.com octra hfhe solved',
  'site:x.com octra hfhe private key',
  'site:x.com octra hfhe lpn samples',
  'site:x.com octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ',
  'site:x.com 2075336875322032268',
  'site:x.com octralex HFHE challenge',
  'site:x.com octrabunch HFHE challenge',
]
ua={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126 Safari/537.36'}
print('# Public Twitter/X search via DuckDuckGo', datetime.datetime.utcnow().isoformat()+'Z')
all_hits=[]
for q in queries:
    url='https://duckduckgo.com/html/?q='+urllib.parse.quote(q)
    print('\n## query:', q)
    try:
        req=urllib.request.Request(url,headers=ua)
        data=urllib.request.urlopen(req,timeout=25).read().decode('utf-8','replace')
        print('bytes', len(data))
        # DDG result anchors use class result__a, sometimes redirect in uddg param
        hits=[]
        for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', data, re.S):
            href=html.unescape(m.group(1)); title=re.sub('<.*?>','',m.group(2)); title=html.unescape(title).strip()
            parsed=urllib.parse.urlparse(href)
            qs=urllib.parse.parse_qs(parsed.query)
            if 'uddg' in qs: href=qs['uddg'][0]
            # snippet after anchor
            tail=data[m.end():m.end()+1200]
            sm=re.search(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>|<div[^>]+class="result__snippet"[^>]*>(.*?)</div>', tail, re.S)
            snip=''
            if sm:
                snip=html.unescape(re.sub('<.*?>',' ', sm.group(1) or sm.group(2))).strip()
                snip=re.sub(r'\s+',' ',snip)
            hits.append({'title':title,'url':href,'snippet':snip})
        if not hits:
            # cheap fallback: print title occurrences with x.com links
            for href in sorted(set(re.findall(r'https?://(?:x|twitter)\.com/[^"&<> ]+', html.unescape(data))))[:10]:
                hits.append({'title':'raw_link','url':href,'snippet':''})
        for i,h in enumerate(hits[:8],1):
            all_hits.append((q,h))
            print(f'{i}. {h["title"]}\n   {h["url"]}\n   {h["snippet"][:350]}')
    except Exception as e:
        print('ERR',repr(e))
print('\n# unique candidate X URLs')
seen=set()
for q,h in all_hits:
    u=h['url']
    if ('x.com/' in u or 'twitter.com/' in u) and u not in seen:
        seen.add(u); print(u)
