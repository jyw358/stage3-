#!/usr/bin/env python3
"""NVD CVE 导入器(T2.6 扩容):真实 CVE 条目入知识库。

查询面:车载关键词(controller area network / ECU / OBD / UDS / telematics / automotive)
+ 内存安全 CWE 族(787/416/121/122/190/193/134/125)。
限速:NVD 无 key 5 req/30s → 请求间隔 7s;resultsPerPage=200。
条目:id=KB-CVE-<seq>, name=CVE-ID + 摘要(英文原文), component=CPE 产品或 CWE,
attack_conditions=摘要, fix=引用中的 patch/advisory 线索, source=public。
"""
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from kb.store import KB

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

QUERIES = [
    ("vehicle", "keywordSearch", q) for q in [
        '"controller area network"', '"on-board diagnostics"', "ECU automotive",
        "UDS diagnostic automotive", "telematics vehicle", "CAN bus vehicle",
        "infotainment vehicle", "OTA vehicle update",
    ]
] + [
    ("memory", "cweId", c) for c in [
        "CWE-787", "CWE-416", "CWE-121", "CWE-122", "CWE-190", "CWE-193", "CWE-125",
    ]
]


def fetch(params: dict, retries: int = 3):
    url = BASE + "?" + urllib.parse.urlencode(params)
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cybergym-kb/0.1"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:
            print(f"  retry {i + 1}: {e}", flush=True)
            time.sleep(10)
    return None


def main(db="/data/cybergym/kb/kb.sqlite", target=300):
    kb = KB(db)
    start = kb.count()
    seq = 0
    seen = set()
    for tag, key, val in QUERIES:
        d = fetch({key: val, "resultsPerPage": 100})
        time.sleep(7)
        if not d:
            print(f"[nvd] {val}: fetch failed, skip", flush=True)
            continue
        got = 0
        for item in d.get("vulnerabilities", []):
            c = item["cve"]
            cid = c["id"]
            if cid in seen:
                continue
            seen.add(cid)
            desc = next((x["value"] for x in c.get("descriptions", [])
                         if x["lang"] == "en"), "")[:400]
            cwes = sorted({w["value"] for x in c.get("weaknesses", [])
                           for w in x.get("description", []) if w["value"].startswith("CWE-")})
            refs = [r["url"] for r in c.get("references", [])[:3]]
            fix = ("; ".join(r for r in refs if any(k in r for k in
                    ("patch", "github.com", "advisory", "commit"))) or "见引用")[:200]
            seq += 1
            kb.add(id=f"KB-CVE-{seq:04d}", name=f"{cid}: {desc[:90]}",
                   component=("CWE: " + ",".join(cwes)) if cwes else "n/a",
                   attack_conditions=desc, fix=fix, cve=cid,
                   tags=f"{tag},nvd", source="public")
            got += 1
            if kb.count() - start >= target:
                break
        print(f"[nvd] {val}: +{got} (total {kb.count()})", flush=True)
        if kb.count() - start >= target:
            break
    print(f"[nvd] done: {start} -> {kb.count()}")


if __name__ == "__main__":
    main()
