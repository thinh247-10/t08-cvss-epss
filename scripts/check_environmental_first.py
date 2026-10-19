"""Optional independent FIRST JS oracle check; not used by production pipeline.

Downloads the inspected official CVSS calculator into memory only; records its
hash and reproducible vector fixtures, not a second production scorer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess

import requests

from src.environmental.cvss_environmental import BASE_ORDER, EXTRA_VALUES, score_environmental_vector

URL = "https://www.first.org/_/cvsscalc31.js?20240610063942"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    response = requests.get(URL, timeout=45)
    response.raise_for_status()
    node = shutil.which("node")
    if node is None:
        raise ValueError("Node is needed only for the independent FIRST oracle check")
    vectors = []
    # Every S/PR combination, all X; zero impact, cap and changed MS witnesses.
    for scope in "UC":
        for pr in "NLH":
            base = f"CVSS:3.1/AV:N/AC:L/PR:{pr}/UI:N/S:{scope}/C:H/I:H/A:H"
            vectors.extend([base, base + "/CR:H/IR:H/AR:H", base + "/MC:N/MI:N/MA:N",
                            base + "/MS:" + ("C" if scope == "U" else "U")])
    rng = random.Random(42)
    values = dict(AV="NALP", AC="LH", PR="NLH", UI="NR", S="UC", C="NLH", I="NLH", A="NLH")
    for _ in range(256):
        vectors.append("CVSS:3.1/" + "/".join(f"{k}:{rng.choice(values[k])}" for k in BASE_ORDER)
                       + "/" + "/".join(f"{k}:{rng.choice(v)}" for k, v in EXTRA_VALUES.items()))
    js = """const fs=require('fs'),vm=require('vm');
const input=JSON.parse(fs.readFileSync(0,'utf8')),box={};
vm.runInNewContext(input.source,box,{timeout:2000});
const result=input.vectors.map(vector=>{const r=box.CVSS31.calculateCVSSFromVector(vector);
if(!r.success)throw new Error(JSON.stringify(r));return {vector,expected:Number(r.environmentalMetricScore),base:Number(r.baseMetricScore)}});
process.stdout.write(JSON.stringify(result));"""
    run = subprocess.run([node, "-e", js], input=json.dumps(dict(source=response.text, vectors=vectors)),
                         text=True, capture_output=True, check=True, timeout=30)
    cases = json.loads(run.stdout)
    for row in cases:
        row["actual"] = score_environmental_vector(row["vector"])[1]
        if row["actual"] != row["expected"]:
            raise AssertionError(row)
    report = dict(source_url=URL, source_sha256=hashlib.sha256(response.content).hexdigest(),
                  source_read_date="2026-10-19", seed=42, cases=len(cases), mismatches=0,
                  expected_origin="Official FIRST CVSS31.calculateCVSSFromVector; not scorer under test",
                  fixtures=cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "fixtures"}, indent=2))


if __name__ == "__main__":
    main()
