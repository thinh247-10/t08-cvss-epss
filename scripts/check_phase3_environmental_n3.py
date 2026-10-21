"""Independent, fixed-case Decimal crosscheck of N2's MOB-02 artifact.

FIRST CVSS 3.1 sections 7.3/7.4; no import of the N2 scorer or ranking policy.
This is not a general Environmental implementation.
"""
import argparse
from decimal import Decimal as D, ROUND_CEILING
import hashlib
import json
from pathlib import Path
import pandas as pd

BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
VECTOR = BASE + "/E:X/RL:X/RC:X/CR:H/IR:H/AR:M/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
SOURCE = "https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations"


def independent_expected():
    # Explicit substitutions for this fixed S:U, C:N/I:H/A:H case, exact decimals.
    raw_miss = 1 - (1 - D('1.5') * 0) * (1 - D('1.5') * D('.56')) * (1 - D('1') * D('.56'))
    miss = min(raw_miss, D('.915'))
    impact = D('6.42') * miss
    exploitability = D('8.22') * D('.85') * D('.77') * D('.85') * D('.85')
    inner = min(impact + exploitability, D(10)).quantize(D('.1'), rounding=ROUND_CEILING)
    expected = (inner * D(1) * D(1) * D(1)).quantize(D('.1'), rounding=ROUND_CEILING)
    return {"raw_miss": str(raw_miss), "miss": str(miss), "modified_impact": str(impact),
            "modified_exploitability": str(exploitability), "sum": str(impact + exploitability),
            "inner_roundup": str(inner), "expected": float(expected)}


def crosscheck(frame):
    if frame.duplicated(['cve_id', 'asset_id']).any():
        raise ValueError('Duplicate CVE/asset pair')
    pair = frame.loc[frame.cve_id.eq('CVE-2023-41387') & frame.asset_id.eq('MOB-02')]
    if len(pair) != 1:
        raise ValueError('Expected exactly one CVE-2023-41387/MOB-02')
    row = pair.iloc[0]
    for key, expected in {'base_vector': BASE, 'environmental_vector': VECTOR,
            'CR': 'H', 'IR': 'H', 'AR': 'M', 'score_source': 'observed',
            'dataset_version': 't08-v1.0-20261010', 'context_version': 'phase3-context-v1'}.items():
        if row[key] != expected:
            raise ValueError(f'Fixed-case assumption/version mismatch: {key}')
    result = independent_expected()
    if row.base_score != 9.1 or row.environmental_score != result['expected']:
        raise ValueError('Independent expected differs from N2; stop and report discrepancy')
    return {"status": "pass", "cve_id": row.cve_id, "asset_id": row.asset_id,
            "base_vector": BASE, "environmental_vector": VECTOR, "calculation": result,
            "n2_score": float(row.environmental_score), "difference": 0.0, "source": SOURCE,
            "dataset_version": row.dataset_version, "context_version": row.context_version,
            "method": "fixed-case exact Decimal substitution; no N2 scorer", "source_read_date": "2026-10-21"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scores', type=Path, default=Path('data/processed/p3_n2_context_20261019_r1_received/p3_n2/environmental_scores.csv'))
    args = parser.parse_args()
    result = crosscheck(pd.read_csv(args.scores))
    result['input'] = {'path': args.scores.as_posix(), 'bytes': args.scores.stat().st_size,
                       'sha256': hashlib.sha256(args.scores.read_bytes()).hexdigest()}
    out = Path('data/processed/p3_n3/environmental_crosscheck_n3.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
