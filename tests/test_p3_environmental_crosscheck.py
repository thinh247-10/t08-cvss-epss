"""N3-owned independent fixed-case check; never call the producer scorer."""
from pathlib import Path
from decimal import Decimal
import unittest
import pandas as pd
from scripts.check_phase3_environmental_n3 import independent_expected, crosscheck, BASE, VECTOR


class EnvironmentalCrosscheckTests(unittest.TestCase):
    def test_decimal_substitution_expected(self):
        result = independent_expected()
        self.assertEqual(Decimal(result['raw_miss']), Decimal('0.9296'))
        self.assertEqual(result['miss'], '0.915')
        self.assertEqual(result['sum'], '9.7613427750')
        self.assertEqual(result['expected'], 9.8)

    def test_mismatch_duplicate_and_changed_assumptions_fail(self):
        frame = pd.DataFrame([dict(cve_id='CVE-2023-41387', asset_id='MOB-02', base_vector=BASE,
            environmental_vector=VECTOR, base_score=9.1, environmental_score=9.8,
            CR='H', IR='H', AR='M', score_source='observed',
            dataset_version='t08-v1.0-20261010', context_version='phase3-context-v1')])
        for bad in [frame.assign(environmental_score=9.7), frame.assign(CR='L'),
                    frame.assign(context_version='wrong'), pd.concat([frame, frame])]:
            with self.assertRaises(ValueError):
                crosscheck(bad)

    @unittest.skipUnless(Path('data/processed/p3_n2_context_20261019_r1_received/p3_n2/environmental_scores.csv').is_file(), 'N2 r1 not installed')
    def test_real_n2_mobile_pair(self):
        path = Path('data/processed/p3_n2_context_20261019_r1_received/p3_n2/environmental_scores.csv')
        before = path.read_bytes()
        self.assertEqual(crosscheck(pd.read_csv(path))['status'], 'pass')
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
