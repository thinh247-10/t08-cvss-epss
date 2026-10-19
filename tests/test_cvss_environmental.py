"""Independent fixed expectations from FIRST calculator, read 2026-10-19."""
import unittest
from src.environmental.cvss_base import calculate_base_score
from src.environmental.cvss_environmental import environmental_score, score_environmental_vector, EXTRA_VALUES

BASE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
CASES = (("", 7.1), ("/MS:C", 8.5), ("/MS:C/MPR:N", 9.3),
         ("/MS:C/MPR:L", 8.5), ("/MS:C/MPR:H", 7.6),
         ("/CR:H/IR:H/AR:H", 8.6), ("/CR:L/IR:L/AR:L", 5.2),
         ("/MC:N/MI:N/MA:N", 0.0), ("/E:U/RL:O/RC:U", 5.7),
         ("/MAV:A/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H/CR:H/IR:H/AR:H/E:P/RL:T/RC:R", 6.5))


class EnvironmentalChecks(unittest.TestCase):
    def test_first_calculator_cases(self):
        for tail, expected in CASES:
            with self.subTest(tail=tail):
                self.assertEqual(score_environmental_vector(BASE + tail)[1], expected)

    def test_not_defined_and_scope_changed_exception(self):
        for scope in ("U", "C"):
            base = BASE.replace("S:U", "S:" + scope)
            full, score = environmental_score(base)
            self.assertEqual(score, calculate_base_score(base))
            for key in EXTRA_VALUES:
                self.assertIn(f"/{key}:X", full)
        vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
        self.assertEqual(calculate_base_score(vector), 9.9)
        self.assertEqual(environmental_score(vector)[1], 10.0)

    def test_modified_scope_overrides_base_both_directions(self):
        self.assertEqual(environmental_score(BASE, {"MS": "C"})[1], 8.5)
        self.assertEqual(environmental_score(BASE.replace("S:U", "S:C"), {"MS": "U"})[1], 7.1)

    def test_impact_cap_and_zero(self):
        high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(environmental_score(high, {"CR": "H", "IR": "H", "AR": "H"})[1], 9.8)
        for scope in ("U", "C"):
            self.assertEqual(environmental_score(BASE.replace("S:U", "S:" + scope),
                                                {"MC": "N", "MI": "N", "MA": "N"})[1], 0.0)

    def test_reordered_vector_and_roundtrip(self):
        vector, score = score_environmental_vector(BASE + "/CR:H/MS:C/E:U")
        reordered = "CVSS:3.1/" + "/".join(reversed(vector.split("/")[1:]))
        self.assertEqual(score_environmental_vector(reordered), (vector, score))

    def test_invalid_vectors_and_metrics_rejected(self):
        bad = [None, 1, "", BASE.replace("3.1", "3.0"), BASE + "/", BASE + "/E:X/E:X",
               BASE + "/CR:", BASE + "/MPR:U", BASE + "/ZZ:X", BASE.replace("/A:N", ""),
               BASE + "/MS:C/MS:U", BASE + "/CR:HIGH", BASE + "/AV:N"]
        for vector in bad:
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                score_environmental_vector(vector)
        for metrics in ({"AV": "N"}, {"CR": None}, {"CR": ""}, {"CR": "HH"}, []):
            with self.subTest(metrics=metrics), self.assertRaises(ValueError):
                environmental_score(BASE, metrics)
        with self.assertRaises(ValueError):
            environmental_score(BASE + "/CR:H")


if __name__ == "__main__":
    unittest.main()
