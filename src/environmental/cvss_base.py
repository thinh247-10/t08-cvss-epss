"""Strict CVSS 3.1 Base scoring, FIRST sections 7.1/7.4 and Appendix A.

https://www.first.org/cvss/v3.1/specification-document
Environmental/Temporal metrics are deliberately rejected by this Base interface.
"""
import math

from src.collect.nvd_collector import parse_base_vector


def roundup(value):
    """FIRST Appendix A: avoid floating point noise before rounding up."""
    integer = math.floor(value * 100000 + 0.5)
    return integer / 100000 if integer % 10000 == 0 else (integer // 10000 + 1) / 10


def calculate_base_score(vector):
    metrics = parse_base_vector(vector)
    if metrics is None:
        raise ValueError("Expected a complete, strict CVSS:3.1 Base vector")
    impact_weights = {"N": 0.0, "L": 0.22, "H": 0.56}
    iss = 1 - math.prod(1 - impact_weights[metrics[k]] for k in ("C", "I", "A"))
    changed = metrics["S"] == "C"
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
              if changed else 6.42 * iss)
    if impact <= 0:
        return 0.0
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62,
          "H": 0.5 if changed else 0.27}[metrics["PR"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    return roundup(min((impact + 8.22 * av * ac * pr * ui) * (1.08 if changed else 1), 10))
