"""CVSS 3.1 Environmental: FIRST 7.3/7.4, Appendix A. No control inference.

Scope-C can differ from Base even with all additions X: Modified Impact differs.
"""
from collections.abc import Mapping
import math

from src.collect.nvd_collector import parse_base_vector
from src.environmental.cvss_base import roundup

BASE_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
EXTRA_VALUES = {
    "E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
    "CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR",
    "MS": "XUC", "MC": "XNLH", "MI": "XNLH", "MA": "XNLH",
}


def parse_environmental_vector(vector):
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise ValueError("Expected CVSS:3.1 vector")
    metrics = {}
    for token in vector.split("/")[1:]:
        parts = token.split(":")
        if len(parts) != 2 or parts[0] in metrics:
            raise ValueError("Malformed or duplicate CVSS metric")
        key, value = parts
        if key not in BASE_ORDER and key not in EXTRA_VALUES:
            raise ValueError(f"Unknown CVSS metric: {key}")
        metrics[key] = value
    base = "CVSS:3.1/" + "/".join(f"{k}:{metrics.get(k, '')}" for k in BASE_ORDER)
    if parse_base_vector(base) is None:
        raise ValueError("Missing or invalid Base metric")
    extras = {key: metrics.get(key, "X") for key in EXTRA_VALUES}
    for key, value in extras.items():
        if value not in EXTRA_VALUES[key] or len(value) != 1:
            raise ValueError(f"Invalid {key}")
    return base, extras


def environmental_score(base_vector, metrics=None):
    """Return (canonical full vector, score); strict Base input + extras mapping."""
    base = parse_base_vector(base_vector)
    if base is None:
        raise ValueError("Expected a complete, strict CVSS:3.1 Base vector")
    if metrics is None:
        metrics = {}
    if not isinstance(metrics, Mapping):
        raise ValueError("Additional metrics must be a mapping")
    extra = dict.fromkeys(EXTRA_VALUES, "X")
    for key, value in metrics.items():
        if (key not in EXTRA_VALUES or not isinstance(value, str)
                or len(value) != 1 or value not in EXTRA_VALUES[key]):
            raise ValueError(f"Unknown or invalid additional metric: {key}")
        extra[key] = value
    effective = {key: base[key] if extra["M" + key] == "X" else extra["M" + key]
                 for key in BASE_ORDER}
    weights = {"N": 0.0, "L": 0.22, "H": 0.56}
    requirements = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
    miss = min(1 - math.prod(1 - weights[effective[key]] * requirements[extra[key + "R"]]
                             for key in ("C", "I", "A")), 0.915)
    changed = effective["S"] == "C"
    impact = (7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
              if changed else 6.42 * miss)
    score = 0.0
    if impact > 0:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[effective["AV"]]
        ac = {"L": 0.77, "H": 0.44}[effective["AC"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62,
              "H": 0.5 if changed else 0.27}[effective["PR"]]
        ui = {"N": 0.85, "R": 0.62}[effective["UI"]]
        temporal = ({"X": 1, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1}[extra["E"]]
                    * {"X": 1, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1}[extra["RL"]]
                    * {"X": 1, "U": 0.92, "R": 0.96, "C": 1}[extra["RC"]])
        score = roundup(roundup(min((impact + 8.22 * av * ac * pr * ui)
                                     * (1.08 if changed else 1), 10)) * temporal)
    full = "CVSS:3.1/" + "/".join(f"{k}:{base[k]}" for k in BASE_ORDER)
    full += "/" + "/".join(f"{k}:{extra[k]}" for k in EXTRA_VALUES)
    return full, score


def score_environmental_vector(vector):
    base, metrics = parse_environmental_vector(vector)
    return environmental_score(base, metrics)
