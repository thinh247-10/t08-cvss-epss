"""Evidence-based bounded product cohort and snapshot-checked manual annotations."""
import re


def cpe_product(criteria):
    """Read escaped CPE 2.3 part/vendor/product; never match by substring."""
    fields = re.split(r"(?<!\\):", criteria)
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return None
    return tuple(re.sub(r"\\(.)", r"\1", value) for value in fields[2:5])


def vulnerable_cpes(value, negated=False):
    """Only positive vulnerable matches, not environment CPEs or negated nodes."""
    if isinstance(value, dict):
        negated = negated or value.get("negate", False)
        if not negated and value.get("vulnerable") is True and "criteria" in value:
            yield value["criteria"]
        for item in value.values():
            yield from vulnerable_cpes(item, negated)
    elif isinstance(value, list):
        for item in value:
            yield from vulnerable_cpes(item, negated)


def classify_scope(cve_id, cpes, references, policy):
    rules = {(p["vendor"], p["product"]): p for p in policy["products"]}
    hits = []
    products = []
    for cpe in cpes:
        parsed = cpe_product(cpe)
        if parsed:
            products.append(":".join(parsed))
        if parsed and parsed[0] == "a" and parsed[1:] in rules:
            hits.append(rules[parsed[1:]])
    tags = sorted({hit["domain"] for hit in hits})
    evidence = sorted({hit["evidence"] for hit in hits})
    if hits:
        evidence += [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    return {"domain_tags": tags, "in_scope": bool(hits),
            "scope_status": "included" if hits else "needs_review",
            "scope_reason": ("Vulnerable application CPE plus official product role: " +
                             "; ".join(sorted({h["vendor"] + ":" + h["product"] + " (" + h["role"] + ")" for h in hits}))
                            if hits else "No match in bounded product policy; not evidence of being outside Web/mobile"),
            "scope_evidence": evidence, "product_groups": sorted(set(products)),
            "reference_urls": sorted(set(references)),
            "scope_policy_version": policy["policy_version"]}
