"""Deterministic approximate audit of 3-token shingles, without fitting a model.

32 MinHash permutations, 8 bands of 4, exact Jaccard >= .95 verification.
Large buckets are reported/skipped. Recall is limited; zero remaining detected
edges never implies zero semantic duplication. Product overlap is reported apart.
"""
from collections import defaultdict
import hashlib
import itertools
import re
import unicodedata

import numpy as np
import pandas as pd


def normalize(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def shingles(text):
    tokens = re.findall(r"\w+|[^\w\s]", text)
    return {" ".join(tokens[i:i+3]) for i in range(max(1, len(tokens)-2))}


def plan_near_duplicates(frame, exact_decisions, threshold=.95, max_bucket=200):
    """Extend exact groups with verified near edges; return stable ID decisions."""
    data = frame.set_index("cve_id").loc[exact_decisions.cve_id]
    normalized = data.description.map(normalize)
    texts = sorted(normalized.unique())
    text_ids = {text: i for i, text in enumerate(texts)}
    groups = defaultdict(list)
    split_by_id = exact_decisions.set_index("cve_id").proposed_split.to_dict()
    for cve_id, text in normalized.items():
        groups[text_ids[text]].append(cve_id)
    group_splits = {i: {split_by_id[c] for c in ids} for i, ids in groups.items()}
    sets = []
    buckets = defaultdict(list)
    rng = np.random.default_rng(42)
    prime = 2147483647
    a = rng.integers(1, prime, size=32, dtype=np.uint64)
    b = rng.integers(0, prime, size=32, dtype=np.uint64)
    for i, text in enumerate(texts):
        words = shingles(text)
        sets.append(words)
        hashes = np.array([int.from_bytes(hashlib.blake2b(w.encode(), digest_size=4).digest(), "little") % prime
                           for w in sorted(words)], dtype=np.uint64)
        signature = ((hashes[:, None] * a + b) % prime).min(axis=0)
        for band in range(8):
            buckets[(band, tuple(signature[4*band:4*band+4]))].append(i)
    parents = list(range(len(texts)))
    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i
    pairs = set()
    skipped = 0
    for ids in buckets.values():
        if len(ids) > max_bucket:
            skipped += 1
            continue
        pairs.update((i, j) for i, j in itertools.combinations(ids, 2)
                     if len(group_splits[i] | group_splits[j]) > 1)
    edges = []
    for i, j in sorted(pairs):
        if min(len(sets[i]), len(sets[j])) / max(len(sets[i]), len(sets[j])) < threshold:
            continue
        similarity = len(sets[i] & sets[j]) / len(sets[i] | sets[j])
        if similarity >= threshold:
            left, right = find(i), find(j)
            parents[max(left, right)] = min(left, right)
            edges.append({"left_id": min(groups[i]), "right_id": min(groups[j]),
                          "jaccard": similarity, "left_group_size": len(groups[i]),
                          "right_group_size": len(groups[j])})
    order = {"train": 0, "validation": 1, "test": 2}
    component_first = {}
    for i, ids in groups.items():
        root = find(i)
        earliest = min((split_by_id[c] for c in ids), key=order.get)
        if root not in component_first or order[earliest] < order[component_first[root]]:
            component_first[root] = earliest
    result = exact_decisions.copy()
    result["duplicate_policy_version"] = "exact-near-earliest-v1"
    result["component_id"] = [hashlib.sha256(texts[find(text_ids[normalized[c]])].encode()).hexdigest()
                              for c in result.cve_id]
    result["earliest_split"] = [component_first[find(text_ids[normalized[c]])] for c in result.cve_id]
    result["keep_in_preview"] = result.proposed_split.eq(result.earliest_split)
    result["reason"] = np.where(result.keep_in_preview, "earliest_component_period", "exact_or_near_in_earlier_period")
    return result, pd.DataFrame(edges, columns=["left_id", "right_id", "jaccard", "left_group_size", "right_group_size"]), {
        "algorithm": "32 MinHash / 8x4 bands / 3-token shingles / exact Jaccard verification",
        "threshold": threshold, "seed": 42, "candidate_pairs": len(pairs),
        "verified_edges": len(edges), "skipped_large_buckets": skipped,
        "max_bucket": max_bucket, "unique_normalized_descriptions": len(texts),
        "limitation": "Approximate retrieval; near/semantic duplicates may remain. Shared products allowed in temporal evaluation."}
