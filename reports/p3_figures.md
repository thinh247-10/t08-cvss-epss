# Phase 3 — N3 figure captions

Run status: complete; N=396 CVEs; KEV=3; K=10/20/50 for metrics, K=50 for top lists.

EPSS 2026-09-29 | KEV released 2026-09-30; retrieved 2026-10-01 UTC.

Dataset/cohort/policy: t08-v1.0-20261010 / t08-v1.0-20261010:ranking / cvss-epss-kev-first-v1.

Observed CVSS only. Ranks, overlaps, recall and context decisions are read from N2 artifacts. No policy is recalculated; ID is only the producer's tie-break.

CVSS: Base descending → ID ascending. EPSS: probability descending → ID ascending. KEV-first: KEV descending → EPSS descending → Base descending → ID ascending.

Illustrative thresholds CVSS≥7.0 / EPSS≥0.1; status=locked. Verified N2 step B config dated 2026-10-18; illustrative only, no policy changes.

Three KEVs are a small denominator. These are snapshot comparisons, not evidence of future prediction accuracy. Absence from KEV does not prove no exploitation.

| Figure (PNG + SVG) | Caption |
|---|---|
| cvss_epss_scatter | N=396 CVEs, K=N/A. Observed Base 0–10 versus EPSS probability 0–1; KEV diamonds=3. Coincident points can overlap; every ID/zero retained in scatter_source.csv. |
| top50_three_policies_p1 | K=50 per policy, positions 1–25 from the full supplied ranks; KEV badges follow source booleans. |
| top50_three_policies_p2 | Same N/K, positions 26–50. No KEV-first score is invented. Exact rows: top50_long.csv. |
| topk_overlap | N=396 CVEs, K=10/20/50; supplied Jaccard in [0,1] from overlap.csv. CVSS/EPSS and CVSS/KEV-first coincide; differing markers/styles expose both. EPSS/KEV-first set overlap=1 does not establish identical order. |
| kev_recall_at_k | N=396, denominator=3 KEV; CVSS/EPSS only, K=10/20/50. Supplied hits/denominator and rate; null is N/A with reason and has no marker at a numeric value. KEV-first recall stays null in source and is excluded from this figure. |

N2 Kendall tau-b on raw CVSS/EPSS scores (ties retained), copied without recomputing: `{"value": 0.30569771817081276, "reason": null, "inputs": ["cvss_base_score", "epss"], "variant": "b"}`.

CVSS cutoff at K=10/20 spans 28 tied CVEs; 10/20 chosen by N2's ID tie-break. See the verified topk_metrics.csv; thresholds do not alter this choice.

## Context severity and action queue

Unit=CVE/asset pair; context=phase3-context-v1; queue policy=context-v1. Complete identical pairs=3; comparison population=N2 patch pairs with complete Base and Environmental scores; scored pairs outside comparison=2; all mapping pairs outside comparison=3 (retained with reasons in context_excluded.csv).

Base→Environmental severity ranks and patch/review decisions are different views. No ranks are derived from queue position, and no missing value is converted to zero.

`context_rank_changes.png/.svg`: supplied Base→Environmental rank on the exact same complete patch CVE/asset pairs declared by N2; labels identify both keys. Rank 1 is highest severity. Both axes use the same population; client review is outside both. Base/Environmental ties follow score descending → CVE/asset ascending, as supplied by N2.

`priority_queue_status.png/.svg`: counts of supplied patch/review_required/not_applicable decisions, without rerunning the action policy.

| Queue status | Pairs |
|---|---:|
| patch | 3 |
| review_required | 3 |
| not_applicable | 0 |

Client/unknown review rows retain null priority_rank=N/A, plus the producer's reason/action.

| CVE | Asset | Exposure | Rank | Supplied review reason | Supplied action |
|---|---|---|---|---|---|
| CVE-2023-22626 | API-02 | internal | N/A | Applicability not established: Deliberate unresolved database-adjacent backend candidate; inventory has no evidence of PgHero installation, cannot mark affected or unaffected. Missing environmental_score; not imputed. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-30470 | MOB-01 | client | N/A | Exposure client/unknown has no numeric rule; verify attack path. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-41387 | MOB-02 | client | N/A | Exposure client/unknown has no numeric rule; verify attack path. | Verify applicability, client attack path and missing signals before numeric ranking. |

Source version is phase3-context-v1 from the supplied package; it is not automatically replaced by newer revisions on N2's branch. Queue counts include every mapping pair; the Environmental table retains all scored client pairs. Plot completion is not completion of the independent Environmental crosscheck or all Phase 3 tasks.

## Input integrity

| Input | Bytes | SHA-256 |
|---|---:|---|
| data/processed/p3_n3_input/rankings.csv | 48438 | `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67` |
| config/phase3_plots.yaml | 1496 | `44b2db73be7eb2220bdd1415d21ab1873cee57bec857865f250976d1ec4679a9` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/metadata.json | 4329 | `2f62ee29f7ed7a2a0be87c39bf3ea72f30498fb09933486878e1b5951a7fddc0` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/rankings.csv | 48438 | `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/ranking_metrics.json | 6189 | `f747c31deb91a023238556bcc9d731606f24d2888ed9b5e2cdd5e5622f2a94f7` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/topk_metrics.csv | 599 | `7a68e595bcb695b732a8bbf269cff793ecdd369d1d4265ac2afac3bb721f12f6` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/overlap.csv | 374 | `714e2804b6fef880a5a6c6ee9338f8347f6ca6a6fb113e890ce17b24b3b19fa4` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/rank_deltas.csv | 11906 | `2607c46f468ae2f2292207b9fb1da0049f73b319ffb47c8b9ccaed196bef4173` |
| data/processed/p3_n2_context_20261019_r1_received/docs/phase-3-artifact-contract.md | 7673 | `2c40c071c5fd1f81323d1a592df30981bf4731597b09f11a86c524175080fe44` |
| data/processed/p3_n2_context_20261019_r1_received/config/phase3.yaml | 720 | `d403aa02bcb622566b45ffff9ad407723fadbaeed9dc550a974b7063463286d0` |
| data/processed/p3_n2_context_20261019_r1_received/handoff_manifest.json | 3409 | `4d543693c01cffbd24280b74112d95236dd8f55b51beccb1c944473d7b0f3029` |
| D:/Downloads/n2_p3_context_20261019_r1.zip | 45788 | `8a2fc661f369e1fa6327472a9464aa01277d4e5406c3eefdd46e416d175069d9` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/context_metadata.json | 5079 | `6df5d966c8dc91609ab6b4cdde0a00d70e59abcb806602fa933649299450971f` |
| data/processed/p3_n2_context_20261019_r1_received/docs/phase-3-artifact-contract.md | 7673 | `2c40c071c5fd1f81323d1a592df30981bf4731597b09f11a86c524175080fe44` |
| data/processed/p3_n2_context_20261019_r1_received/handoff_manifest.json | 3409 | `4d543693c01cffbd24280b74112d95236dd8f55b51beccb1c944473d7b0f3029` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/environmental_scores.csv | 3214 | `1d40e31ed9341b90a8af93ca2dc5a3c9788ad0bd76cc3890fb6d2c17d8b2cf33` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/context_comparison.csv | 584 | `c51b733e4838ba12c479b990f3370e0bf84fbdb85607536959fa22738ef9895b` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/priority_queue.csv | 2117 | `8946e90fb5308bd34e3e1c3c7c8b0f476bb144413e8a39cd5a7c64e7fdf6405f` |
| data/processed/p3_n2_context_20261019_r1_received/p3_n2/cve_asset_mapping.csv | 4382 | `8872293c53ff1fe429259aeb17ac3dd7ee8e6d5433e51c3d56b9b0cab3c9a98b` |

Output hashes/bytes and exact command: `data/processed/p3_n3/figures_manifest.json`.

Only the files listed in this run's manifest are certified. Synthetic fixture outputs are confined to temporary test directories.

Pending:
- None for the supplied artifact scope.
