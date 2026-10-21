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

Unit=CVE/asset pair; context=phase3-context-v2; queue policy=context-v1. Complete identical pairs=8; comparison population=N2 patch pairs with complete Base and Environmental scores; scored pairs outside comparison=2; all mapping pairs outside comparison=7 (retained with reasons in context_excluded.csv).

Base→Environmental severity ranks and patch/review decisions are different views. No ranks are derived from queue position, and no missing value is converted to zero.

`context_rank_changes.png/.svg`: supplied Base→Environmental rank on the exact same complete patch CVE/asset pairs declared by N2; labels identify both keys. Rank 1 is highest severity. Both axes use the same population; client review is outside both. Base/Environmental ties follow score descending → CVE/asset ascending, as supplied by N2.

`priority_queue_status.png/.svg`: counts of supplied patch/review_required/not_applicable decisions, without rerunning the action policy.

| Queue status | Pairs |
|---|---:|
| patch | 8 |
| review_required | 7 |
| not_applicable | 0 |

Client/unknown review rows retain null priority_rank=N/A, plus the producer's reason/action.

| CVE | Asset | Exposure | Rank | Supplied review reason | Supplied action |
|---|---|---|---|---|---|
| CVE-2022-46168 | API-01 | internet | N/A | Applicability not established: Version matches but inventory does not establish group SMTP usage; verify configuration before affected decision. Missing environmental_score; not imputed. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-22454 | API-01 | internet | N/A | Applicability not established: Version matches but pending-topic approval and modified/disabled default CSP are not established by inventory. Missing environmental_score; not imputed. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-22455 | API-01 | internet | N/A | Applicability not established: Version matches but tag-description editing and CSP conditions are unverified. Missing environmental_score; not imputed. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-22468 | API-01 | internet | N/A | Applicability not established: Source range conflict plus unverified CSP; do not mark 2.8.13 unaffected or change v1 labels automatically. Missing environmental_score; not imputed. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-22626 | API-02 | internal | N/A | Applicability not established: Deliberate unresolved database-adjacent backend candidate; inventory has no evidence of PgHero installation, cannot mark affected or unaffected. Missing environmental_score; not imputed. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-30470 | MOB-01 | client | N/A | Exposure client/unknown has no numeric rule; verify attack path. | Verify applicability, client attack path and missing signals before numeric ranking. |
| CVE-2023-41387 | MOB-02 | client | N/A | Exposure client/unknown has no numeric rule; verify attack path. | Verify applicability, client attack path and missing signals before numeric ranking. |

Source version is phase3-context-v2 from the supplied package; it is not automatically replaced by newer revisions on N2's branch. Queue counts include every mapping pair; the Environmental table retains all scored client pairs. Plot completion is not completion of the independent Environmental crosscheck or all Phase 3 tasks.

## Input integrity

| Input | Bytes | SHA-256 |
|---|---:|---|
| data/processed/p3_n2/rankings.csv | 48438 | `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67` |
| config/phase3_plots_n1.yaml | 1105 | `88370db32835038da62b74a2de87d9937199949907b0ffc8bdb7775f19842193` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/metadata.json | 4131 | `40f1da8cebfc80f5dbcd85cd694d0d9757eee6e6d130a55b871603a45041e550` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/rankings.csv | 48438 | `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/ranking_metrics.json | 6189 | `49eca7c469c59b74d15ee670d2103804d1a6b6fc29887aedf36452b2c7bb3165` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/topk_metrics.csv | 599 | `7a68e595bcb695b732a8bbf269cff793ecdd369d1d4265ac2afac3bb721f12f6` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/overlap.csv | 374 | `714e2804b6fef880a5a6c6ee9338f8347f6ca6a6fb113e890ce17b24b3b19fa4` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/rank_deltas.csv | 11906 | `2607c46f468ae2f2292207b9fb1da0049f73b319ffb47c8b9ccaed196bef4173` |
| data/processed/p3_n1_context_verified_20261021/docs/phase-3-artifact-contract.md | 8414 | `f2dc6738040c952ff5d00a0c68939da92e47cff0282f4ea8d450a3d42c5a541f` |
| data/processed/p3_n1_context_verified_20261021/config/phase3.yaml | 804 | `715657ccbc60ffb84302268faa1a5df9df1e5d98ee006fb62ef43975dff933c7` |
| data/processed/p3_n1_context_verified_20261021/handoff_manifest.json | 4808 | `5148db8026e38a734fff725b6bf6ad18a46e07c3eb5913e8beba7b9b325426ea` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/context_metadata.json | 5312 | `899966c4cad3f1512578b009b9ebf2c3edfbac60f98786c1fa5be5fda64098e5` |
| data/processed/p3_n1_context_verified_20261021/docs/phase-3-artifact-contract.md | 8414 | `f2dc6738040c952ff5d00a0c68939da92e47cff0282f4ea8d450a3d42c5a541f` |
| data/processed/p3_n1_context_verified_20261021/handoff_manifest.json | 4808 | `5148db8026e38a734fff725b6bf6ad18a46e07c3eb5913e8beba7b9b325426ea` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/environmental_scores.csv | 6208 | `878f89ea8d5435188cff99e58ee6bbf0e55b60faf033ae2ce8ff9d447f7a94f2` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/context_comparison.csv | 1139 | `6b80612e1bab86f4ae24f3cdf763a8ec6de5c84c1479bac263651e79b6c38366` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/priority_queue.csv | 5262 | `38204e9c317209cc64fcbc2f87bd1f66581ddf5d4cfe6bf65c1c768505880946` |
| data/processed/p3_n1_context_verified_20261021/p3_n2/cve_asset_mapping.csv | 9799 | `2f05ed03ba10a730d868b30d10db00535d853d4a6d1f5ae832980477d938bf36` |

Output hashes/bytes and exact command: `data/processed/p3_n3/figures_manifest.json`.

Only the files listed in this run's manifest are certified. Synthetic fixture outputs are confined to temporary test directories.

Pending:
- None for the supplied artifact scope.
