# Phase 3 N2 — context queue và sensitivity (mục 8)

Ngày thực hiện 2026-10-19. Branch `feat/p3-ranking-context`.
Dataset `t08-v1.0-20261010`, context `phase3-context-v1`, inventory `phase1-v1`.
Không sửa release hay inventory cũ. Ranking A/B vẫn cùng 396 ID/3 KEV.

## Lệnh thực chạy và kiểm tra

```powershell
.\.venv\Scripts\python.exe -m src.analysis.context_priority --help
.\.venv\Scripts\python.exe -m src.analysis.context_priority --master data/processed/phase1_v1_20261010/cves.parquet --mapping config/phase3_mapping.yaml --inventory config/assets.yaml --config config/phase3.yaml --output-dir data/processed/p3_n2
.\.venv\Scripts\python.exe -m scripts.check_environmental_first --output data/processed/p3_n2/environmental_first_check.json
.\.venv\Scripts\python.exe -m unittest tests.test_cvss_environmental tests.test_context_priority tests.test_ranking_metrics tests.test_rankings tests.test_cvss tests.test_phase1_release tests.test_asset_inventory -q
.\.venv\Scripts\python.exe -m pip check
```

64 test đạt (6 Environmental, 15 context, 13 ranking metrics, 8 ranking, 6 Base,
9 release, 7 inventory). CLI roundtrip dùng release thật, kiểm hash output và input
không bị sửa. Test có missing/duplicate joins, version, client, unaffected,
KEV cần review, shuffled input/ties, priority chỉ patch, thiếu Environmental,
sensitivity đổi thứ tự cùng cặp và M=0/1. Oracle FIRST 280/280 khớp, 0 mismatch.
Đây chưa thay cho N3 kiểm một case độc lập.

## Kết quả queue trên 6 cặp mapping

Master join many_to_one theo CVE, inventory many_to_one theo asset, Environmental
one_to_one theo cặp; không nhân dòng. Tất cả cặp mapping được giữ.

| CVE / asset | Applicability | Environmental | Queue | Rank context | Rank env-first |
|---|---|---:|---|---:|---:|
| 2018-25067 / WEB-01 | affected giả định | 7.2 | patch | 2 | 3 |
| 2022-46177 / API-01 | affected giả định | 8.8 | patch | 1 | 2 |
| 2023-22626 / ADMIN-01 | affected giả định | 9.3 | patch | 3 | 1 |
| 2023-22626 / API-02 | needs_review | null | review_required | null | null |
| 2023-30470 / MOB-01 | affected có điều kiện | 9.8 | review_required | null | null |
| 2023-41387 / MOB-02 | affected có điều kiện | 9.8 | review_required | null | null |

Sáu mapping rows, năm scored rows, một Environmental exclusion do unknown
applicability; queue 3 patch + 3 review. Không có unaffected được xác nhận trong
các cặp hiện tại. Mobile vẫn ở review dù tính được điểm; exposure client không
đồng nghĩa internet hoặc 0. API-02 candidate không phải bằng chứng đã cài PgHero.
Tất cả CVE nguồn của các cặp hiện tại KEV=false; nhánh KEV+review kiểm bằng fixture,
không giả tạo KEV trong dữ liệu thật.

## Sensitivity, không thay đổi population

Policy chính `context-v1`: KEV → exposure → Environmental → EPSS → CVE/asset.
Policy `context-v1-env-first`: KEV → Environmental → exposure → EPSS → CVE/asset.
Ba patch pairs giống hệt, thứ tự đổi vì ADMIN-01 internal có Environmental cao hơn.
Đây là sensitivity theo giả định, không chứng minh một policy tối ưu.

| Cặp | Base rank | Env rank | Base−Env | Context−Sensitivity |
|---|---:|---:|---:|---:|
| WEB-01 | 3 | 3 | 0 | -1 |
| API-01 | 1 | 2 | -1 | -1 |
| ADMIN-01 | 2 | 1 | 1 | 2 |

Delta dương là phương án thứ hai xếp sớm hơn. Base/Env rank tính cùng ba patch
pairs, không trộn 5 scored pairs với 396 CVE hoặc top-50. M=3, K=1/2 hợp lệ:

| So sánh | Jaccard@1 | Jaccard@2 |
|---|---:|---:|
| context / env-first | 0 | 1/3 |
| Base / Environmental | 0 | 1 |

EPSS 2026-09-29; KEV phát hành 2026-09-30, tải 2026-10-01 UTC. Không gọi đây là
kiểm định dự báo hay hiệu quả vận hành. Không-KEV không chứng minh chưa khai thác.

## Artifact, giới hạn và việc còn lại

- Output `data/processed/p3_n2/`; schema bổ sung tại `docs/phase-3-artifact-contract.md`.
- `context_metadata.json` ghi provenance cho C/D, `metadata.json` giữ riêng ranking B.
  Metadata/package manifest/ZIP checksum giúp N3 đối chiếu đúng revision.
- Chưa đạt target 15 mapping (6 tổng, 5 affected); không bịa product/version/cặp
  hoặc nhân Descartes để đủ số. N1 cần quyết định có bổ sung có căn cứ ở revision sau.
- Giữ logic FIRST all-X Scope-C exception, báo N1 để đính chính hướng dẫn.
- Chưa có case mobile/đối chiếu Environmental độc lập từ N3 khi fetch ngày 2026-10-19;
  điều này không chặn pipeline hiện tại, nhưng chưa đánh dấu xác nhận của N3.
- Phần E case tổng/playbook và kiểm caption N3 chưa làm trong yêu cầu mục 7–8 này.
- ZIP mới là bản chuẩn bị bàn giao; người dùng chuyển cho N1/N3 qua kênh nhóm.
  Không tự ghi “đã nhận” hoặc “đã gửi” khi chưa có xác nhận.
