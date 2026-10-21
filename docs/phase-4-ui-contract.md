# Phase 4 — contract đọc offline do N3 bàn giao

Schema đề xuất `p4-ui-read-contract-v1`, ngày 2026-10-21. Đây là adapter đọc artifact;
không sửa data contract chung, policy hoặc scorer N2. Chưa triển khai ứng dụng.

## Bộ dữ liệu và kiểm toàn vẹn

Dataset bắt buộc `t08-v1.0-20261010`; ranking cohort `t08-v1.0-20261010:ranking`,
policy `cvss-epss-kev-first-v1`. Tích hợp N1 ngày 21/10 chuyển sang **context-v2**:
`phase3-context-v2`, policy `context-v1`, inventory `phase1-v1`;
schema N2 `p3-ranking-metrics-v1` và `p3-context-artifacts-v1`.
Không ghép hai context version. Gói thống nhất và receipt: `docs/handoffs/phase-3-complete-20261021.json`.

App cần Phase 1 release, gói Phase 2 nếu bật view AI và gói Phase 3 thống nhất N1.
Đường dẫn gốc là cấu hình triển khai, không hard-code `D:/Downloads` trong UI.
Kiểm receipt ZIP SHA-256/bytes trước giải nén; kiểm từng file theo manifest, rồi
dataset/context/model version và uniqueness. Sai hash/version/duplicate: dừng view
liên quan với lỗi cụ thể; không tự lấy dữ liệu khác. Thiếu Phase 2: view AI ghi
“Chưa có prediction đã xác minh”; các view có input hợp lệ vẫn dùng được.

## View và join

| View | Artifact / khóa | Trường bắt buộc và cách hiển thị |
|---|---|---|
| Tổng quan | N2 `ranking_metrics.json`, `metadata.json`; N3 `figures_manifest.json` | dataset/cohort/policy, `n=396`, `total_kev=3`; EPSS 2026-09-29, KEV released 2026-09-30T16:59:23.0688Z, retrieved 2026-10-01T11:29:35.854976+00:00, ba ngày riêng |
| Tra CVE | N2 `rankings.csv` left join Phase 1 `ranking_cohort.parquet` qua `cve_id`, one-to-one | `description`, `cvss_vector`, `cvss_base_score`, `cvss_source`, `cvss_type`, `epss`, `epss_date`, `is_kev`, `kev_date_added`, `cvss_rank`, `epss_rank`, `kev_first_rank`; nhãn “CVSS quan sát” |
| AI | Phase 2 `baseline/data/processed/predictions.csv`, `distilbert/predictions.csv`; khóa `(cve_id,model_version)` | `predicted_vector`, `predicted_base_score`, `vector_valid`, `prediction_error`, `split`, `prediction_usage`, dataset/model version; nhãn “Dự đoán”, tách khỏi Base quan sát |
| So rank AI | N3 `predicted_rank_comparison.csv`, `prediction_rank_metrics.json` | chọn split validation/test riêng; cùng `common_ids` observed/TF-IDF/DistilBERT, N/coverage/missing/invalid, K, tau-b, Jaccard, `rank_delta` |
| Bối cảnh | N2 `cve_asset_mapping.csv` left join `environmental_scores.csv` qua `(cve_id,asset_id)`; join inventory `config/assets.yaml` qua `asset_id` | `applicability`, `mapping_reason`, `affected_version_evidence`, `evidence_url`, `exploit_conditions`, `evidence_limitations`, `base_vector`, `base_score`, `environmental_vector`, `environmental_score`, CR/IR/AR, `modification_reason`, `score_source`, context/dataset version; inventory product/version/exposure/rationale/assumptions |
| Hành động | Mapping left join N2 `priority_queue.csv` qua cùng cặp, one-to-one | `queue_status`, nullable `priority_rank`, `priority_reason`, `recommended_action`, `exposure`, `applicability`, `is_kev`, `epss`, `environmental_score`, policy/context version |
| Hình | N3 `reports/figures/phase3/*.{png,svg}` + `reports/p3_figures.md` | chỉ hiển thị hình có trong manifest; top-50 gồm cả trang 1–25 và 26–50; nguồn/caption/N/K/đơn vị đi cùng hình |

Với tra CVE, nếu hai nguồn có cùng trường thì kiểm bằng nhau trước khi chọn giá trị;
không dựa vào thứ tự dòng hoặc suffix ngầm. Mapping là bảng dẫn cho bối cảnh: 15 cặp
ở v2; score có 10, queue có 15 (8 patch/7 review). Không inner join làm mất API-02 hoặc client review.
Context comparison là 8 cặp patch có đủ điểm, không phải toàn bộ queue hay cả 10 score.

## Quy tắc kiểu dữ liệu và trạng thái

- CSV UTF-8; ID/version là string, không suy kiểu số; rank là integer nullable,
  score 0–10, EPSS 0–1. `False` phải parse boolean, không dùng `bool("False")`.
- Ô trống/null hiển thị **N/A + lý do nguồn**; 0 hợp lệ vẫn hiển thị 0.
  Không biến null score/rank/recall thành 0. API-02 thiếu Environmental; giữ review.
- Client MOB-01/MOB-02 có Environmental 9.8 nhưng `priority_rank=null`;
  luôn hiện trong review cùng reason/action. Không gán exposure internet hoặc tự rank.
- Không có KEV không đồng nghĩa chưa từng bị khai thác. KEV-first không có điểm
  severity tổng hợp và không được trình bày như thắng benchmark recall độc lập.
- Recall chỉ CVSS/EPSS; KEV-first recall N/A với `policy_uses_kev_directly`.
  Tau-b dùng score gốc; app chỉ đọc metric, không tính lại từ rank đã phá hòa.
- TF-IDF: `tfidf-v1-n1-reproduction-20261017`; DistilBERT: `distilbert-v1-n1-20261017`.
  Loại bản `-dummy`; chỉ dùng `prediction_usage=evaluation`, split validation/test
  khớp ML release. Mobile case nằm train nên view AI ghi không có prediction held-out,
  không ghép train để lấp đủ 396.
- `rank_delta=observed_rank-predicted_rank`, dương nghĩa dự đoán xếp sớm hơn.
  K=10/20/50 chỉ chọn lọc khi K<N; N<2 hoặc metric undefined hiển thị N/A + reason.
- Nút sort/filter chỉ đổi cách xem, không ghi đè rank nguồn/cohort. Không chấm điểm,
  train/inference hoặc gọi API khi mở app; không có trường API key trong contract.

## Luồng demo chấp nhận

1. Mở tổng quan: 396 CVE/3 KEV, ba ngày nguồn riêng; xem scatter và đủ hai trang top-50.
2. Tra `CVE-2023-41387`: Base 9.1, EPSS 0.00874, rank 30/128/127; view AI N/A vì train.
3. Chọn MOB-02: hiển thị giả định iOS/plugin 1.11.1, Environmental 9.8, review_required,
   priority rank N/A và lý do; mở [case mobile](cases/p3-mobile-n3.md).
4. Mở API-02: vẫn thấy cặp mapping chưa rõ applicability, Environmental N/A, review.
5. Chọn AI validation rồi test: N=69 rồi108, không gộp; hiển thị coverage 100% cho r1
   prediction hiện có và giải thích đây là thứ tự severity, không đo hiệu quả vá.

N1/N2 chịu trách nhiệm chốt tích hợp chung; tài liệu này không khẳng định app Phase 4
đã chạy hoặc toàn nhóm đã hoàn tất Phase 3.
