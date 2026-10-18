# Phase 3 — Artifact contract N2 → N3

Schema `p3-ranking-metrics-v1`, chốt 2026-10-18 trước lần chạy B.
N2 sở hữu producer; N3 đọc artifact, không tự tính lại bằng cách đổi cohort/tie-break.
Không sửa `docs/data_contract.md` hoặc schema ranking 11 cột hiện có.
Đây là bản sẵn sàng gửi, chưa có xác nhận N3 nhận schema.

## Snapshot và cấu hình

Dataset `t08-v1.0-20261010`, cohort `t08-v1.0-20261010:ranking`, policy
`cvss-epss-kev-first-v1`, context `phase3-context-v1` (dự kiến cho phần C/D,
chưa có Environmental ở B). N=396, tổng KEV=3; CVSS dùng observed.
EPSS 2026-09-29; KEV phát hành 2026-09-30T16:59:23.0688Z,
tải 2026-10-01T11:29:35.854976+00:00. Ba mốc khác nhau.

`config/phase3.yaml` chốt K=[10,20,50], ngưỡng minh họa CVSS>=7.0/EPSS>=0.10.
Không dùng ngưỡng để lọc cohort hoặc đổi ngưỡng theo kết quả.

## Files trong p3_n2/

- `rankings.csv`: nguyên 11 cột contract §7, UTF-8/LF, 396 ID duy nhất.
  Ba rank là vị trí 1..N theo policy; không dùng rank phá hòa để tính tau-b.
- `ranking_metrics.json`: schema/dataset/cohort/policy/context, N (`n`), `total_kev`,
  `k`, `source_dates`, `kendall_tau_b` (value/reason/inputs/variant), các mảng
  `topk`, `overlap`, định nghĩa delta, ngưỡng và bảng đếm 2x2 minh họa, limitations.
- `topk_metrics.csv`: `policy,k,n,kev_total,kev_hits,kev_recall,cutoff_tie_count,selected_from_cutoff_tie,selected_n,effective_k,selection_is_discriminating,selection_reason,kev_recall_reason`.
  Policy enum `cvss`, `epss`, `kev_first`; khóa `(policy,k)`.
- `overlap.csv`: `policy_a,policy_b,k,intersection,union,jaccard`.
  Mỗi cặp không thứ tự xuất đúng một lần theo thứ tự cvss/epss/kev_first; khóa `(policy_a,policy_b,k)`.
- `rank_deltas.csv`: `cve_id,cvss_rank,epss_rank,kev_first_rank,rank_delta_cvss_epss`.
  Một dòng/ID, ID tăng; delta=CVSS rank trừ EPSS rank, dương nghĩa EPSS xếp sớm hơn.
- `metadata.json`: phiên bản, ngày nguồn, command/commit, trạng thái tracked dirty,
  Python/package versions, SHA-256/bytes của input/config/code/output, số dòng CSV.
  Không tự hash chính metadata; ZIP bàn giao có checksum riêng.

## Định nghĩa và null

- Jaccard=intersection/union tại cùng K trên cùng 396 ID.
- Kendall tau-b tính bằng `scipy.stats.kendalltau(variant='b')` trên
  `cvss_base_score` và `epss` gốc. N<2/điểm hằng: JSON null kèm reason.
  Tham chiếu: https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.kendalltau.html.
- CVSS/EPSS Recall@K=kev_hits/kev_total. Tổng KEV=0: null, `no_kev_in_cohort`.
  KEV-first luôn null, `policy_uses_kev_directly`, vẫn báo hits mô tả.
- CSV null là ô rỗng, không phải 0; JSON null đúng chuẩn, không NaN/Infinity.
  Các trường reason null/rỗng nếu chỉ số hợp lệ. KEV không có trong catalog không
  phải nhãn âm khai thác. Không gọi Recall là accuracy/precision/false-positive rate.
- Cutoff tie theo score gốc (CVSS/EPSS) hoặc bộ KEV/EPSS/Base; không gồm ID.
  `cutoff_tie_count` đếm toàn nhóm kể cả khi nhóm chỉ có 1; `selected_from_cutoff_tie`
  đếm số trong nhóm được chọn. Không đổi cách chọn top-K để tránh hòa.
- K phải nguyên dương, duy nhất, không rỗng. K>=N lấy cả cohort, effective_k=N,
  selection_is_discriminating=false và reason `k_at_least_n_selects_whole_cohort`.
  N3 không vẽ trường hợp này như bằng chứng policy có phân biệt.
- Thiếu tín hiệu, ID trùng/khác cohort, rank sai hoặc version sai: dừng lỗi,
  không impute 0/false, không silently drop rows.

## Cách đọc cho N3

Đợt A đủ scatter/top-rank. Đợt B bổ sung metric/overlap/delta và provenance.
N3 dùng cột `kev_recall_reason` khi tạo caption/null display; total_kev chỉ 3.
Đọc `metadata.json` và kiểm SHA trước khi vẽ, không sửa CSV bằng Excel rồi lưu lại.
Chưa có Environmental/queue ở đợt này; chúng sẽ có contract/version bổ sung rõ ràng.
