# Phase 3 — Artifact contract N2 → N3

**Revision hiện hành 2026-10-20: context-v2.** Ranking schema/policy không đổi.
15 mapping rows (10 affected có điều kiện, 5 needs_review), 10 score rows,
15 dòng mỗi queue (8 patch/7 review), 8 comparison rows. Cấu trúc cột C/D giữ nguyên.
Phần C/D bên dưới ghi số r1/v1 lịch sử; không dùng 6/5/3 làm số lượng v2.
Config khai báo context_mapping_extension; metadata hash cả source r1 và extension.
K sensitivity=[1,2] trên M=8; không so population v2 trực tiếp với r1 M=3.
docs/analysis-results.md và playbook đã có bản N2; peer input/check/figure còn chờ.

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

## Bổ sung đợt C+D — 2026-10-19

Không đổi schema A+B. Context artifact schema riêng `p3-context-artifacts-v1`,
context `phase3-context-v1`, inventory vẫn `phase1-v1` vì không đổi tài sản/CR/IR/AR.
Không tự hiểu context đã có từ chuỗi version trong metadata B cũ.

### Files và khóa

- `cve_asset_mapping.csv`: giữ trường §8 của data contract, thêm `context_version`,
  `evidence_read_at` (ISO date), `exploit_conditions`, `evidence_limitations`.
  Key `(cve_id,asset_id)`, applicability affected/unaffected/needs_review.
  6 dòng: 5 affected có điều kiện giả định + 1 unknown candidate, không phải 6 affected.
- `environmental_scores.csv`: đúng 13 cột contract §8, key cặp, chỉ affected đủ
  vector/nhãn quan sát. `score_source=observed`, 5 dòng. Full vector giữ rõ tất cả X.
- `priority_queue.csv`: đúng 14 cột contract §9, key cặp, 6 dòng; policy `context-v1`.
  `priority_rank` integer nullable, chỉ patch có 1..M. Không được điền rank mobile từ Base.
- `priority_queue_env_first.csv`: cùng 6 cặp và queue_status, policy `context-v1-env-first`.
- `context_comparison.csv`: key cặp, chỉ 3 patch pairs có đủ Base/Environmental:
  `cve_id,asset_id,context_rank,dataset_version,context_version,sensitivity_rank,base_score,environmental_score,base_rank,environmental_rank,rank_delta_base_environmental,rank_delta_context_sensitivity,primary_policy_version,sensitivity_policy_version`.
- `context_sensitivity.json`: số cặp/coverage/exclusions/target, source dates,
  thay đổi thứ tự, Jaccard@K cùng patch population, định nghĩa delta và limitations.
- `context_metadata.json`: command/commit/dirty/packages/input/code/output hashes/bytes,
  số dòng và version; không ghi đè `metadata.json` dành cho ranking B.
- `environmental_first_check.json`: oracle FIRST source URL/SHA-256, 280 fixture,
  expected/actual (không phải dữ liệu nghiên cứu), seed và số mismatch.

### Null, policy và hướng delta

Missing không thành 0/false. API-02 thiếu product/version giữ needs_review;
unaffected (nếu có bằng chứng) luôn not_applicable. Client/unknown exposure và
missing signals vẫn review_required, KEV present cần xác minh sớm. CSV ô rỗng là null.

Policy context-v1: KEV ↓ → exposure internet/internal/isolated=2/1/0 ↓ →
Environmental ↓ → EPSS ↓ → CVE/asset ↑. Client không có numeric exposure.
Sensitivity chỉ hoán đổi exposure/Environmental sau KEV, giữ cùng patch pairs.
Base/Environmental rank là điểm giảm + CVE/asset tăng, cũng trên cùng 3 patch pairs,
không so với top-50 của cohort 396 hoặc thêm client vào một phía.

- `rank_delta_base_environmental = base_rank - environmental_rank`: dương là Env sớm hơn.
- `rank_delta_context_sensitivity = context_rank - sensitivity_rank`: dương là env-first sớm hơn.
- K context=[1,2]; nếu M<2 hoặc K>=M, Jaccard null + reason, không claim ưu tiên phân biệt.

N3 vẽ context chỉ từ artifact này, không tự tạo scorer/queue. 5 scored pairs không đồng
nghĩa 5 numeric patch priorities; hiển thị review list riêng. N3 còn phải đối chiếu độc
lập một case; N2 oracle check không tự đánh dấu thay N3. Quy tắc all-X identity trong
bản giao việc có ngoại lệ Scope Changed đã ghi `reports/p3_environmental_check.md`;
scorer tuân FIRST v3.1, không ép identity sai chuẩn.
