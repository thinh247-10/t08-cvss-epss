# Phase 3 — N3: nhật ký kiểm tra hình

**Trạng thái mới nhất (2026-10-20): hoàn tất phạm vi plots với gói context r1 đã xác minh.**
Xem mục cuối “Kiểm tra context r1”. Các mục ngày 2026-10-18 bên dưới là lịch sử;
trạng thái thiếu context ở lần chạy cũ đã được giải quyết, không phải trạng thái hiện tại.

Ngày kiểm tra: **2026-10-18 (Asia/Saigon)**. Phạm vi theo yêu cầu cuối: scatter và top-50 hai trang. Phần A hoàn tất; không đánh dấu toàn Phase 3 hoàn tất.

## Dữ liệu và môi trường

- Phase 1 verifier đã trả `PHASE1 RELEASE OK` (14 file); dataset `t08-v1.0-20261010`.
- Input: `data/processed/p3_n3_input/rankings.csv`, 48.438 byte, SHA-256 `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.
- Đủ 396 ID duy nhất, 3 KEV; không lọc/thêm CVE. `scatter_source.csv` đủ 396 dòng; `top50_long.csv` đủ 150 dòng = 50 mỗi policy.
- Python **3.13.16**, matplotlib **3.11.2**; dùng `.venv` của repo. `pip check`: không có dependency lỗi.
- EPSS **2026-09-29**; KEV phát hành **2026-09-30**, tải **2026-10-01 UTC**. Giữ ngày nguồn riêng trong hình, caption và manifest.
- Ngưỡng minh họa 7.0/0.10 khớp config N2 đã nhận và kiểm hash, không thay score/rank. Gói N2 A+B có sẵn nhưng không dùng để xuất thêm hình trong lần chạy phần A này.

## Lệnh đã chạy

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
.\.venv\Scripts\python.exe -m src.analysis.compare_rankings --output data/processed/p3_n3_input/rankings.csv
.\.venv\Scripts\python.exe -m src.analysis.plots --rankings data/processed/p3_n3_input/rankings.csv --output-dir reports/figures/phase3 --tables-dir data/processed/p3_n3
.\.venv\Scripts\python.exe -m unittest tests.test_plots tests.test_rankings -q
.\.venv\Scripts\python.exe -m pip check
```

**18 tests đạt**: 10 plot tests và 8 ranking tests. Kiểm đủ ID/top-K, không mutate frame, trùng/missing/rank gap, giữ zero, N/A, thiếu input CLI, chặn ghi đè input, hash manifest và smoke PNG/SVG. Fixture synthetic chỉ nằm trong test/temp, không đi vào output nghiên cứu. Test không so từng pixel.

## Kiểm tra trực quan thực tế

Đã mở cả ba PNG và render cả ba SVG bằng Chrome headless trên file cục bộ, xem ảnh render sau sửa. Browser tích hợp lỗi `missing field sandboxPolicy`, nên dùng Chrome cục bộ. Ảnh QA tạm trong `data/processed/p3_n3_qa/`, không thuộc bộ hình nghiên cứu.

| File trong reports/figures/phase3 | Đã xem | Kết quả cuối |
|---|---|---|
| cvss_epss_scatter.png / .svg | PNG + SVG render | Trục X 0–10, Y 0–1; 3 KEV hình thoi khác màu; nhãn/legend/ngày đọc được |
| top50_three_policies_p1.png / .svg | PNG + SVG render | Ba cột CVSS/EPSS/KEV-first, đủ vị trí 1–25, ID/badge đọc được |
| top50_three_policies_p2.png / .svg | PNG + SVG render, kiểm riêng header | Đủ vị trí 26–50 và tên ba policy, cùng bố cục trang 1; badge CVSS ở vị trí 32 |

Lỗi đã phát hiện và sửa:

1. Nhãn KEV gần EPSS=1 chồng tiêu đề; chuyển nhãn xuống dưới điểm, tăng khoảng cách tiêu đề.
2. Marker sát biên trục bị cắt; cho phép vẽ trọn marker, giữ nguyên tọa độ và trục 0–1.
3. SVG dạng text bị thay font vì máy xem không có DejaVu; nhúng glyph outlines (`svg_fonttype: path`) để PNG/SVG giữ cùng kiểu chữ. Dữ liệu truy nguyên vẫn ở CSV.

Không còn nhãn chồng/cắt quan sát thấy ở kích thước xuất. Scatter có các CVE trùng tọa độ nên không thể đếm 396 điểm bằng mắt; đã kiểm tổng phần tử scatter và bảng nguồn. Dữ liệu thật không có EPSS=0; test synthetic xác nhận zero không bị bỏ.

## Đối chiếu 5 CVE mỗi policy

So trực tiếp rank, score, EPSS và badge trong `top50_long.csv` với ranking nguồn theo `cve_id`; dòng nguồn tính cả header. Các vị trí này bao phủ hai trang và có cả KEV/non-KEV.

| Policy | Rank | CVE | Badge KEV | Dòng CSV nguồn |
|---|---:|---|---|---:|
| cvss | 1 | CVE-2014-125052 | False | 4 |
| cvss | 3 | CVE-2021-36393 | False | 11 |
| cvss | 25 | CVE-2024-55636 | False | 394 |
| cvss | 32 | CVE-2024-38475 | True | 316 |
| cvss | 50 | CVE-2024-34001 | False | 281 |
| epss | 1 | CVE-2023-44487 | True | 183 |
| epss | 3 | CVE-2023-23752 | True | 70 |
| epss | 25 | CVE-2024-38473 | False | 314 |
| epss | 32 | CVE-2023-30943 | False | 126 |
| epss | 50 | CVE-2024-22259 | False | 240 |
| kev_first | 1 | CVE-2023-44487 | True | 183 |
| kev_first | 3 | CVE-2023-23752 | True | 70 |
| kev_first | 25 | CVE-2024-38473 | False | 314 |
| kev_first | 32 | CVE-2023-30943 | False | 126 |
| kev_first | 50 | CVE-2024-22259 | False | 240 |

## Giới hạn và đầu ra

[Caption](p3_figures.md) và [manifest](../data/processed/p3_n3/figures_manifest.json) lưu provenance, hashes/bytes, phiên bản, command, dependencies, N/K và trạng thái. Manifest chỉ chứng nhận các file được liệt kê trong lần chạy này; output từ công việc trước vẫn được giữ nguyên.

Environmental/context/queue chưa được N2 giao. Không dùng số giả hoặc tự tính thay. Chỉ 3 KEV; đây là mô tả snapshot, không kết luận hiệu quả dự báo tương lai hoặc coi non-KEV là chưa từng khai thác.

## Bổ sung phần B — 2026-10-19 (Asia/Saigon)

Đã đọc contract N2 trong `data/processed/p3_n2_received/phase-3-artifact-contract.md`,
schema **p3-ranking-metrics-v1**. Bản contract ở remote N2 được đọc sau fetch cũng
chỉ quy định A+B, ghi rõ chưa bàn giao Environmental/queue. Không checkout hoặc
ghi đè file của N2. Chỉ sửa code/config/test và báo cáo hình thuộc N3.

### Kiểm integrity và version trước/sau xuất hình

ZIP `D:/Downloads/n2_p3_step_b_20261018.zip`: **19.198 byte**, SHA-256
`c3aacd4e7b8afddc5950365c929c71358a56e2d794a3d37626feb714d7508945`.
Đã đối chiếu CRC và byte của cả **9 thành viên** ZIP với thư mục nhận; metadata,
contract và config không được tự thay thế. Hash/bytes của các CSV/JSON đọc vào
được kiểm theo metadata. Không chỉ dựa vào metadata tự khai hash của chính nó.

Các version khớp giữa config N2/metadata/metrics/ranking:
dataset `t08-v1.0-20261010`, cohort `t08-v1.0-20261010:ranking`,
policy `cvss-epss-kev-first-v1`, context dự kiến `phase3-context-v1`, N=396/KEV=3.
Ba ngày nguồn khớp giữa metadata/config/metrics; giữ riêng EPSS 2026-09-29,
KEV phát hành 2026-09-30 và tải 2026-10-01 UTC.

Manifest lần chạy mới có **11 input + 14 output**; sau khi xuất đã đọc lại từng
file và kiểm SHA-256/bytes đều khớp. Input N2 giữ nguyên; 9 dòng overlap được
sao chép nguyên giá trị sang `overlap_plot.csv`; 6 dòng Recall CVSS/EPSS giữ đúng
hits/denominator/rate. Ba dòng Recall KEV-first trong CSV nguồn vẫn rỗng với reason
`policy_uses_kev_directly`; không đổi thành 0 và không đưa vào đường Recall.

### Lệnh thực tế và kiểm thử

```powershell
.\.venv\Scripts\python.exe -m src.analysis.plots --rankings data/processed/p3_n3_input/rankings.csv --output-dir reports/figures/phase3 --tables-dir data/processed/p3_n3 --n2-dir data/processed/p3_n2_received/p3_n2
.\.venv\Scripts\python.exe -m unittest tests.test_plots tests.test_rankings -q
git diff --check -- src/analysis/plots.py tests/test_plots.py config/phase3_plots.yaml
```

**29 tests đạt: 21 plot tests + 8 ranking tests.** Có kiểm N/A còn NaN trong dữ
liệu vẽ, không có marker ở điểm 0 giả, Recall chỉ CVSS/EPSS, rate không mâu thuẫn
hits/denominator, context ghép bằng cặp dù đảo dòng, thiếu/trùng/blank key báo lỗi,
không mutate input, checksum/version/missing contract và chặn output vào thư mục
producer. Không so pixel và không chạy lại producer/scorer/ranking policy.

### Đã xem từng PNG và SVG render

Trình duyệt tích hợp không kết nối được; đã dùng Chrome headless cục bộ render
cả 5 SVG, rồi mở ảnh render và cả 5 PNG bằng trình xem ảnh. Ảnh QA mới nằm trong
`data/processed/p3_n3_qa/*-b-20261019-svg.png`; đây là ảnh kiểm tra, không phải
output nghiên cứu. SVG nhúng glyph outlines, không phụ thuộc font ở máy nhận.

| File PNG + SVG trong reports/figures/phase3 | Quan sát trực tiếp |
|---|---|
| cvss_epss_scatter | Marker/nhãn 3 KEV, legend và ngày nguồn rõ; marker sát biên không cắt |
| top50_three_policies_p1 | Header 3 policy và ID ở vị trí 1–25 đọc được; badge KEV đúng |
| top50_three_policies_p2 | Header và vị trí 26–50 rõ; badge CVSS ở vị trí 32, không đổi thành top-25 |
| topk_overlap | K=10/20/50, trục Jaccard 0–1; hai đường trùng vẫn thấy marker tròn/x và nét liền/đứt; đường EPSS/KEV-first=1 |
| kev_recall_at_k | Chỉ 2 đường CVSS/EPSS, nhãn 0/3, 1/3, 3/3 đọc được; legend/nhãn ở K=50 không bị cắt |

Không phát hiện nhãn/legend bị chồng hoặc cắt trong bản xuất này. Hai đường
overlap trùng là đúng số liệu, được nêu trong caption; không dịch tọa độ để tạo
khác biệt giả. Tính chọn lọc K và mẫu số 3 KEV được ghi rõ.

### Đối chiếu thủ công so với CSV

Đọc từng dòng CSV dưới đây và đối chiếu vị trí đường/nhãn trên cả PNG/SVG.
Dòng tính cả header. Không tính lại tập top-K/Jaccard/recall để thay số N2.

| overlap.csv: dòng | Policy pair | K | Jaccard nguồn và vị trí trên hình |
|---:|---|---:|---:|
| 2 | cvss / epss | 10 | 0,05263158 |
| 3 | cvss / kev_first | 10 | 0,05263158 |
| 4 | epss / kev_first | 10 | 1,0 |
| 5 | cvss / epss | 20 | 0,05263158 |
| 6 | cvss / kev_first | 20 | 0,05263158 |
| 7 | epss / kev_first | 20 | 1,0 |
| 8 | cvss / epss | 50 | 0,11111111 |
| 9 | cvss / kev_first | 50 | 0,11111111 |
| 10 | epss / kev_first | 50 | 1,0 |

| topk_metrics.csv: dòng | Policy | K | Nhãn được kiểm |
|---:|---|---:|---|
| 2 | cvss | 10 | 0/3 (0,0%) |
| 3 | epss | 10 | 3/3 (100,0%) |
| 4 | kev_first | 10 | N/A, policy_uses_kev_directly; không vẽ |
| 5 | cvss | 20 | 0/3 (0,0%) |
| 6 | epss | 20 | 3/3 (100,0%) |
| 7 | kev_first | 20 | N/A, policy_uses_kev_directly; không vẽ |
| 8 | cvss | 50 | 1/3 (33,3%) |
| 9 | epss | 50 | 3/3 (100,0%) |
| 10 | kev_first | 50 | N/A, policy_uses_kev_directly; không vẽ |

Tau-b trong caption được chép từ `ranking_metrics.json`:
`value=0.30569771817081276`, `variant=b`, inputs=`cvss_base_score, epss`, reason=null.
Không dùng thứ hạng đã phá hòa để tính lại. 15 CVE/rank/badge của bảng phần A ở
trên vẫn khớp bản hình xuất lại; không thay cohort hoặc tie-break.

### Context/queue: lịch sử trước khi nhận r1 — dữ liệu thật còn thiếu

Đã nối CLI tới reader của `environmental_scores.csv`, `context_comparison.csv`,
`priority_queue.csv` và metadata/contract bổ sung. Khi nhận gói, cần truyền rõ
`--context-dir`, `--context-contract`, `--context-schema`, `--queue-policy-version`
và context version khớp gói; ZIP có thể kiểm bằng ba cờ receipt
`--context-archive`, `--context-archive-sha256`, `--context-archive-bytes`.
Không tự đặt schema/version thay N2.

Reader kiểm hash/bytes cả 3 bảng và version trước khi join; chỉ so Base→Environmental
trên **cùng cặp đầy đủ điểm**, giữ dòng thiếu điểm trong bảng excluded. N<2 không
vẽ đường severity giả. Queue giữ mọi dòng nguồn và tách bảng đếm patch /
review_required / not_applicable; client/unknown review có priority_rank=null
được giữ cùng reason/action, hiển thị N/A trong báo cáo. Không gọi scorer hoặc
tái chạy policy queue. Có hình trạng thái queue tách khỏi hình severity.

CLI context đã chạy với **fixture synthetic chỉ trong tempfile**: 4 dòng score,
2 cặp đủ điểm, 2 dòng excluded, queue 4 cặp gồm 1 client review. Đây là bằng chứng
đường chạy/kỹ thuật, **không phải số liệu N2 thật**, không đưa vào bộ hình nghiên cứu.

Hiện chưa có supplemental contract hoặc 3 CSV context trong repo/gói nhận/Downloads
đã kiểm. Vì vậy **chưa xuất `context_rank_changes` hoặc `priority_queue_status`
từ dữ liệu thật**; số client review thực tế vẫn N/A. Manifest ghi
`part_b_metrics_status=complete`, `part_b_context_status=pending_inputs`,
`status=partial`. Chỉ đánh dấu context hoàn tất sau khi nhận và kiểm gói N2.

## Kiểm tra context r1 — 2026-10-20 (Asia/Saigon)

Đã đọc contract trong chính ZIP người dùng chỉ định; không trộn với revision mới hơn
trên branch N2. ZIP `D:/Downloads/n2_p3_context_20261019_r1.zip`: **45.788 byte**,
SHA-256 `8a2fc661f369e1fa6327472a9464aa01277d4e5406c3eefdd46e416d175069d9`,
khớp hash người dùng cung cấp. Đã kiểm CRC, byte nội dung từng member sau giải nén,
hash/bytes của 21 file trong `handoff_manifest.json`, rồi kiểm manifest lại sau khi xuất.
Không sửa file N2. Contract hash:
`2c40c071c5fd1f81323d1a592df30981bf4731597b09f11a86c524175080fe44`.

- Dataset: `t08-v1.0-20261010`; ranking cohort: 396 ID, 3 KEV, cùng input SHA-256 phần A.
- Handoff schema: `p3-n2-handoff-manifest-v1`; context schema: `p3-context-artifacts-v1`.
- Context: `phase3-context-v1`; queue policy: `context-v1`; producer commit: `2b9d6787491353de4dafbaf5e858b1a1849b0813`.
- Metadata context là `context_metadata.json`; `metadata.json` thuộc A+B. Config đầy đủ 720 byte được kiểm theo handoff envelope, không ép khớp receipt config A+B cũ 690 byte.
- EPSS: 2026-09-29; KEV released: 2026-09-30T16:59:23.0688Z; retrieved: 2026-10-01T11:29:35.854976+00:00. Ngày nguồn riêng được giữ trong caption và manifest.

### Chạy và kết quả

```powershell
.\.venv\Scripts\python.exe -m src.analysis.plots --rankings data/processed/p3_n3_input/rankings.csv --output-dir reports/figures/phase3 --tables-dir data/processed/p3_n3 --n2-dir data/processed/p3_n2_context_20261019_r1_received/p3_n2 --context-dir data/processed/p3_n2_context_20261019_r1_received/p3_n2 --context-contract data/processed/p3_n2_context_20261019_r1_received/docs/phase-3-artifact-contract.md --context-schema p3-context-artifacts-v1 --context-version phase3-context-v1 --queue-policy-version context-v1 --context-archive D:/Downloads/n2_p3_context_20261019_r1.zip --context-archive-sha256 8a2fc661f369e1fa6327472a9464aa01277d4e5406c3eefdd46e416d175069d9 --context-archive-bytes 45788
.\.venv\Scripts\python.exe -m unittest tests.test_plots tests.test_rankings -q
```

CLI exit 0: `status=complete`, `figures=7`, `n=396`, `context_status=ready`, `pending=[]`.
31 tests pass. Bao gồm hash/version sai, null/N/A, mất client trong queue, đưa client
vào comparison trái contract, bảo vệ thư mục N2 và regression trên r1 thật.

Đầu ra: 7 PNG + 7 SVG; `top50_long.csv` 150 dòng; scatter 396 dòng;
overlap 9 dòng; recall 6 dòng CVSS/EPSS; Environmental 5 dòng;
context comparison 3 dòng; excluded 3 dòng; queue 6 dòng; review 3 dòng.
Các file được chứng nhận cùng hash/bytes nằm trong `data/processed/p3_n3/figures_manifest.json`.

### Đối chiếu thủ công với CSV

`context_comparison.csv` và `environmental_scores.csv` đều dùng khóa `(cve_id, asset_id)`.
Dòng tính cả header. Hình chỉ dùng rank N2 cung cấp; không chạy scorer/ranking/policy.

| Dòng comparison | Cặp CVE / asset | Base → Environmental | Rank Base → Env trên PNG/SVG |
|---:|---|---|---|
| 2 | CVE-2018-25067 / WEB-01 | 7.2 → 7.2 | 3 → 3, hai marker trùng đúng vị trí |
| 3 | CVE-2022-46177 / API-01 | 8.1 → 8.8 | 1 → 2 |
| 4 | CVE-2023-22626 / ADMIN-01 | 7.5 → 9.3 | 2 → 1 |

Theo contract r1, hai tập rank cùng **3 cặp patch có đủ điểm**, không phải cả 5 cặp
có Environmental. `environmental_source.csv` giữ đủ 5 cặp; 2 client không bị mất.
Queue giữ đủ 6 mapping; `context_excluded.csv` giữ cả 2 client và 1 cặp chưa rõ applicability.

| Dòng priority_queue.csv | Cặp / trạng thái | Đối chiếu bảng và báo cáo |
|---:|---|---|
| 2–4 | WEB-01, API-01, ADMIN-01 / patch | Tổng 3; priority rank nguồn lần lượt 2, 1, 3, không nhầm với severity rank |
| 5 | CVE-2023-22626 / API-02 / review_required | Environmental và priority rank null; giữ N/A; giữ nguyên reason/action |
| 6 | CVE-2023-30470 / MOB-01 / client review | Environmental 9.8 được giữ; priority rank N/A; reason yêu cầu kiểm attack path |
| 7 | CVE-2023-41387 / MOB-02 / client review | Environmental 9.8 được giữ; priority rank N/A; reason/action được giữ |

Hình queue có patch=3, review_required=3, not_applicable=0; chú thích client review=2.
Overlap được đối chiếu lại với 9 dòng CSV: hai series CVSS trùng nhau ở
0.05263158 / 0.05263158 / 0.11111111; EPSS/KEV-first = 1 tại cả ba K.
Recall chỉ có CVSS (0/3, 0/3, 1/3) và EPSS (3/3 cả ba K).
Recall KEV-first vẫn null trong nguồn với reason `policy_uses_kev_directly`, không được vẽ thành 0.

### Mở hình và lỗi đã sửa

Đã mở PNG của context, queue, overlap, recall và render cả 4 SVG bằng Chrome headless
ẩn, rồi mở screenshot để kiểm. Browser runtime của skill không khả dụng do thiếu
`sandboxPolicy`; Chrome cục bộ là phương án kiểm SVG đã chạy thành công.
Ảnh QA lưu trong `data/processed/p3_n3_qa/*-context-r1-svg.png`.

Phát hiện legend context đè nhãn trục ở lần xuất đầu. Đã chuyển legend sang vùng
riêng dưới nhãn trục, xuất lại, mở cả PNG/SVG và thêm regression kiểm hai bounding box
không giao nhau. Bản cuối không còn cắt/chồng chữ; CVE/asset đầy đủ, mũi tên và glyph
đọc được. Queue/overlap/recall không phát hiện lỗi bố cục. Các hình phần A dùng dữ liệu
và bố cục đã được kiểm ở phần lịch sử phía trên.

Phạm vi hoàn tất là đọc artifact và xuất/kiểm hình. Không train, không gọi API dữ liệu,
không tính lại policy; việc đối chiếu điểm CSV không thay thế Environmental crosscheck
độc lập và không tuyên bố toàn Phase 3 hoàn tất.
