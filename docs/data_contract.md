# Data contract — Giao diện bàn giao T08

> **Thiết kế v0.1 để triển khai, chưa phải schema của một dataset đã tạo.**
> Chủ trì: Người 1. N2 review scope/thời gian/nguồn; N3 review nhãn/split.
> Áp dụng cùng [kế hoạch 30 ngày](05-ke-hoach-phan-cong.md). Ngày 2 chốt; ngày 7 khóa v1 sau pilot.

## 1. Quy tắc chung

- Mọi đường dẫn tương đối tính từ thư mục gốc repo; UTF-8, timestamp UTC dạng ISO 8601, ngày dạng `YYYY-MM-DD`.
- `cve_id` viết hoa theo định danh nguồn. Không giới hạn phần số CVE ở đúng 4 chữ số.
- Master một dòng/CVE; bảng context một dòng/cặp CVE–tài sản; prediction một dòng/CVE/model.
- Thiếu số dùng null/NaN đúng dtype; thiếu EPSS không phải 0. Boolean nullable phải phân biệt true, false, unknown.
- File CSV đọc với dtype được chỉ định; ô rỗng là missing. Không để chuỗi `"False"` bị hiểu là boolean true.
- JSON/list trong CSV phải serialize chuẩn JSON; Parquet có thể dùng list/struct. Không ghép URL bằng dấu phẩy không escape.
- Giữ raw nguồn bất biến theo lần tải; ghi checksum. Tất cả output có `dataset_version`; thay mẫu/nhãn/snapshot/split thì tăng version.
- Những file code/config ở đây là đích cần xây dựng. Nếu cần đổi tên/hàm, cập nhật đồng thời phase, contract và nơi dùng.

## 2. Cấu hình chung — tạo mới, không chứa secret

| File | Owner | Nội dung |
|---|---|---|
| `config/project.yaml` | N1 | Khoảng công bố; ngày snapshot T; paths; schema/dataset version; quy tắc chọn nhãn; ranh giới split; seed; scope policy; top-K |
| `config/assets.yaml` | N2 | Tài sản, phần mềm/phiên bản, vùng triển khai, exposure, CR/IR/AR, lý do; policy context/version |
| `config/model.yaml` | N3 | Input description; 8 tập nhãn; TF-IDF/classifier; transformer tùy chọn; seed; giới hạn thời gian và artifact paths |

Dùng YAML thì bổ sung thư viện đọc YAML vào requirements khi triển khai. Không tự ý chuyển qua config riêng trong mỗi notebook. N1 điều phối dependency; chỉ giữ thư viện thực sự sử dụng. API key đọc từ `.env`, không ghi vào metadata/log/config.

### Khoảng thời gian và tập huấn luyện

Đề xuất pilot: CVE công bố từ 2023-01-01 đến hết 2024-12-31. Train 2023; validation nửa đầu 2024; test nửa cuối 2024. Sau kiểm tra số lượng/lớp, nếu cần mở rộng năm thì ghi quyết định và ranh giới mới **trước khi xem kết quả test**.

Phân tích ranking chính là ảnh chụp dữ liệu tại một ngày T trong đợt thu thập: EPSS đúng ngày T, catalog KEV và thời điểm tải được lưu; ưu tiên tải KEV cùng ngày T. Nếu hai nguồn lệch thời điểm, ghi rõ khoảng lệch hoặc tải lại để đồng bộ. Không dùng EPSS tại `published + 30 ngày` riêng từng CVE cho bảng này.

NVD tải hiện tại có thể chứa mô tả/điểm chỉnh sửa sau ngày công bố. Chia theo thời gian không tự khôi phục dữ liệu lịch sử “as known then”. Báo đây là đánh giá trên snapshot hiện có; không tuyên bố dự báo hồi cứu không nhìn trước tương lai.

## 3. Dữ liệu nguồn và metadata

| Đầu ra | Chức năng | Kiểm tra chính |
|---|---|---|
| `data/raw/nvd_cves.parquet` | Bản trích NVD; vẫn giữ toàn bộ CVSS entries/configurations/CPE/references trong raw JSON hoặc struct | Pagination đủ, checkpoint không nhân CVE; không bỏ missing label |
| `data/raw/epss.parquet` | CVE, xác suất, percentile, ngày được trả về | Đúng ngày yêu cầu; [0,1]; phân biệt không có dữ liệu với lỗi tải |
| `data/raw/kev.parquet` | CVE trong catalog, dateAdded, ransomware và trường liên quan | Catalog tải/parse đầy đủ; giữ raw và metadata catalog |
| `data/raw/nvd/`, `data/raw/epss/`, `data/raw/kev/` | Cache raw theo lần tải, manifest và checksum | Có đường dẫn tra ngược mỗi nguồn; tránh ghi đè snapshot |
| `data/metadata.json` | Manifest dataset và giới hạn | Không chứa token/key |
| `data/sample/cves_sample.csv` | Mẫu thật cùng schema để phát triển song song | Kèm `data/sample/metadata.json`; không dùng để công bố chất lượng model |

Metadata tối thiểu: schema/dataset version; ngày bắt đầu/kết thúc thu thập; khoảng published; endpoint/params không có secret; retrieval time từng nguồn; EPSS requested/returned date; catalog version/dateReleased; checksum file raw/final; số dòng từng bước; missing từng trường; quy tắc chọn nhãn; scope policy; counts mỗi cohort/split; cấu hình split; trạng thái kiểm tra; hạn chế.

Phiên bản model EPSS nếu nguồn cung cấp thì lưu; không đoán từ ngày hoặc xem `version` của REST API là phiên bản model. Các giá trị chính thức và giới hạn truy vấn cần đối chiếu [EPSS API](https://api.first.org/epss/) và [EPSS data](https://www.first.org/epss/data).

## 4. Master — `data/processed/cves.parquet`

| Cột | Kiểu | Ý nghĩa / quy tắc |
|---|---|---|
| `cve_id` | string, unique, not null | Khóa ghép |
| `published`, `last_modified` | UTC timestamp | Thời gian do NVD cung cấp |
| `vuln_status` | string | Giữ trạng thái nguồn; không suy ra missing chỉ từ tên status |
| `description` | string nullable | Mô tả tiếng Anh; không bịa nếu thiếu |
| `cvss_version` | string nullable | Nhãn chính chỉ `3.1`; v2/v3.0/v4 giữ raw |
| `cvss_vector` | string nullable | Vector nguồn được chọn |
| `cvss_base_score` | float nullable, [0,10] | Điểm nguồn, có kiểm tra tính lại |
| `cvss_source`, `cvss_type` | string nullable | Nguồn metric và Primary/Secondary nếu có |
| `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A` | categorical nullable | Parse từ vector hợp lệ; không lấy từ prediction |
| `has_cvss31_label` | bool | Đủ vector v3.1 hợp lệ đã kiểm tra |
| `epss`, `epss_percentile` | float nullable, [0,1] | Xác suất và thứ hạng tương đối là hai đại lượng khác nhau |
| `epss_date` | date nullable | Ngày điểm EPSS thực tế trả về |
| `is_kev` | nullable bool | false chỉ khi đã đối chiếu catalog đầy đủ thành công |
| `kev_date_added` | date nullable | Ngày thêm vào catalog, không phải ngày khai thác đầu tiên |
| `kev_known_ransomware` | string nullable | Giữ giá trị nguồn, không tự suy diễn |
| `domain_tags` | list[string] | Tập con của web, mobile; có thể cả hai hoặc rỗng |
| `in_scope` | bool | Đủ bằng chứng được nhận vào cohort Web/mobile |
| `scope_reason` | string | Lý do nhận/loại/chờ review; không chỉ một keyword |
| `scope_evidence` | list[string] | URL advisory/CPE/references hỗ trợ; giữ trace raw |
| `scope_status` | enum | included / excluded / needs_review |
| `split` | string nullable | train / validation / test; null nếu không vào thí nghiệm NLP |
| `dataset_version` | string | Khớp metadata |
| `retrieved_at` | UTC timestamp | Thời điểm build/tổng hợp; metadata lưu riêng từng nguồn |

Lưu toàn bộ metric gốc. Chọn một nhãn v3.1 bằng quy tắc ổn định: metric hợp lệ từ `nvd@nist.gov` trước; tiếp theo Primary; rồi nguồn/vector theo thứ tự cố định. Đây là quy ước dataset, không khẳng định nguồn nào luôn đúng hơn. Metric cùng ưu tiên nhưng khác vector phải được log; ngoài NVD không tự gán tất cả là CNA.

Rejected vẫn truy được trong raw; loại khỏi cohort nghiên cứu và báo số lượng. Giữ CVE thiếu description/vector/EPSS trong master để phân tích missing. Không sửa vector nguồn khi thấy sai; ghi lỗi, cách xử lý và trạng thái đủ điều kiện.

### Nhãn CVSS v3.1

| Metric | Các lớp hợp lệ |
|---|---|
| AV | N, A, L, P |
| AC | L, H |
| PR | N, L, H |
| UI | N, R |
| S | U, C |
| C / I / A | N, L, H |

Thứ tự nhãn trong model mapping phải cố định và lưu cùng artifact. Metric X không phải nhãn Base cho bài toán NLP này. N2 kiểm chứng parser và scorer theo [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document).

### Điều kiện thuộc từng cohort

- **Ranking:** in_scope; không Rejected; Base/vector v3.1 hợp lệ; EPSS đúng T; trạng thái KEV xác định. Ba cách ranking dùng đúng cùng tập ID.
- **ML:** description có nội dung, nhãn đủ tám metric, không Rejected; split không chồng. Có thể mở rộng miền train nếu cần, nhưng lưu quyết định và báo kết quả Web/mobile riêng.
- **Context:** chỉ tạo mapping khi đã xem bằng chứng sản phẩm/phiên bản. Trường hợp chưa rõ đưa vào review; không ngầm coi là an toàn.
- **Case study:** ghi rõ thuộc cohort định lượng hay ví dụ bổ sung ngoài cohort. Case bổ sung không được âm thầm đưa vào top-50/F1.

Rà duplicate mô tả/nhóm sản phẩm để phát hiện leakage giữa split. Fit vectorizer, class weights và preprocessing có học tham số chỉ trên train; validation chọn tham số; test dùng đánh giá cuối.

## 5. Scope review — `data/annotations/scope_review.csv`

N2 đặt quy tắc và review, N1 xây `filter_scope.py`. Cột tối thiểu: cve_id, proposed_domain_tags, final_domain_tags, scope_status, reason, evidence_url, reviewer, reviewed_at, scope_policy_version. Đây là annotation của nhóm, không phải trường chính thức từ NVD.

Keyword/CWE giúp tạo ứng viên, chưa đủ xác nhận thuộc Web/mobile. CPE/advisory và chức năng sản phẩm quyết định; AV:N không đồng nghĩa Web. Với mobile, chứng minh thành phần ảnh hưởng là client/framework/SDK/nền tảng chạy ứng dụng. Rà cả mẫu được nhận lẫn mẫu bị loại để phát hiện thiên lệch; công bố quy trình và hạn chế.

## 6. Prediction và đánh giá NLP

`data/processed/predictions.csv`, N3 tạo. Khóa `(cve_id, model_version)`:

| Cột | Nội dung |
|---|---|
| cve_id, split, dataset_version, model_version | Truy vết và tránh trộn train/test |
| predicted_vector, predicted_base_score | Kết quả ước lượng, không thay CVSS nguồn |
| prediction_usage | evaluation / demo; evaluation chỉ validation/test tương ứng |
| pred_AV, pred_AC, pred_PR, pred_UI, pred_S, pred_C, pred_I, pred_A | Nhãn từng đầu ra |
| vector_valid, prediction_error | Kiểm tra vector/lỗi; không loại lỗi khỏi báo cáo mà không thống kê |

Output model khác: `models/baseline.joblib`, thư mục `models/distilbert/` nếu làm, label mapping/config; `reports/model_metrics.json`; `docs/model-card.md`; `notebooks/02_model_eval.ipynb`.

Metrics phải có số mẫu, dataset/split/model version, accuracy và macro-F1 từng metric, F1/support từng lớp, exact-vector accuracy, Base MAE/RMSE; mẫu số score chỉ gồm các prediction tính được và báo coverage/lỗi. Có thể thêm confidence nhưng không gọi xác suất chưa hiệu chỉnh là độ chắc chắn bảo mật. Chưa có nhãn của CVE mới thì không có ground truth để công bố accuracy trên CVE đó.

## 7. Ranking — `data/processed/rankings.csv`

N2 tạo; N3 hỗ trợ biểu đồ. Một dòng/CVE trong cohort cố định:

`cve_id, cvss_base_score, epss, is_kev, cvss_rank, epss_rank, kev_first_rank, dataset_version, epss_date, cohort_id, policy_version`.

- Thứ hạng xuất file là vị trí 1..N để chọn đúng K; CVSS/EPSS đồng điểm được phá hòa bằng CVE ID.
- KEV-first phá hòa theo EPSS giảm, CVSS giảm, CVE ID tăng.
- Tương quan cần xử lý ties theo điểm gốc (ví dụ Kendall tau-b), không lấy thứ hạng CVE ID phá hòa rồi giả vờ không có ties.
- Lưu toàn bảng; top-K lấy từ bảng đó. Không chỉ lưu 50 dòng khiến không tính được mẫu số.
- `Jaccard(A,B)=|A∩B|/|A∪B|`. `KEV coverage@K=|topK∩KEV_cohort|/|KEV_cohort|`; mẫu số 0 thì N/A.
- Nếu dùng `KEV fraction@K`, mẫu số là số hàng thực có trong top-K, không gọi đó là độ chính xác dự đoán khai thác thực tế.
- Top-50 khi N>50, ưu tiên N≥200; báo thêm top-10/20 nếu có ý nghĩa. N nhỏ không được dùng K=N để chứng minh ưu tiên tốt.
- Đây là phân tích mô tả tại snapshot. KEV không đầy đủ và có quan hệ với tín hiệu EPSS; không suy ra quan hệ nhân quả hoặc độ chính xác dự báo 30 ngày từ bảng này.

Ba panel top-50 và scatter chỉ gắn badge KEV. Có thể lưu thêm `reports/ranking_metrics.json`, `reports/figures/` kèm caption/cohort/version/ngày.

## 8. Inventory, mapping và Environmental

`config/assets.yaml`: asset_id unique, name, function, domain, product, version, exposure, data_type, CR/IR/AR, rationale, assumptions. Tài sản là giả định, không mô tả như hệ thống đã kiểm thử.

`data/processed/cve_asset_mapping.csv`, N2 tạo:

`cve_id, asset_id, applicability, product, assumed_version, affected_version_evidence, evidence_url, mapping_reason, reviewer, dataset_version`.

`applicability` ∈ affected / unaffected / needs_review. Mỗi cặp tối đa một dòng sau khi giải quyết bằng chứng xung đột; lưu nhiều nguồn trong trường JSON nếu cần. Có thể chỉ tạo ứng viên thay vì tích Descartes tất cả CVE×tài sản.

`data/processed/environmental_scores.csv`, N2 tạo cho cặp đủ bằng chứng ảnh hưởng:

`cve_id, asset_id, base_vector, base_score, environmental_vector, environmental_score, CR, IR, AR, modification_reason, score_source, dataset_version, context_version`.

- Luồng chính dùng CVSS quan sát; score_source=observed. Prediction là thí nghiệm riêng có model_version, không trộn vào bảng chính.
- Giữ vector Environmental đầy đủ và lý do thay đổi. Temporal không đánh giá thì E/RL/RC:X; modified metrics chưa có căn cứ thì X.
- Không tự đổi MAV:N thành A/L chỉ vì ở mạng nội bộ; không tự nâng MAC vì có WAF; không tự hạ tác động vì có backup/HA.
- Với tổ chức giả định, lý do là giả định có tài liệu, không tuyên bố đã kiểm chứng biện pháp trên hệ thống thật.
- N2 cung cấp một hàm tính Base dùng chung cho model evaluation. Kiểm tra Scope, Not Defined, zero impact và Roundup với công cụ/đặc tả FIRST.

Context được so trên cùng tập cặp có đủ Base/Environmental, hoặc theo từng tài sản. Nếu gộp một CVE qua nhiều tài sản phải nêu quy tắc; không đặt bảng 20 cặp cạnh top-50 toàn cohort rồi coi cùng mẫu.

## 9. Hàng đợi theo bối cảnh — `data/processed/priority_queue.csv`

N2 viết `src/analysis/context_priority.py`; đây là **chính sách minh họa của nhóm**, không phải chuẩn CVSS/EPSS/SSVC.

Trường tối thiểu: `cve_id, asset_id, applicability, is_kev, epss, environmental_score, exposure, queue_status, priority_rank, priority_reason, recommended_action, policy_version, context_version, dataset_version`.

Luồng: kiểm tra applicability → đưa affected vào đánh giá → dùng KEV, exposure, Environmental, EPSS để sắp ưu tiên → giải thích và chọn hành động. Unaffected lưu lý do ngoài hàng đợi vá; needs_review giữ trong danh sách cần xác minh. Không mất dấu CVE KEV khi thiếu thông tin.

Quy ước `exposure` trong inventory và hàng đợi:

| Giá trị | Ý nghĩa | `exposure_priority` của policy ban đầu |
|---|---|---|
| `internet` | Thành phần được triển khai cho phép truy cập từ Internet | 2 |
| `internal` | Thành phần chỉ cho phép truy cập từ mạng nội bộ theo giả định triển khai | 1 |
| `isolated` | Thành phần nằm trong vùng cách ly theo giả định đã ghi | 0 |
| `client` | Ứng dụng chạy trên thiết bị người dùng; chưa xác định đường tấn công chỉ từ vai trò này | Chưa định nghĩa, không gán số |

`client` là giá trị hợp lệ để mô tả inventory, nhưng không đồng nghĩa với một dịch vụ
public-facing hoặc một tài sản an toàn hơn. Với cặp CVE–tài sản `affected` có exposure
`client`, policy ban đầu đặt `queue_status=review_required`, `priority_rank=null` và ghi
`priority_reason` là chưa có quy tắc exposure cho client. Vẫn giữ cặp trong đầu ra và
ưu tiên xác minh khi có KEV; không bỏ mẫu hoặc tự gán exposure_priority=0.
N2 phải xem đường tấn công cụ thể (ví dụ nội dung từ xa, deep link, tệp hoặc truy cập
thiết bị), rồi đề xuất policy có version riêng trước khi xếp hạng tự động cho client.
Không tự đổi `client` thành `internet` chỉ vì ứng dụng có kết nối mạng.
Giá trị exposure thiếu hoặc chưa được policy hỗ trợ cũng đưa vào review.
Applicability vẫn được xét trước: `unaffected` nằm ngoài hàng đợi vá và `needs_review`
cần xác minh, không bị quy tắc exposure ghi đè. Các ca mobile vẫn có thể được phân tích
scope, applicability và Environmental khi đủ căn cứ trong lúc chờ policy xếp hạng.

Chính sách minh họa ban đầu cho những cặp **đủ dữ liệu và có exposure đã được policy hỗ trợ**: is_kev giảm, exposure_priority giảm (`internet`=2, `internal`=1, `isolated`=0), Environmental giảm, EPSS giảm, cve_id tăng, asset_id tăng. Đây là thứ tự cấu hình để phân tích, không phải kết luận exposure luôn quan trọng hơn tác động. N2 kiểm tra sensitivity với thứ tự khác trước khi đưa ra khuyến nghị.

Thiếu applicability/exposure/score/EPSS → queue_status=review_required và ưu tiên xác minh nếu có KEV; không gán số 0 rồi âm thầm đẩy cuối. Nếu tính tiếp một nhánh thiếu dữ liệu, phải đặt tên policy riêng và trình bày giả định.

SLA/hành động trong playbook là đề xuất cho tổ chức giả định, có người phụ trách và ngoại lệ (chưa có bản vá, gián đoạn dịch vụ, biện pháp tạm thời); không báo thời gian vá đo được nếu không có log vận hành.

## 10. Giao diện code và trách nhiệm

| Module | Owner | Giao diện dự kiến / mục đích |
|---|---|---|
| `collect/nvd_collector.py` | N1 | CLI khoảng ngày/output; phân trang/retry/cache; lưu raw và nguồn |
| `collect/epss_client.py` | N1 | Input CVE, date T, output; kiểm tra ngày và missing |
| `collect/kev_client.py` | N1 | Tải catalog, kiểm tra đầy đủ, lưu metadata |
| `collect/filter_scope.py` — mới | N1; N2 đặt quy tắc | Gắn scope từ bằng chứng/annotation, trả lý do và trạng thái |
| `collect/build_dataset.py` — mới | N1 | Join/parse/validate/split/output metadata; không tự train |
| `environmental/asset_inventory.py` | N2 | Đọc/validate inventory và mapping |
| `environmental/cvss_environmental.py` | N2 | Parser + Base/Environmental scorer dùng chung |
| `model/baseline.py` | N3 | Dummy + TF-IDF/Logistic Regression từng đầu ra, lưu artifact |
| `model/distilbert_multihead.py` | N3 | Encoder chung/8 head; thử nghiệm tùy điều kiện |
| `model/evaluate.py`, `model/predict.py` — mới | N3 | Đánh giá nhất quán và suy luận tái dùng artifact |
| `analysis/compare_rankings.py` | N2 | Cohort cố định, 3 chính sách, metrics/top-K |
| `analysis/plots.py` | N2 chủ trì; N3 hỗ trợ | Đọc kết quả, tạo hình; không tự đổi lọc/snapshot |
| `analysis/context_priority.py` — mới | N2 | Tạo queue, reason/action và review list |
| `app.py` — mới/tùy chọn | N3 | Hiển thị artifact và dự đoán; không train/tải API lại khi mở app |

Đường dẫn trong bảng đều dưới `src/` trừ `app.py`. Hàm/CLI cụ thể được chốt trong phase; gọi dưới dạng module `python -m src.…` nếu dùng import nội bộ để tránh lỗi đường dẫn.

## 11. Kiểm tra trước khi bàn giao v1

- [ ] IDs không trùng; left join không nhân dòng; hàng bị loại có lý do.
- [ ] Missing giữ đúng ý nghĩa; KEV false chỉ sau catalog thành công.
- [ ] Mọi EPSS có cùng ngày T; metadata không nhầm model version/API version.
- [ ] Mọi vector đủ phiên bản và lớp; điểm tính lại khớp hoặc có báo bất thường.
- [ ] Nhãn scope có bằng chứng; review cả false positive và ứng viên bị bỏ sót.
- [ ] Split không chồng ID; kiểm tra mô tả gần/trùng và lớp hiếm.
- [ ] Ranking cùng cohort và tie-break ổn định; K/mẫu số đúng.
- [ ] Mapping có căn cứ; pair key unique; queue không bỏ quên unknown.
- [ ] N2/N3 đọc dataset và ghi output đúng schema/version trên máy mình.
- [ ] Tệp lớn không cần commit nhưng có cách chuyển đúng phiên bản/checksum để chấm lại.

Nguồn đặc tả để tra khi triển khai: [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document), [FIRST EPSS API](https://api.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
