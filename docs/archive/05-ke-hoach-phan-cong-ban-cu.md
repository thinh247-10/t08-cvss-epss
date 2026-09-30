# Kế hoạch thực hiện và phân công theo phase — T08 CVSS vs EPSS

> Người 1: **bạn — Data pipeline, hạ tầng và nhóm trưởng**.
> Lịch đề xuất: **20 ngày làm việc, khoảng 4 tuần**. Ngày 1 là ngày nhóm bắt đầu, chưa phải deadline đã thống nhất.
> Tài liệu được lập sau khi đọc repo ngày 19/09/2026. Các đầu ra ghi bên dưới là việc cần làm, không phải tính năng đã hoàn thành.

## 1. Bắt đầu từ đâu?

**Ưu tiên đầu tiên của bạn: chốt cấu trúc dữ liệu, rồi giao một bộ dữ liệu mẫu cho Người 2 và Người 3.** Hoàn thiện dataset trước khi chuyển trọng tâm sang deploy.

Thứ tự công việc của Người 1:

```text
Chốt schema → NVD → EPSS + KEV → ghép và kiểm tra dữ liệu
→ bàn giao dataset + EDA → hỗ trợ tích hợp → Docker/deploy → nghiệm thu
```

Trong lúc bạn làm pipeline, Người 2 xây dựng kịch bản tài sản và công thức chấm điểm; Người 3 chuẩn bị baseline và khung dashboard. Hai bạn đó có thể bắt đầu bằng dữ liệu mẫu.

### Hiện trạng repo

| Hạng mục | Hiện trạng khi lập kế hoạch | Hành động tiếp theo |
|---|---|---|
| `src/collect/explore_apis.py` | Đã có code gọi ba nguồn; theo phân công của nhóm, bước khám phá đã xong | Dùng làm tài liệu tham khảo, chỉ chạy lại khi cần kiểm tra schema |
| `nvd_collector.py`, `epss_client.py`, `kev_client.py` | Chỉ có docstring/TODO | Người 1 triển khai |
| `src/environmental/*.py`, `src/analysis/*.py` | Các module nghiệp vụ chỉ có docstring/TODO | Người 2 triển khai |
| `src/model/baseline.py`, `distilbert_multihead.py` | Chỉ có docstring/TODO | Người 3 triển khai |
| Hai notebook, `app.py`, `deploy/` | Chưa có | Tạo theo phase bên dưới |
| `docs/03-environmental-context.md`, `04-patch-playbook.md` | Có nội dung khung, cần rà soát phương pháp và bổ sung kết quả | Người 2 phụ trách nội dung |
| `requirements.txt` | Có thư viện dữ liệu/ML, chưa có Streamlit | Người 3 bổ sung khi làm app; Người 1 tổng hợp phiên bản đã chạy được |
| Lệnh chạy trong README | Có nhắc `apply_environmental.py`, `generate_report_charts.py`, nhưng hai file này chưa tồn tại | Chốt dùng `cvss_environmental.py`, `plots.py` và cập nhật lệnh sau khi có CLI |

**Chạy một file TODO hiện tại có thể kết thúc mà không tạo dữ liệu. Không xem việc “không báo lỗi” là đã xong.**

## 2. Quyền phụ trách và review

| Thành viên | Phạm vi chính | Sản phẩm phải chịu trách nhiệm | Người review |
|---|---|---|---|
| **Người 1 — bạn** | `src/collect/`, `notebooks/01_eda.ipynb`, `deploy/`; điều phối nhóm | Dataset tái tạo được, mô tả dữ liệu, EDA, hướng dẫn chạy/deploy | Người 3 review schema/nhãn ML; Người 2 review ngày snapshot/nguồn điểm |
| **Người 2 — Security analysis** | `src/environmental/`, `src/analysis/`, `docs/03-*`, `docs/04-*` | RQ2–RQ4: so sánh thứ hạng, bối cảnh tài sản, playbook có căn cứ | Người 1 review dữ liệu; Người 3 review đầu ra để tích hợp |
| **Người 3 — ML/NLP + Dashboard** | `src/model/`, `notebooks/02_model_eval.ipynb`, `app.py` | Baseline, DistilBERT, đánh giá RQ1, dashboard | Người 1 review khả năng chạy lại; Người 2 review diễn giải điểm/ưu tiên |
| **Cả nhóm** | README, requirements, báo cáo, slide, demo | Một luồng chạy thống nhất và câu trả lời cho RQ1–RQ4 | Nhóm trưởng tổng hợp, mỗi người kiểm tra phần chuyên môn |

Người 1 tạo thêm `src/collect/build_dataset.py` để ghép/làm sạch dữ liệu. Đây là phần còn thiếu trong sơ đồ ban đầu; cần có người sở hữu rõ ràng.

Người 2 và Người 3 thống nhất một hàm tính Base Score từ vector trong `src/environmental/cvss_environmental.py`, tránh viết hai công thức khác nhau. Người 2 chịu trách nhiệm tính đúng công thức; Người 3 dùng lại để đánh giá mô hình.

## 3. Phân công theo từng phase

### Phase 0 — Chốt phạm vi và cách bàn giao | Ngày 1

**Mục tiêu:** ba người thống nhất sẽ làm gì, dùng dữ liệu nào và trao đổi qua file nào.

| Người | Việc làm | Đầu ra |
|---|---|---|
| Người 1 | Họp khởi động 30–45 phút; xác nhận thời gian còn lại; chốt schema, snapshot, cách chia train/validation/test; tạo danh sách task | `docs/data_contract.md` bản đầu và bảng công việc |
| Người 2 | Chọn một tổ chức giả định; đề xuất 5–10 tài sản, stack công nghệ và tiêu chí ưu tiên; chốt schema kết quả ranking/context | Khung tài sản và cập nhật phạm vi trong `docs/03-environmental-context.md` |
| Người 3 | Kiểm tra CPU/GPU; chốt 8 nhãn CVSS v3.1; định nghĩa file prediction và các màn hình demo | Thiết kế baseline, prediction schema và phác thảo dashboard |

**Điều kiện kết thúc:** cả ba xác nhận tên cột, phiên bản CVSS, khoảng dữ liệu, thời điểm EPSS/KEV, khóa ghép và chủ sở hữu từng đầu ra. Chưa cần có model hay app hoàn chỉnh.

### Phase 1 — Dữ liệu mẫu và các phần có thể chạy độc lập | Ngày 2–4

**Mục tiêu:** Người 2 và Người 3 đọc được dữ liệu thật đủ sớm.

| Người | Việc làm | Đầu ra |
|---|---|---|
| Người 1 | Viết NVD collector bản nhỏ; bổ sung EPSS/KEV tối thiểu; ghép thử; giao khoảng 100–300 CVE thật nếu đủ dữ liệu | `data/sample/cves_sample.csv`, schema và metadata mẫu |
| Người 2 | Hoàn thiện `asset_inventory.py`; xây hàm tính Base/Environmental và đối chiếu trường hợp mẫu; tạo ánh xạ CVE–tài sản | Inventory, kết quả kiểm tra công thức, mẫu `environmental_scores.csv` |
| Người 3 | Viết luồng đọc data → tạo nhãn → train/predict baseline; dựng `app.py` đọc file mẫu; kiểm tra các lớp hiếm/thiếu trong mẫu | Baseline chạy thử và dashboard khung |

**Điều kiện kết thúc:** Người 2 và Người 3 tự đọc mẫu trên máy mình mà không đổi tên cột. Mẫu nhỏ chỉ kiểm tra luồng xử lý, chưa dùng kết luận chất lượng mô hình.

Nếu dữ liệu mẫu không có trường hợp KEV/thiếu điểm/nhiều nguồn, bổ sung fixture kiểm tra có ghi rõ là dữ liệu giả lập; không trộn fixture vào kết quả nghiên cứu.

### Phase 2 — Dataset v1, EDA và baseline | Ngày 5–8

**Mục tiêu:** có dataset ổn định để cả nhóm tạo kết quả chính thức.

| Người | Việc làm | Đầu ra |
|---|---|---|
| Người 1 | Hoàn thiện phân trang, retry, cache/checkpoint; thu thập phạm vi đã chốt; viết `build_dataset.py`; kiểm tra join và EDA | Ba file nguồn, `cves.parquet`, `data/metadata.json`, `01_eda.ipynb` |
| Người 2 | Áp dụng Environmental cho khoảng 30–50 CVE phù hợp với tài sản giả định, hoặc ghi rõ lý do nếu ít hơn; làm ranking CVSS/EPSS bước đầu | Bảng context theo cặp CVE–tài sản và ranking bản đầu |
| Người 3 | Train baseline với split theo thời gian; đánh giá F1 từng metric/lớp và MAE/RMSE Base Score; lưu model và prediction | Baseline v1, `predictions.csv`, `02_model_eval.ipynb` bản đầu |

**Điều kiện kết thúc:** dataset không trùng `cve_id`, giữ được nguồn điểm và ngày snapshot, có thống kê thiếu dữ liệu; cả ba dùng cùng `dataset_version`. Train/validation/test không chồng CVE.

### Phase 3 — Kết quả nghiên cứu và phân tích bảo mật | Ngày 9–13

**Mục tiêu:** trả lời RQ1–RQ4 bằng kết quả có thể kiểm tra.

| Người | Việc làm | Đầu ra |
|---|---|---|
| Người 1 | Đóng băng dataset v1; kiểm tra các bất thường do hai bạn báo; bổ sung EDA theo nguồn điểm, thiếu nhãn, phân bố lớp; hỗ trợ chạy lại | Dataset v1 được xác nhận, danh sách hạn chế dữ liệu |
| Người 2 | Hoàn thiện `compare_rankings.py`, `plots.py`; so sánh CVSS/EPSS/KEV và Base/Environmental; viết case study, ngưỡng/SLA đề xuất | `rankings.csv`, `environmental_scores.csv`, biểu đồ, bản nháp hoàn chỉnh docs 03/04 |
| Người 3 | Train DistilBERT multi-head; so với baseline trên cùng split; kiểm tra lỗi điển hình; nối prediction vào app | Model, bảng so sánh hai mô hình, notebook đánh giá, giao diện suy luận |

**Điều kiện kết thúc:** có ít nhất ba case study giải thích vì sao thứ tự vá thay đổi; bảng đánh giá baseline/DistilBERT có số liệu thật; đầu ra của Người 2 đủ ổn định để Người 3 tích hợp.

Người 2 dùng **CVSS quan sát được từ nguồn dữ liệu** để làm RQ2/RQ3 trước. So sánh bằng CVSS dự đoán là nhánh bổ sung khi Người 3 bàn giao prediction, không chặn toàn bộ phân tích.

### Phase 4 — Tích hợp dashboard và đóng gói | Ngày 14–17

**Mục tiêu:** chạy được một demo liên tục từ dữ liệu đến quyết định ưu tiên.

| Người | Việc làm | Đầu ra |
|---|---|---|
| Người 1 | Viết `deploy/Dockerfile`, `docker-compose.yml`, `ec2_setup.sh`; thống nhất dependency; kiểm tra tải dữ liệu/model theo hướng dẫn; sửa README theo lệnh thực tế | Bộ deploy và hướng dẫn chạy lại |
| Người 2 | Kiểm tra ranking/context trên dashboard; hoàn thiện lý do ưu tiên, các ngoại lệ và giới hạn của playbook | Docs 03/04 hoàn chỉnh và xác nhận kết quả hiển thị |
| Người 3 | Tích hợp ranking, biểu đồ, chọn tài sản, nhập mô tả để dự đoán CVSS; xử lý thiếu dữ liệu/model; thêm Streamlit vào requirements | Dashboard hoàn chỉnh |

**Điều kiện kết thúc:** Người 2 chạy được demo từ checkout sạch theo README; dashboard hiển thị ngày snapshot, phân biệt điểm quan sát/điểm dự đoán và đúng tài sản bị ảnh hưởng. Container chạy được trên môi trường kiểm tra.

File `ec2_setup.sh` là script cho máy Linux, không chạy trực tiếp trong PowerShell Windows. Chỉ triển khai EC2 thật khi nhóm đã có tài khoản, cấu hình và ngân sách; nếu không, bàn giao Docker local cùng script/hướng dẫn EC2 được ghi rõ mức kiểm tra đã thực hiện.

### Phase 5 — Nghiệm thu, báo cáo và diễn tập | Ngày 18–20

**Mục tiêu:** nộp được sản phẩm nhất quán và mọi thành viên giải thích được phần mình làm.

| Người | Việc làm | Đầu ra |
|---|---|---|
| Người 1 | Kiểm tra checklist, phiên bản dữ liệu/model và lệnh chạy; tổng hợp README, slide; điều phối diễn tập | Bản bàn giao, slide tổng hợp, kịch bản demo |
| Người 2 | Hoàn thiện phần RQ2–RQ4; kiểm tra kết luận không vượt quá bằng chứng; chuẩn bị trả lời về ngưỡng, KEV và context | Phần báo cáo bảo mật và case study |
| Người 3 | Hoàn thiện RQ1; chụp kết quả model/app; chuẩn bị demo dự đoán và giải thích giới hạn mô hình | Phần báo cáo ML, dashboard ổn định |

**Điều kiện kết thúc:** cả nhóm chạy thử từ đầu ít nhất một lần, kiểm tra link/file nộp, có ảnh hoặc video demo dự phòng và không còn lỗi chặn luồng chính.

## 4. Dữ liệu và giao diện phải thống nhất sớm

Đây là **đề xuất để chốt ở Phase 0**, chưa phải schema đã được code triển khai. Người 1 ghi phiên bản được thống nhất vào `docs/data_contract.md`.

### 4.1. Phạm vi và thời gian

- Phạm vi khởi đầu đề xuất: CVE có ngày công bố trong **2023–2024**, phù hợp ví dụ README. Chạy thử một tuần trước khi mở rộng.
- Nhãn chính: **CVSS v3.1**, tám thành phần `AV/AC/PR/UI/S/C/I/A`. Không trộn v2/v3.0/v4.0 vào cùng bộ nhãn v3.1.
- RQ2 mặc định là **so sánh thứ tự ưu tiên tại một ngày snapshot T gần ngày thu thập**; dùng cùng ngày EPSS cho toàn bộ cohort, lưu KEV catalog và thời điểm tải tương ứng. Đây là phân tích tại snapshot, không phải chứng minh mô hình đã dự báo được khai thác trong quá khứ.
- Nếu muốn đánh giá hồi cứu tại `published + 30 ngày`, cần một thiết kế riêng: EPSS đúng ngày, trạng thái KEV tại mốc đó và kiểm soát dữ liệu/nhãn được cập nhật sau mốc. NVD tải hôm nay có thể chứa mô tả/điểm đã sửa; chỉ chia train/test theo ngày công bố chưa loại bỏ hết hạn chế này.
- Split RQ1 đề xuất: train năm 2023; validation tháng 1–6/2024; test tháng 7–12/2024. Kiểm tra kích thước/lớp trước khi chốt; mọi điều chỉnh phải hoàn tất trước khi xem kết quả test. Fit TF-IDF và tính class weights chỉ trên train; dùng validation để chọn tham số/ngưỡng; test chỉ dùng đánh giá cuối.

### 4.2. Bảng CVE chung: `data/processed/cves.parquet`

Một dòng cho một `cve_id`; các trường điểm/nhãn được phép null nếu thiếu. Tập ML được lọc từ bảng này, không xóa CVE thiếu nhãn khỏi dữ liệu gốc.

| Nhóm | Cột đề xuất | Quy ước |
|---|---|---|
| Định danh | `cve_id`, `published`, `last_modified`, `vuln_status` | CVE ID chuẩn hóa; timestamp UTC |
| Văn bản | `description` | Mô tả tiếng Anh; thiếu thì đánh dấu, không bịa nội dung |
| CVSS được chọn | `cvss_version`, `cvss_vector`, `cvss_base_score`, `cvss_source`, `cvss_type` | Giữ nguyên nguồn chấm điểm và Primary/Secondary; điểm trong [0,10] |
| Nhãn ML | `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`, `has_cvss31_label`, `split` | Dùng mã ngắn trong vector; `split` là train/validation/test hoặc null |
| EPSS | `epss`, `epss_percentile`, `epss_date` | Giá trị số trong [0,1]; thiếu là null, không thay bằng 0 |
| KEV | `is_kev`, `kev_date_added`, `kev_known_ransomware` | `false` chỉ khi đối chiếu thành công với catalog đầy đủ; lỗi tải là unknown/null hoặc dừng build |
| Nguồn gốc | `retrieved_at`, `dataset_version` | Thời điểm thu thập chi tiết từng nguồn nằm trong metadata |

Quy tắc chọn nhãn đề xuất: trong các metric v3.1 hợp lệ, ưu tiên nguồn `nvd@nist.gov`; nếu không có thì ưu tiên `Primary`, rồi dùng thứ tự nguồn/vector cố định để xử lý hòa. Đây là quy ước tạo nhãn của nhóm, không phải khẳng định nguồn được chọn luôn đúng hơn. Lưu toàn bộ metric gốc để Người 2 phân tích bất đồng giữa nguồn; không mặc định mọi nguồn khác NVD đều là CNA.

### 4.3. Các file bàn giao giữa thành viên

| Người tạo → người dùng | File đề xuất | Nội dung tối thiểu |
|---|---|---|
| Người 1 → cả nhóm | `data/sample/cves_sample.csv` | Mẫu nhỏ cùng schema dataset chính; kèm mô tả phạm vi/ngày snapshot |
| Người 1 → cả nhóm | `data/raw/nvd_cves.parquet`, `epss.parquet`, `kev.parquet` | Các bảng nguồn trước khi ghép; giữ raw JSON/cache để truy vết metric khi cần |
| Người 1 → cả nhóm | `data/processed/cves.parquet`, `data/metadata.json` | Dataset đã kiểm tra; metadata có schema version, khoảng thu thập, snapshot, nguồn, số dòng, missing, quy tắc chọn metric, split và checksum |
| Người 2 → analysis/app | `data/processed/cve_asset_mapping.csv` | `cve_id`, `asset_id`, sản phẩm/phiên bản giả định, nguồn bằng chứng ảnh hưởng và lý do ánh xạ |
| Người 2 → Người 3 | `data/processed/rankings.csv` | `cve_id`, `cvss_rank`, `epss_rank`, `is_kev`, `dataset_version`; giữ score để giải thích |
| Người 2 → Người 3 | `data/processed/environmental_scores.csv` | `cve_id`, `asset_id`, vector đầu vào, vector Environmental, `environmental_score`, `priority`, `reason`, `dataset_version` |
| Người 3 → Người 2/app | `data/processed/predictions.csv` | `cve_id`, `predicted_vector`, `predicted_base_score`, `model_version`, `dataset_version`, `split` |
| Người 2 → báo cáo/app | `reports/figures/` | Biểu đồ, caption, cohort và ngày snapshot |
| Người 3 → app/Người 1 | `models/` và hướng dẫn tải | Model, tokenizer/vectorizer, mapping nhãn, config và kết quả đánh giá |

Khóa bảng Environmental là **`(cve_id, asset_id)`**, vì cùng CVE có thể có điểm khác nhau trên nhiều tài sản. Chỉ tạo cặp khi có căn cứ phần mềm/phiên bản bị ảnh hưởng; ghi rõ mapping là giả định của bài tập khi không kiểm chứng trên hệ thống thật. Người 1 giữ `configurations`/CPE và `references` trong raw NVD để Người 2 tra cứu; nếu thiếu, Người 2 kiểm tra advisory của nhà cung cấp thay vì suy đoán từ mô tả ngắn.

Khóa bảng prediction là **`(cve_id, model_version)`**; giữ riêng kết quả baseline và DistilBERT, không ghi đè để mất bảng đối chiếu.

`data/raw/`, `data/processed/` và `models/` đang bị gitignore. Người 1 ghi cách tải/chia sẻ bản dữ liệu đã chốt trong README; không chỉ gửi đường dẫn cục bộ. Mẫu CSV nhỏ và mô tả schema có thể commit. Metadata không chứa API key hay URL có token.

## 5. Hướng dẫn Người 1 từng bước

### Bước 1 — Chuẩn bị môi trường và kiểm tra phần đã làm

Mở terminal **PowerShell tại thư mục gốc repo**. Nếu chưa có `.venv`, tạo môi trường; các lệnh dưới gọi Python trong venv trực tiếp nên không cần đổi Execution Policy:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install requests python-dotenv pandas pyarrow numpy matplotlib seaborn jupyter
if (-not (Test-Path -LiteralPath .env)) { Copy-Item -LiteralPath .env.example -Destination .env }
```

Điền key thật vào `.env` nếu có; nếu chưa có key thì để giá trị rỗng, không dùng chuỗi mẫu `your-key-here`. Không commit `.env`. Bộ cài trên đủ cho phần Data/EDA của bạn; cả nhóm kiểm tra toàn bộ `requirements.txt` ở phase tích hợp.

Nếu cần kiểm tra lại kết nối/schema:

```powershell
.\.venv\Scripts\python.exe src/collect/explore_apis.py CVE-2021-44228
```

Đọc `sample_CVE-2021-44228.json`, xác định vị trí ID, mô tả, ngày và danh sách metric. Script chỉ lưu raw NVD; EPSS/KEV hiện được in ra terminal. Theo ảnh phân công, bước khám phá đã xong thì chuyển thẳng sang Bước 2.

**Xong khi:** bạn chỉ được đường dẫn JSON của các trường cần lấy và biết dữ liệu nào còn thiếu.

### Bước 2 — Chốt cách làm với hai thành viên

Trong buổi đầu, thống nhất mục 4; tạo `docs/data_contract.md`. Giao việc ngay:

- **Người 2:** chọn kịch bản, lập tài sản, công thức Base/Environmental, quy tắc ánh xạ CVE, đầu ra ranking/context.
- **Người 3:** đọc schema, viết baseline, chuẩn bị split/mapping nhãn và dashboard dùng dữ liệu mẫu.
- **Bạn:** thông báo mốc giao mẫu cuối Phase 1, dataset v1 cuối Phase 2; ghi rõ người review.

**Xong khi:** cả hai xác nhận đã hiểu cột đầu vào và biết phần có thể làm trước khi đủ data.

### Bước 3 — Viết `nvd_collector.py` trước

Triển khai theo thứ tự nhỏ đến lớn:

1. Thêm CLI `--start`, `--end`, `--output`; quy định ngày kết thúc được bao gồm, chuyển sang khoảng timestamp rõ ràng.
2. Lấy một trang trong một tuần; đọc `vulnerabilities[].cve`, mô tả tiếng Anh, ngày và toàn bộ metric.
3. Thêm phân trang qua `startIndex`/`resultsPerPage`; kiểm tra đã lấy đủ theo `totalResults` và không lặp CVE.
4. Chia phạm vi lớn theo tháng; tránh bỏ sót ngày ở ranh giới và loại trùng bằng CVE ID.
5. Thêm timeout, điều tiết tốc độ, retry có giới hạn cho lỗi tạm thời, checkpoint/cache để chạy tiếp. Kiểm tra chính sách hiện hành trong [tài liệu NVD API](https://nvd.nist.gov/developers/start-here) khi triển khai.
6. Ghi bảng nguồn và log: số record nhận, số CVE duy nhất, thiếu mô tả, thiếu v3.1, lỗi và khoảng chưa lấy xong.

Giữ CVE chưa có nhãn trong raw; chỉ loại khỏi tập huấn luyện có giám sát. Không suy ra thiếu CVSS chỉ từ `vuln_status`; kiểm tra metric thực tế. TODO “bỏ qua CVE không có vector” cần hiểu ở bước tạo tập ML, không áp dụng để xóa dữ liệu nguồn.

**Xong khi:** lấy được một tuần dữ liệu; chạy lại từ cache không tạo dòng trùng; lỗi mạng không tạo ra dataset trông như đầy đủ.

### Bước 4 — Viết `epss_client.py`

1. Nhận danh sách CVE từ bảng NVD và ngày snapshot đã chốt.
2. Với mẫu nhỏ, gọi API theo batch; tham số `cve` có giới hạn 2.000 ký tự gồm dấu phẩy, nên chia theo độ dài thay vì gán cứng số CVE. Lưu ngày trả về, ép điểm sang số. Xem [đặc tả EPSS API](https://api.first.org/epss/).
3. Với cả cohort lớn, tải file EPSS theo ngày rồi lọc/join; FIRST hướng dẫn dùng file CSV cho tải hàng loạt. Lưu ngày và phiên bản mô hình từ metadata nguồn nếu có, không nhầm phiên bản API với phiên bản mô hình. Xem [FIRST — Get the Data](https://www.first.org/epss/data).
4. Lưu `data/raw/epss.parquet`; báo số CVE ghép được, thiếu và bị lỗi. Với snapshot cố định, mỗi CVE có tối đa một điểm ở ngày đó.

**Xong khi:** điểm nằm trong [0,1], toàn bộ kết quả dùng đúng ngày, CVE thiếu EPSS vẫn nhận diện được. Không âm thầm thay snapshot yêu cầu bằng ngày hiện tại.

### Bước 5 — Viết `kev_client.py`

1. Tải catalog JSON từ endpoint đã dùng trong `explore_apis.py`.
2. Giữ `cveID`, `dateAdded`, `knownRansomwareCampaignUse` cùng metadata catalog; chuẩn hóa khóa thành `cve_id` ở bảng xuất.
3. Lưu `data/raw/kev.parquet` và raw catalog để tái lập kết quả.
4. Chỉ gắn `is_kev=False` sau khi xác nhận catalog tải/parse thành công. Nếu tải thất bại, báo lỗi; không coi toàn bộ CVE là không thuộc KEV.

**Xong khi:** kiểm tra được cả CVE có trong catalog lẫn CVE không có; giữ ngày thêm vào catalog và thời điểm tải. Không thuộc KEV không chứng minh chưa từng bị khai thác.

### Bước 6 — Tạo `build_dataset.py` và bàn giao mẫu sớm

1. Chuẩn hóa ID, timestamp và dtype; giữ mọi metric gốc, chọn một nhãn v3.1 theo quy tắc đã chốt.
2. Parse tám nhãn từ vector; đối chiếu với trường metric có sẵn để phát hiện lỗi.
3. Dùng NVD làm bảng gốc, **left join** EPSS và KEV; kiểm tra khóa trước/sau join để tránh nhân bản dòng hoặc mất CVE thiếu EPSS.
4. Tạo `has_cvss31_label`, chia split theo thời gian trên dữ liệu đủ điều kiện; loại Rejected khỏi cohort phân tích/huấn luyện nhưng vẫn giữ dấu vết ở raw.
5. Ghi `cves.parquet`, metadata và mẫu nhỏ. Gửi mẫu ngay khi đủ schema, không chờ chạy hết hai năm.

**Xong khi:** không trùng CVE, nhãn hợp lệ, số dòng sau join giải thích được; Người 2/3 đọc file bằng cùng schema.

### Bước 7 — Chạy dữ liệu đầy đủ và làm EDA

Sau khi kiểm tra mẫu, mở rộng sang phạm vi đã chốt. Tạo `notebooks/01_eda.ipynb` theo trình tự:

1. Tổng số CVE, khoảng ngày, snapshot và nguồn dữ liệu.
2. Tỷ lệ thiếu mô tả, CVSS v3.1, EPSS; số CVE bị loại và lý do.
3. Phân bố CVSS/EPSS, tỷ lệ thuộc KEV.
4. Phân bố tám nhãn và số mẫu từng split; cảnh báo lớp thiếu trong train hoặc test.
5. Số liệu theo `cvss_source`; bao nhiêu CVE có nhiều nguồn/vector không đồng nhất.
6. Các phát hiện dữ liệu ảnh hưởng tới phân tích/model, tách khỏi kết luận bảo mật do Người 2 phụ trách.

**Xong khi:** notebook chạy từ đầu đến cuối trên dataset v1, không phụ thuộc biến tạo thủ công hoặc đường dẫn riêng trên máy bạn.

### Bước 8 — Bàn giao dataset và khóa phiên bản

Gói bàn giao gồm: dataset, metadata, schema, cách tải, checksum, lệnh tái tạo và các hạn chế đã biết. Yêu cầu Người 2/3 chạy thử trên máy của họ.

Sau khi chốt v1, mọi thay đổi làm đổi dòng/cột/nhãn phải tăng phiên bản và thông báo cả nhóm; không âm thầm ghi đè dataset đang dùng để báo cáo. Người 3 không cần train lại chỉ vì bạn sửa phần trình bày notebook.

**Xong khi:** cả ba xác nhận cùng phiên bản; các kết quả analysis/model ghi lại phiên bản đầu vào.

### Bước 9 — Đóng gói khi app đã chạy local

1. Lấy lệnh chạy app đã được Người 3 kiểm tra, các dependency và đường dẫn artifact.
2. Viết Dockerfile, Compose; mount hoặc tải artifact theo hướng dẫn, không nhúng `.env` chứa key vào image.
3. Kiểm tra app đọc dữ liệu/model và chạy inference; demo nên dùng snapshot/cache đã chốt để tái lập.
4. Viết `ec2_setup.sh` và mô tả môi trường Linux mục tiêu; ghi rõ phần nào đã kiểm tra local/cloud.
5. Nhờ một thành viên chạy lại từ README, sửa các bước thiếu.

**Xong khi:** người khác chạy được demo theo hướng dẫn và bạn báo cáo đúng phạm vi đã kiểm tra.

### Bước 10 — Nghiệm thu với vai trò nhóm trưởng

Đối chiếu checklist ở mục 8, đóng băng bản nộp, phân vai thuyết trình và diễn tập. Dành hai ngày cuối cho sửa lỗi và thống nhất nội dung, không thêm tính năng lớn.

### Giao diện lệnh dự kiến sau khi triển khai

**Chưa chạy các lệnh sau để kỳ vọng có output ngay:** đây là CLI đề xuất cho Người 1 xây dựng; hiện các file collector vẫn là TODO và `build_dataset.py` chưa có. Các đường dẫn output cần được script tạo thư mục cha khi cần.

```powershell
# Chạy thử một tuần trước
.\.venv\Scripts\python.exe src/collect/nvd_collector.py --start 2024-01-01 --end 2024-01-07 --output data/raw/nvd_cves.parquet

# Điền ngày snapshot thực tế đã thống nhất và có dữ liệu
$snapshotDate = 'YYYY-MM-DD'
.\.venv\Scripts\python.exe src/collect/epss_client.py --input data/raw/nvd_cves.parquet --date $snapshotDate --output data/raw/epss.parquet
.\.venv\Scripts\python.exe src/collect/kev_client.py --output data/raw/kev.parquet
.\.venv\Scripts\python.exe src/collect/build_dataset.py --nvd data/raw/nvd_cves.parquet --epss data/raw/epss.parquet --kev data/raw/kev.parquet --output data/processed/cves.parquet
```

## 6. Người 2 và Người 3 cần kiểm tra gì?

### Người 2 — điều kiện nghiệm thu phần bảo mật

- Tính điểm theo đặc tả; giữ vector và lý do điều chỉnh. Rà lại bảng gợi ý trong docs 03: “mạng nội bộ” không tự động đổi `MAV:N` thành `MAV:A/L`; không tự động hạ tác động chỉ vì có WAF/backup/HA. Mạng nội bộ định tuyến vẫn có thể là AV:N. Xem [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document).
- Kiểm tra công thức với trường hợp Scope thay đổi (`MS:C`), phép `Roundup` và metric `X` (Not Defined). Temporal chưa đánh giá thì ghi `E/RL/RC:X`; không tự đặt giá trị để điều chỉnh kết quả.
- So sánh thứ hạng trên cùng tập CVE đủ dữ liệu; công bố số mẫu bị loại. Context so sánh theo từng tài sản hoặc quy tắc gộp được nêu rõ.
- Chốt cách xử lý đồng điểm. Dùng Kendall tau-b cho thứ hạng có ties, Jaccard cho top-K. Dùng top-50 cho cohort RQ2 đủ lớn; với case study RQ3 khoảng 30–50 CVE, dùng top-10/top-20 phù hợp và nhỏ hơn kích thước cohort. Nếu K bao phủ toàn bộ cohort thì không diễn giải overlap/recall như khả năng ưu tiên. Recall@K trên KEV có mẫu số là số CVE KEV trong cohort so sánh; nếu mẫu số bằng 0 thì ghi N/A.
- Khi lấy KEV làm mốc đánh giá, không dùng chính `is_kev` để xây ranking rồi trình bày recall cao như bằng chứng dự báo độc lập. Ranking vận hành có KEV override được trình bày riêng.
- Kiểm tra tài sản có bị ảnh hưởng **trước** khi đưa vào hàng đợi vá; chỉnh thứ tự trong playbook hiện tại. SLA là đề xuất cho tổ chức giả định, không phải cam kết hiệu quả đã đo được.
- CVSS cao/EPSS thấp chỉ là dấu hiệu cần phân tích, chưa đủ kết luận “vá lãng phí”. Nếu không có log vận hành thì không báo cáo thời gian vá hay công sức tiết kiệm như số liệu thực nghiệm.

### Người 3 — điều kiện nghiệm thu phần model và dashboard

- Baseline trước, DistilBERT sau; dùng cùng dataset/split và báo cáo F1 từng metric/lớp, MAE/RMSE score cùng số mẫu.
- Chỉ dùng mô tả làm input cho bài toán RQ1; không đưa nhãn CVSS, EPSS hay KEV vào feature để vô tình làm thay đổi bài toán.
- Giữ test tách biệt khi chọn mô hình/ngưỡng; so sánh prediction chỉ trên test hoặc tập đánh giá chưa dùng train. Gắn nhãn rõ prediction dùng cho demo khác với kết quả đánh giá.
- Lưu mapping nhãn, tokenizer/vectorizer, seed, config và phiên bản model. Không bắt buộc DistilBERT phải thắng baseline; giải thích kết quả thực tế.
- Dashboard hiển thị được ba luồng: xem CVE/ranking; chọn tài sản xem context/lý do ưu tiên; nhập mô tả xem CVSS dự đoán. Có trạng thái thiếu EPSS, thiếu model và vector không hợp lệ.
- Điểm dự đoán luôn được ghi là ước lượng; không ghi đè điểm quan sát được. Mỗi score đi kèm vector/nguồn hoặc model version tương ứng.

## 7. Cách bạn điều phối nhóm mỗi ngày

**Mỗi task chỉ có một người chịu trách nhiệm chính**, một đầu ra và một tiêu chí xong. Dùng GitHub Issues/Projects nếu nhóm đang có; nếu chưa thì bảng task Markdown cũng đủ.

Mẫu giao việc:

```text
Task: P2-N1 — Hoàn thiện bộ ghép dữ liệu
Owner: Người 1 | Reviewer: Người 2 + Người 3
Input: nvd_cves.parquet, epss.parquet, kev.parquet
Output: cves.parquet + metadata + báo cáo kiểm tra
Deadline tương đối: cuối ngày 8
Done: không trùng CVE; giữ missing/nguồn/ngày; hai thành viên đọc được file
Blocker: ghi rõ người hoặc đầu vào đang chờ
```

- Đầu ngày: mỗi người ghi **đã xong / hôm nay làm / đang vướng** trong một cập nhật ngắn.
- Cuối phase: demo đầu ra thật trong 15–20 phút, đối chiếu điều kiện kết thúc; cập nhật bảng task.
- Vướng quá một buổi: báo nhóm trưởng sớm. Đổi sang dữ liệu mẫu/cache hoặc nhiệm vụ độc lập trong lúc xử lý.
- Mỗi người làm trên branch riêng, ví dụ `feat/data-pipeline`, `feat/security-analysis`, `feat/model-dashboard`; ưu tiên PR nhỏ theo phase.
- Sửa schema hoặc requirements dùng chung phải thông báo trước khi merge. Nhóm trưởng tổng hợp README/requirements sau khi từng người cung cấp thay đổi đã kiểm tra.
- Review là kiểm tra input/output, cách chạy và kết quả; không chỉ xác nhận “đã có file”.

### Mốc bàn giao mà bạn cần theo dõi

| Mốc | Ai giao → ai nhận | Bằng chứng hoàn thành |
|---|---|---|
| Cuối Phase 0 | Cả ba | Schema, thời gian và interface được xác nhận |
| Cuối Phase 1 | Người 1 → Người 2/3 | Mẫu được mở thành công trên hai máy còn lại |
| Cuối Phase 2 | Người 1 → cả nhóm; Người 3 → nhóm | Dataset v1 + metadata; baseline có kết quả |
| Cuối Phase 3 | Người 2 → Người 3; Người 3 → Người 2 | Ranking/context và prediction theo schema đã chốt |
| Cuối Phase 4 | Người 3 + Người 1 → Người 2 | Dashboard đóng gói chạy lại được |
| Cuối Phase 5 | Cả nhóm | Bản nộp, báo cáo, slide và demo thống nhất |

Nếu trễ tiến độ: giảm phạm vi dữ liệu có giải thích, giảm số lần thử tham số DistilBERT và hoàn thiện demo local trước EC2. Giữ trọng tâm RQ2–RQ4, baseline, nguồn gốc dữ liệu và báo cáo trung thực; phần chưa hoàn thành phải được ghi rõ.

## 8. Checklist nghiệm thu cuối cùng

- [ ] Người 1 bàn giao được NVD + EPSS + KEV, dataset, metadata, EDA và hướng dẫn tái tạo.
- [ ] Người 2 có inventory, mapping CVE–tài sản, công thức kiểm tra được, ranking, biểu đồ và docs 03/04 hoàn chỉnh.
- [ ] Người 3 có baseline, DistilBERT, đánh giá theo thời gian, artifact và dashboard.
- [ ] Cả nhóm dùng cùng phiên bản dữ liệu; snapshot/nguồn điểm/model được ghi trong kết quả.
- [ ] Lệnh README trỏ đúng file đã triển khai; không còn trình bày CLI dự kiến như tính năng đã chạy được.
- [ ] Người khác chạy được demo theo README; Docker được kiểm tra; trạng thái EC2 được ghi đúng thực tế.
- [ ] Kiểm tra quan trọng đã qua: phân trang/retry, join không nhân dòng, missing, công thức CVSS, split không chồng CVE và app đọc được artifact.
- [ ] Không commit key hoặc dataset/model lớn; có cách lấy đúng artifact phục vụ chấm bài.
- [ ] Kết luận phân biệt severity, khả năng khai thác, bằng chứng KEV và bối cảnh; không dùng fixture làm bằng chứng.
- [ ] Slide trả lời được RQ1–RQ4; mỗi thành viên biết phần thuyết trình và luồng demo của mình.

**Việc làm ngay trong buổi đầu của bạn:** chốt mục 4 với nhóm → giao task Phase 0/1 → viết NVD collector cho một tuần dữ liệu → hướng tới bàn giao mẫu cuối Phase 1.
