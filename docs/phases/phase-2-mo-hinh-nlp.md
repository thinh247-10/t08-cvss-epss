# Phase 2 — Mô hình NLP có kiểm chứng, không để AI lấn át bài toán bảo mật

> **Ngày 8–13 / 30 ngày. Ngân sách: khoảng 14 giờ/người.**
> Đây là kế hoạch triển khai, chưa phải chức năng đã có hoặc kết quả đã chạy.
> [Kế hoạch tổng](../05-ke-hoach-phan-cong.md) · [Phase trước](phase-1-du-lieu-web-mobile.md) · [Phase sau](phase-3-xep-hang-va-boi-canh.md) · [Hợp đồng dữ liệu](../data_contract.md).
> Git: [quy trình branch/PR](../06-git-workflow.md). N1 `fix/p2-dataset-split`; N2 `feat/p2-cvss-scorer`; N3 `feat/p2-nlp-baseline`, rồi `feat/p2-distilbert` nếu đạt gate.

## 1. Kết quả cần có khi kết thúc ngày 13

Trả lời RQ1: từ **mô tả tiếng Anh của CVE**, mô hình dự đoán được tám thành phần CVSS v3.1 tới mức nào, sai ở đâu và các sai số đó ảnh hưởng đến diễn giải bảo mật ra sao?
Mô hình cung cấp ước lượng severity để hỗ trợ chuyên viên; không trực tiếp dự đoán xác suất khai thác hay quyết định vá.
Phần so sánh CVSS–EPSS ở Phase 3 vẫn lấy **CVSS quan sát từ nguồn dữ liệu** làm thí nghiệm chính.

Sản phẩm bắt buộc:

- Một mô hình dummy dự đoán lớp phổ biến nhất cho từng metric, làm mốc tối thiểu.
- Một baseline TF-IDF + Logistic Regression cho tám metric, lưu được và nạp lại để suy luận.
- Kết quả validation và kết quả test cuối cùng tách biệt; có F1 từng metric/lớp, support, exact vector match và sai số Base Score.
- `data/processed/predictions.csv` đúng schema; khóa `(cve_id, model_version)`, có `dataset_version`, `split`, `prediction_usage`, `vector_valid`, `prediction_error` và tám cột `pred_AV` … `pred_A`.
- Notebook đánh giá, model card và ít nhất 10 lỗi validation được đọc bằng kiến thức bảo mật.
- Quyết định có bằng chứng: chạy DistilBERT trong giới hạn thời gian hay ghi rõ chưa hoàn thành nhánh mở rộng.
- Ranking sơ bộ cuối ngày 13: sort ba chính sách và xuất đúng schema, chưa cần kết luận hay hoàn thiện biểu đồ/metric RQ2.

Không đặt trước một ngưỡng F1 để tuyên bố thành công. Kết quả thấp nhưng quy trình đúng, phân tích lỗi tốt vẫn có giá trị.
Không được viết trước kết luận “AI dự đoán tốt”, “DistilBERT vượt baseline” hoặc đổi test để có điểm đẹp.

## 2. Đầu vào và điều kiện bắt đầu

| Đầu vào | Người bàn giao | Cần kiểm tra trước khi chạy |
|---|---|---|
| `data/processed/cves.parquet` | Người 1 | CVE duy nhất; mô tả; ngày publish; nguồn/vector CVSS; cờ scope; nhãn tám metric |
| `data/metadata.json` | Người 1 | Phiên bản/hash dữ liệu; ngày thu thập; snapshot T; số lượng missing và nguồn CVSS |
| `config/project.yaml` | Người 1 | Phạm vi Web/mobile; chính sách chọn nguồn; mốc thời gian dự kiến |
| Bộ nhãn cố định và schema prediction | Người 3 | Cả nhóm đọc [data contract](../data_contract.md), không tự đổi tên cột |
| Hàm Base Score v3.1 | Người 2, cuối ngày 8 | Có đối chiếu với công cụ/đặc tả FIRST, chưa cần xong Environmental |

Nếu dữ liệu đầy đủ còn chờ tải, dùng sample thật của Phase 1 để thử đọc/fit/export.
Chỉ thử đường chạy với sample; kết quả nghiên cứu phải dùng snapshot đã chốt.
Tách riêng hai tập: `ml_eligible` cần mô tả và nhãn hợp lệ; `ranking_eligible` còn cần EPSS/KEV đầy đủ.
Không loại khỏi ML chỉ vì thiếu EPSS, vì EPSS không phải đầu vào hay nhãn ML.

## 3. Giao thức thí nghiệm phải khóa trước khi mở test

### 3.1. Đầu vào và nhãn

| Metric | Nhãn hợp lệ |
|---|---|
| AV — Attack Vector | `N`, `A`, `L`, `P` |
| AC — Attack Complexity | `L`, `H` |
| PR — Privileges Required | `N`, `L`, `H` |
| UI — User Interaction | `N`, `R` |
| S — Scope | `U`, `C` |
| C, I, A — Confidentiality / Integrity / Availability | Mỗi metric: `N`, `L`, `H` |

Các nhãn theo [đặc tả CVSS v3.1 của FIRST](https://www.first.org/cvss/v3.1/specification-document).
Model chỉ nhìn cột mô tả. Không đưa `cve_id`, vector, Base Score, EPSS, KEV, source CVSS, ngày publish hoặc nhãn do pipeline sinh vào feature.
Ngày publish dùng để chia tập; ID dùng nối kết quả; chúng không đi vào mô hình.
Rà các chuỗi vector/điểm CVSS được chép trực tiếp trong mô tả và áp dụng một quy tắc xử lý thống nhất, có thống kê số dòng.
Không xóa các từ như “remote”, “authenticated”, “user interaction”: đây có thể là thông tin nghiệp vụ thật.

### 3.2. Chia tập và chống rò rỉ

Mặc định dự kiến, sau khi kiểm tra dữ liệu ở Phase 1:

| Tập | `published` | Mục đích |
|---|---|---|
| Train | 2023-01-01 đến trước 2024-01-01 | Fit vocabulary, IDF, classifier và trọng số lớp |
| Validation | 2024-01-01 đến trước 2024-07-01 | Chọn cấu hình, early stopping, đọc lỗi |
| Test | 2024-07-01 đến trước 2025-01-01 | Đánh giá cuối sau khi khóa model/config |

- Người 1 kiểm tra số dòng và lớp theo split; nếu quá ít, cả nhóm điều chỉnh khoảng thu thập trước khi xem điểm test và ghi quyết định.
- Không đổi sang random split chỉ để tăng điểm. Không sao chép lớp hiếm giữa các tập.
- Khử trùng CVE trước split. Kiểm tra mô tả trùng hoặc gần trùng; nhóm bản sao không được xuất hiện ở cả train và test.
- Giữ bản ghi sớm nhất của nhóm mô tả trùng; loại bản sao đến sau khỏi tập đánh giá hoặc áp dụng quy tắc nhóm được ghi trước. Không đẩy CVE tương lai vào train.
- Ghi số bản ghi bị loại; rà nhanh mẫu near-duplicate để tránh gộp các mô tả ngắn chỉ giống mẫu câu.
- TF-IDF chỉ `fit` trên train. Không fit vocabulary trên toàn dataset rồi mới split.
- Weighted loss/class weight tính từ train. Sampling để giảm thời gian cũng chỉ dùng train và lưu danh sách ID.
- Nếu một head chỉ có một lớp ở train, dùng constant classifier riêng cho head đó; log cảnh báo, không bỏ metric.
- Lớp có trong test nhưng vắng ở train vẫn phải có tên trong báo cáo, support và F1 theo quy ước đã ghi.

Chia theo thời gian không biến dataset hiện tại thành bản lưu lịch sử: mô tả/nhãn có thể đã được cập nhật sau ngày publish.
Model card phải nêu hạn chế này; không gọi kết quả là đánh giá triển khai thật tại thời điểm CVE vừa công bố.

### 3.3. Hai mức triển khai

**Bắt buộc:** dummy và TF-IDF. Dùng một vectorizer chung, tám classifier độc lập; mỗi classifier học một metric.
Có thể bắt đầu `ngram_range=(1,2)`, giới hạn vocabulary và số vòng lặp trong `config/model.yaml`; đây là cấu hình khởi đầu, không phải kết quả tối ưu.
Chọn tối đa hai cấu hình baseline trên validation, lưu lý do chọn theo macro-F1 trung bình tám metric cùng chi phí chạy.

**Có kế hoạch nhưng có thể cắt:** DistilBERT một encoder chung, tám classification head, loss tổng/mean tám head được ghi rõ.
Timebox kỹ thuật **4 giờ chủ động của Người 3**; tối đa một lượt smoke test và một lượt huấn luyện giới hạn, không grid search.
Ghi tên checkpoint, phiên bản/revision, seed, max_length, tỷ lệ bị truncation, batch size, số epoch, thời gian và thiết bị.
Không có GPU hoặc lỗi môi trường quá một buổi: chốt baseline; ghi nhánh DistilBERT chưa hoàn thành và chuyển giờ sang phân tích lỗi/demo.
Đây là tái lập ý tưởng dự đoán metric CVSS từ mô tả, không tự nhận tái lập đúng DeepCVA ở mức commit hoặc paper khác khi dữ liệu/kiến trúc khác.

Trong `docs/model-card.md`, Người 3 phải thêm **bảng đối chiếu tái lập** với phương pháp được chọn từ Costa et al. (2022), *Predicting CVSS Metric via Description Interpretation* (DOI `10.1109/ACCESS.2022.3179692`).
Đọc bản bài báo truy cập được trước khi điền, ghi rõ phần chưa xác minh nếu không có toàn văn; không đoán chi tiết thí nghiệm từ tên bài.
Các hàng bắt buộc: dữ liệu/phạm vi, đầu vào, nhãn/phiên bản CVSS, mô hình, split, metric đánh giá; các cột: bài gốc, cách nhóm làm, giống/khác và lý do.
DeepCVA là tài liệu liên quan về đánh giá ở mức commit, không phải thí nghiệm nhóm đang tái lập chính xác nếu chỉ dùng mô tả CVE.

## 4. Phân công cụ thể cho ba người

### Người 1 — Dữ liệu, khả năng tái chạy và kiểm soát đầu vào: 14 giờ

| Mã | Việc làm cụ thể | File làm việc | Giờ | Người kiểm tra |
|---|---|---|---:|---|
| P2-N1-1 | Chốt cohort ML; kiểm tra label/source/missing; xuất bảng số lượng mỗi split | `src/collect/build_dataset.py`, `config/project.yaml` | 3 | Người 3 |
| P2-N1-2 | Thêm kiểm tra trùng ID/mô tả xuyên split, xuất danh sách loại kèm lý do | `src/collect/build_dataset.py`, `notebooks/01_eda.ipynb` | 3 | Người 3 |
| P2-N1-3 | Rà mẫu Web/mobile và độ phủ dữ liệu; hỗ trợ mở rộng phạm vi nếu thiếu trước khi khóa test | `src/collect/filter_scope.py`, `notebooks/01_eda.ipynb` | 2 | Người 2 |
| P2-N1-4 | Chạy lại baseline trên máy thứ hai; kiểm tra artifact/hash/version và đường dẫn tương đối | `data/metadata.json`, ghi nhận vào `docs/model-card.md` qua PR của Người 3 | 2 | Người 3 |
| P2-N1-5 | Đóng băng dataset v1, chuẩn bị đầu vào ranking và bảng thiếu dữ liệu cho Phase 3 | `data/metadata.json`, `docs/data_contract.md` | 2 | Người 2 |
| P2-N1-6 | Review, sửa blocker, tổng hợp bằng chứng bàn giao | Bảng task của nhóm | 2 | Cả nhóm |

**Hoàn thành khi:** Người 3 dùng dataset không cần sửa cột thủ công; Người 2 biết chính xác số CVE đủ điều kiện ranking.
Người 1 không tự thay nhãn CVSS để giúp model: sửa chỉ khi có lỗi parse/chọn nguồn, tăng dataset version và chạy lại các artifact bị ảnh hưởng.

### Người 2 — Ý nghĩa nhãn và nền móng phân tích bảo mật: 14 giờ

| Mã | Việc làm cụ thể | File làm việc | Giờ | Người kiểm tra |
|---|---|---|---:|---|
| P2-N2-1 | Hoàn thành parser/vector validator và Base Score, đối chiếu FIRST | `src/environmental/cvss_environmental.py`, `tests/test_cvss.py` (mới) | 4 | Người 3 |
| P2-N2-2 | Đọc cùng Người 3 ít nhất 10 lỗi validation; giải thích lỗi AV/PR/UI/S/C/I/A | `docs/model-card.md` qua phần review | 2 | Người 3 |
| P2-N2-3 | Hoàn thiện kịch bản 5–6 tài sản Web/mobile; mỗi tài sản có stack/version/lý do CR/IR/AR | `config/assets.yaml`, `src/environmental/asset_inventory.py` | 3 | Người 1 |
| P2-N2-4 | Chuẩn bị shortlist case study, nguồn vendor và mapping sơ bộ CVE–asset | `docs/analysis-results.md` (mới), bảng mapping theo contract | 2 | Người 1 |
| P2-N2-5 | Review giao thức ML, interface score và artifact; bàn giao đầu vào Phase 3 | `docs/data_contract.md`, PR Người 3 | 2 | Cả nhóm |
| P2-N2-6 | Tái dùng cohort đủ điều kiện Người 1 giao; sort CVSS/EPSS/KEV-first theo Phase 3, xuất ranking sơ bộ ngày 13; chưa làm metric/plot | `src/analysis/compare_rankings.py`, `data/processed/rankings.csv` | 1 | Người 1 |

**Mốc chặn phụ thuộc:** giao `base_score(vector)` cuối ngày 8; Người 3 làm F1/accuracy theo nhãn trước, sau đó ghép MAE/RMSE bằng scorer đã kiểm tra.
Với mapping, kiểm tra sản phẩm, phiên bản, thành phần và điều kiện affected; cùng tên vendor chưa đủ chứng minh áp dụng.
Shortlist có ít nhất một trường hợp Web và một trường hợp client/framework/SDK mobile thật sự.

### Người 3 — Mô hình, đánh giá và artifact cho demo: 14 giờ

| Mã | Việc làm cụ thể | File làm việc | Giờ | Người kiểm tra |
|---|---|---|---:|---|
| P2-N3-1 | Chốt label map, split/config, giao diện model và dummy baseline | `config/model.yaml` (mới), `src/model/baseline.py` | 2 | Người 1 |
| P2-N3-2 | TF-IDF + tám classifier, train/validation, lưu/nạp artifact | `src/model/baseline.py` | 3 | Người 1 |
| P2-N3-3 | Metrics, prediction export và notebook gọi lại hàm Python | `src/model/evaluate.py` (mới), `src/model/predict.py` (mới), `notebooks/02_model_eval.ipynb` | 3 | Người 2 |
| P2-N3-4 | DistilBERT có timebox hoặc dùng cùng thời gian xử lý lỗi baseline | `src/model/distilbert_multihead.py` | 4 | Người 1 |
| P2-N3-5 | Chốt model card cùng bảng đối chiếu Costa et al.; chạy test sau khi khóa config, bàn giao | `docs/model-card.md` (mới), artifact ML | 2 | Người 2 |

**Hoàn thành khi:** một câu mô tả đi qua model đã nạp từ disk tạo vector hợp lệ và điểm tính lại; báo cáo có cả sai sót, không chỉ ví dụ đẹp.
Phần đọc lỗi do Người 2 cùng làm; Người 3 không phải tự viết toàn bộ kết luận bảo mật.

## 5. Vibe code file nào, file đó làm gì?

Các interface dưới đây là **đề xuất cần triển khai**, không phải API hiện đang chạy.
Hiện `baseline.py`, `distilbert_multihead.py`, `cvss_environmental.py`, `asset_inventory.py` mới có docstring/TODO.

| File | Trạng thái / chủ sở hữu | Input → output / trách nhiệm |
|---|---|---|
| `config/model.yaml` | Mới, Người 3 | Cấu hình TF-IDF, model, training, artifact paths; tham chiếu seed/split đã chốt trong `config/project.yaml`; giữ label map cố định; không chứa API key |
| `src/model/baseline.py` | Có TODO, Người 3 | Dataset + config → dummy/baseline artifact; `train_baseline(train_df, config)`; không gọi NVD/EPSS |
| `src/model/distilbert_multihead.py` | Có TODO, Người 3 | Mô tả + tám nhãn → encoder/head/checkpoint; train và predict dùng cùng label map |
| `src/model/evaluate.py` | Mới, Người 3 | Ground truth + prediction join bằng ID → metric JSON, bảng theo lớp, danh sách lỗi; `evaluate_predictions(...)` |
| `src/model/predict.py` | Mới, Người 3 | Artifact + danh sách mô tả → tám nhãn, `predicted_vector`, `predicted_base_score`; `predict_descriptions(...)` |
| `src/environmental/cvss_environmental.py` | Có TODO, Người 2 | `parse_vector(vector)`; `base_score(vector) -> float`; báo lỗi phiên bản/vector thiếu metric |
| `src/environmental/asset_inventory.py` | Có TODO, Người 2 | Đọc `config/assets.yaml`, kiểm tra ID và trường bắt buộc, chuẩn bị mapping; không train model |
| `src/analysis/compare_rankings.py` | Có TODO, Người 2 | Ngày 13 chỉ `build_rankings(cohort, policies)` với ba sort keys ở Phase 3 → ranking sơ bộ; chưa kết luận chất lượng chính sách |
| `src/collect/build_dataset.py` | Theo Phase 1, Người 1 | Chuẩn hóa dữ liệu, quản lý split/cohort theo contract; báo lỗi thay vì âm thầm sửa nhãn |
| `src/collect/filter_scope.py` | Theo Phase 1, Người 1 | Lưu quyết định in-scope và bằng chứng Web/mobile; không chọn scope dựa trên điểm model |
| `notebooks/02_model_eval.ipynb` | Mới, Người 3 | Gọi module đánh giá, hiển thị biểu đồ/10 lỗi; không là nơi duy nhất chứa thuật toán |
| `docs/model-card.md` | Mới, Người 3; Người 2 review | Bảng Costa et al. đối chiếu với nhóm; dữ liệu, mục đích, split, metric thật, chi phí, lỗi và giới hạn; ghi nhánh chưa hoàn thành |
| `docs/analysis-results.md` | Mới, Người 2 | Khung case study và nguồn; Phase 3 sẽ thêm ranking thật, chưa điền số kết quả |

**Artifact dự kiến:** `models/baseline.joblib`, checkpoint DistilBERT nếu có, `reports/model_metrics.json`, `data/processed/predictions.csv`.
Nếu dùng đường dẫn khác, sửa đồng thời config, contract và tài liệu; không để mỗi thành viên dùng một tên.
Không commit model lớn hoặc dữ liệu riêng; bàn giao theo cơ chế artifact đã chốt trong kế hoạch tổng.

## 6. Hướng dẫn prompt nhỏ, có thể review

Mỗi prompt làm một việc; người phụ trách phải đọc diff, chạy kiểm tra và giải thích lại chức năng trước khi merge.
Không yêu cầu công cụ “làm hết phase”, tự chọn CVE hay tự viết kết quả nghiên cứu.

**P2-A — Người 3, baseline tối thiểu:**

```text
Đọc docs/data_contract.md, config/model.yaml và src/model/baseline.py.
Chỉ triển khai dummy most-frequent và TF-IDF + Logistic Regression cho 8 metric.
Feature duy nhất là description; fit TF-IDF trên train; dùng split đã cung cấp.
Xử lý head chỉ có một lớp bằng constant classifier, log rõ head bị ảnh hưởng.
Lưu vocabulary, 8 classifiers, label map, config và dataset_version cùng artifact.
Chưa thêm DistilBERT, app, tải dữ liệu hoặc lựa chọn cấu hình dựa trên test.
Trả lệnh chạy dự kiến và một kiểm tra save/load có kết quả dự đoán giống nhau.
```

**P2-B — Người 2, scorer dùng chung:**

```text
Triển khai parse_vector và base_score cho CVSS:3.1 trong
src/environmental/cvss_environmental.py theo FIRST v3.1, không trộn v3.0/v4.0.
Báo lỗi metric thiếu, trùng hoặc giá trị lạ; có xử lý Scope và PR đúng nhánh.
Roundup tuân đặc tả, không thay bằng round() thông thường.
Thêm tests/test_cvss.py bằng vector có expected score đối chiếu độc lập.
Chưa triển khai chính sách ưu tiên hoặc suy luận Environmental từ vùng mạng.
```

**P2-C — Người 1, kiểm tra split:**

```text
Đọc build_dataset.py và data contract. Thêm kiểm tra giao train/val/test rỗng
theo cve_id và nhóm mô tả trùng sau normalization được mô tả rõ.
Giữ thứ tự thời gian; không đưa bản ghi tương lai vào train.
Xuất số dòng loại và lý do, thống kê lớp theo split để người dùng kiểm tra.
Không đổi mốc split hoặc nguồn CVSS một cách tự động để tăng độ cân bằng lớp.
```

**P2-D — Người 3, đánh giá:**

```text
Tạo src/model/evaluate.py theo contract; join theo cve_id + model_version,
không giả định thứ tự dòng. Báo F1 theo metric/lớp với support và label map cố định,
accuracy từng metric, macro-F1, exact vector match, Base MAE/RMSE.
Dùng base_score từ module Environmental. Lớp support=0 phải được ghi rõ;
ghi quy ước zero_division/macro aggregation; không ẩn metric khó học.
Xuất số vector invalid riêng, không âm thầm bỏ khỏi mẫu số.
```

## 7. Đánh giá thế nào để có ý nghĩa?

| Kiểm tra / metric | Câu hỏi được trả lời | Cách diễn giải |
|---|---|---|
| Dummy vs TF-IDF trên cùng split | Mô hình học hơn tần suất lớp chưa? | Báo cùng bảng, không chỉ so accuracy |
| F1 từng metric và từng lớp, support | Metric/lớp hiếm nào bị bỏ sót? | Nêu rõ nhãn vắng ở train hoặc test |
| Macro-F1 trung bình tám head | Chất lượng cân bằng giữa các nhiệm vụ | Cố định quy ước lớp support=0; không dùng một số duy nhất để kết luận |
| Exact vector match | Bao nhiêu CVE đúng cả tám thành phần? | Khó hơn accuracy từng head; báo mẫu số |
| Base Score MAE/RMSE | Sai vector làm lệch điểm bao nhiêu? | Dùng scorer chung trên vector hợp lệ; báo tỷ lệ invalid riêng |
| Lỗi vượt qua ngưỡng severity | Sai số nào dễ gây diễn giải sai? | Đọc từng case; không biến thành khuyến nghị vá tự động |
| Thời gian train/inference, kích thước model | Chi phí có hợp lý cho đồ án? | Đo trên thiết bị cụ thể, không hứa tốc độ máy khác |

Quy ước F1 dùng label map cố định, `zero_division=0`, kèm support; có thể báo thêm macro trên các lớp có support nhưng phải đặt tên riêng.
Tham khảo cách tính từ [tài liệu metrics của scikit-learn](https://scikit-learn.org/stable/modules/model_evaluation.html).
Test chỉ chạy sau khi chốt model/config trên validation; nếu sửa bug sau đó, ghi bug, lý do chạy lại và không biến test thành vòng tuning.
Prediction dùng trong so sánh thứ hạng phụ ở Phase 3 chỉ lấy mẫu held-out; không dùng dự đoán trên train để chứng minh chất lượng.

## 8. Nhịp làm việc và bàn giao theo ngày

| Ngày | Người 1 | Người 2 | Người 3 | Bằng chứng cuối ngày |
|---|---|---|---|---|
| 8 | Chốt split và cohort ML | Giao scorer Base cuối ngày, test độc lập | Dummy + đọc config; F1/accuracy trước, chờ scorer để tính MAE | Cùng parse được một vector, có dummy output |
| 9 | Audit duplicate/leakage | Rà ý nghĩa metric và inventory | TF-IDF bản chạy được | Model save/load thành công |
| 10 | Rà scope, lớp hiếm | Đọc lỗi validation | Evaluate + predict CLI | Bảng metric validation thật |
| 11 | Chạy lại trên máy thứ hai | Chuẩn bị mapping/case shortlist | Timebox DistilBERT | Log chạy hoặc quyết định cắt có lý do |
| 12 | Đóng băng dataset/hash | Review model card | Khóa cấu hình, chạy test | Metric test và artifact khớp model/dataset |
| 13 | Giao cohort đủ điều kiện cho ranking | Xuất ranking sơ bộ; giao scorer/inventory cho Phase 3 | Giao prediction/notebook | Demo 15 phút, CSV đúng schema, đánh dấu checklist |

Lệnh CLI cần có sau triển khai, chạy từ repo root; hiện chưa phải lệnh đã xác minh:

```powershell
python -m src.model.baseline --config config/model.yaml
python -m src.model.evaluate --config config/model.yaml --split test
python -m src.model.predict --config config/model.yaml --split test
# Chỉ chạy nhánh này nếu đã vượt điều kiện thời gian/môi trường:
python -m src.model.distilbert_multihead --config config/model.yaml
```

## 9. Gate kết thúc, tình huống trễ và phần bàn giao

- [ ] Không giao CVE/duplicate giữa train, validation và test; TF-IDF không fit trên test.
- [ ] Có dummy và TF-IDF; tám metric đều xuất hiện trong báo cáo cùng support.
- [ ] Vector dự đoán hợp lệ hoặc lỗi được đếm/ghi rõ; `predicted_base_score` dùng scorer đã kiểm tra.
- [ ] Scorer có ca Scope changed/unchanged, tác động bằng 0, PR khác nhau, Roundup và vector invalid.
- [ ] Model nạp lại được trên máy khác; metadata đủ xác định cấu hình/dataset/split.
- [ ] Ít nhất 10 lỗi validation được phân tích; model card có giới hạn nguồn nhãn và thời điểm cập nhật mô tả.
- [ ] Model card có bảng so với Costa et al., nêu khác biệt dữ liệu/input/model/split/evaluation; không gọi nhánh mô tả CVE là tái lập DeepCVA.
- [ ] Ranking sơ bộ ngày 13 có `cvss_rank`, `epss_rank`, `kev_first_rank` trên cùng cohort theo contract; phân tích chính tiếp tục Phase 3.
- [ ] DistilBERT có trạng thái thật: hoàn thành có log hoặc cắt phạm vi có giải thích; không để TODO được hiểu là đã làm.
- [ ] Người 2 nhận dataset quan sát để làm RQ2 độc lập với thời gian train model.

| Blocker | Cách xử lý trong phase | Điều không được làm |
|---|---|---|
| Train nhỏ hoặc nhiều lớp hiếm | Rà lại filter, mở rộng dữ liệu có lý do trước khóa test; báo support | Tự tạo CVE/nhãn để làm đẹp số liệu |
| Thiếu một lớp ở train | Constant head hoặc classifier học các lớp hiện có; đánh dấu giới hạn | Xóa lớp khỏi báo cáo |
| DistilBERT lỗi/GPU không có | Dừng theo timebox, giữ baseline, phân tích giới hạn | Dời RQ2/RQ3 để tuning nhiều ngày |
| Base scorer chưa sẵn sàng | Đánh giá nhãn trước; Người 2 ưu tiên scorer trước Environmental | Viết một scorer thứ hai không kiểm chứng |
| Baseline kém hơn dummy ở vài metric | Báo thật, kiểm tra leakage/label/split, đọc lỗi | Che metric hoặc lựa test khác |

**Bàn giao sang Phase 3:** Người 1 gửi dataset v1 + metadata; Người 2 gửi Base scorer + inventory + shortlist + ranking sơ bộ; Người 3 gửi model/metrics/prediction, model card đối chiếu bài gốc và ghi rõ test IDs.
RQ2/RQ3 vẫn triển khai được nếu DistilBERT bị cắt: đồ án cần giải thích ưu tiên vá cho Web/mobile bằng dữ liệu và bối cảnh.
