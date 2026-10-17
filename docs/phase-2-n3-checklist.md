# Phase 2 — checklist thực hiện của Người 3

Đối chiếu theo [yêu cầu N3](phase-2-nguoi-3.md), [hợp đồng dữ liệu](data_contract.md),
[kế hoạch model](model-plan.md) và [manifest v1](handoffs/phase-1-v1.json).
Ngày kiểm tra đầu vào: **2026-10-15, Asia/Saigon**. Dấu hoàn thành chỉ dùng cho việc
có bằng chứng thực tế; mã chạy được trên fixture không thay thế kết quả nghiên cứu v1.

## 1. Đầu vào và điều kiện chạy thật

- [x] Xác định đúng dataset yêu cầu: `t08-v1.0-20261010`.
- [x] Đọc hash và kích thước mong đợi trong manifest, không tạo hash thay thế.
- [x] Kiểm tra tên gói/thư mục trong workspace, kể cả file bị Git ignore, và tìm
  `phase1_v1_20261010*` trực tiếp trong `C:/Users/ASUS/Downloads`.
- [x] Có `phase1_v1_20261010.zip` đúng **38.599.819 byte**, SHA-256
  `215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.
- [x] Có `data/processed/phase1_v1_20261010/ml_cohort.parquet`, SHA-256
  `eaa7f845596cc8b1a0ac802a792f2b495006cec87acc7cab28434fcb8905fdb6`.
- [x] Verifier thực tế báo `PHASE1 RELEASE OK` trước khi huấn luyện/đánh giá v1.

**Kết quả tìm đầu vào:** probe đầu không thấy gói trong workspace/Downloads mặc
định. Người dùng sau đó cung cấp đường dẫn
`D:/Downloads/Quản trị mạng-Đồ án/phase1_v1_20261010.zip`; hash và kích thước đã
khớp manifest. Release đã được giải nén đúng vào `data/processed/phase1_v1_20261010`.
Giữ pilot `joined_pilot_20261005T164912_356960Z` riêng. Không tải lại NVD/EPSS/KEV
hoặc tự tái tạo gói v1 từ pilot. Verifier đã kiểm đủ **14 hash**, xác nhận 67.242
dòng ML, split **28.815/19.606/18.821**, **0** sai lệch Base Score.

Gói v1 cần giữ nguyên 67.242 ID: train **28.815**, validation **19.606**, test
**18.821**. Không chia lại hoặc khử trùng lại. Chỉ `description` là feature;
AV/AC/PR/UI/S/C/I/A là target. EPSS, KEV, CVSS nguồn, ID và ngày không là feature.
Web/mobile phải báo riêng theo support **219/69/108**; 8 mobile đều ở train, vì vậy
không tuyên bố đã đo chất lượng trên mobile validation/test.

## 2. Chứng cứ cần có cho Bước A — baseline

- [x] Dummy most-frequent cho từng metric fit riêng trên train.
- [x] Một TF-IDF chung fit chỉ train, tám Logistic Regression độc lập.
- [x] Head chỉ có một lớp dùng constant/Dummy và ghi rõ fallback.
- [x] Train rỗng, mô tả rỗng, vocabulary rỗng hoặc dataset version sai báo lỗi.
- [x] Kiểm kê chuỗi vector/điểm CVSS trong description, ghi số dòng theo split;
  preprocessing cố định dùng giống nhau ở train/inference.
- [x] Tối đa hai cấu hình TF-IDF; khóa tiêu chí validation trước khi lựa chọn.
- [x] Dùng trung bình macro-F1 tám metric trên toàn label map để chọn cấu hình;
  chi phí và tie-break có quy tắc công khai; không chọn bằng test.
- [x] Artifact chứa Dummy, vectorizer, classifier/fallback, labels, config,
  model/dataset version, seed và phiên bản thư viện.
- [x] Save/load cho prediction giống nhau.
- [x] `requirements-model.txt` chứa dependency baseline thực sự dùng.
- [x] Unit test chứng minh description-only, train-only vocabulary, fallback,
  save/load và các input/version lỗi; không huấn luyện full v1 trong unit test.
- [x] Ghi metric validation thật của Dummy và TF-IDF trên v1.

Đã chọn candidate 1 (`C=1.0`) với validation mean macro-F1
**0,7504305488266946**, so với **0,7449259908422061** của candidate 2 (`C=0.5`).
Dummy đạt **0,2986276006979571** trên cùng 19.606 mẫu validation. Xem
[model_selection.json](../reports/model_selection.json); các giá trị này là
toàn miền, không được gọi là kết quả riêng Web/mobile. Unit/smoke test đã qua
trước chạy thật; split v1 không bị thay đổi.

## 3. Chứng cứ cần có cho Bước B — inference/evaluation

- [x] Inference nạp artifact, tạo tám nhãn/vector và gọi scorer chung
  `src.environmental.cvss_base.calculate_base_score`.
- [x] Prediction giữ khóa `(cve_id, model_version)`; model khác có version khác.
- [x] Export đủ schema: ID, split, dataset/model version, `prediction_usage`,
  `pred_AV`…`pred_A`, `predicted_vector`, `predicted_base_score`, `vector_valid`,
  `prediction_error`.
- [x] Evaluator join theo ID/version; đảo thứ tự prediction không làm sai kết quả.
- [x] Thiếu/trùng ID, sai version hoặc split phải phát hiện được.
- [x] Có accuracy, macro-F1, F1 từng lớp và support với label map cố định;
  `zero_division=0`, giữ lớp support 0.
- [x] Exact-vector dùng toàn bộ số CVE đủ nhãn làm mẫu số, prediction lỗi tính sai.
- [x] Base MAE/RMSE chỉ trên cặp score tính được; báo cả tử số/mẫu số coverage.
- [x] Đếm prediction lỗi, vector invalid và target lỗi riêng; không âm thầm bỏ dòng.
- [x] Split rỗng/cặp score rỗng trả null/N/A, không tạo metric 0 giả.
- [x] Báo riêng toàn miền và scoped, validation và test.
- [x] Notebook gọi module, đọc artifact thật và lưu output; N1 chạy 12 cell trong
  `notebooks/02_model_eval_n1.ipynb` ngày 17/10, không train/đánh giá lại test.
- [x] Xuất ít nhất 10 lỗi **validation** cho N2, kèm
  [phân tích bảo mật từng ca](../reports/validation_error_analysis.md).
- [x] N2 đã review 13 CVE: `reports/p2_validation_security_review.md`, commit
  `add095a`, N1 đối chiếu với release v1 và bảng lỗi N3.

## 4. Chứng cứ cần có cho Bước C — khóa/test/bàn giao

- [x] Khóa config, artifact/hash và tiêu chí lựa chọn trước khi chạy test cuối.
- [x] Ghi kết quả test thực tế sau khóa, không chỉnh model từ lỗi/điểm test.
- [x] Model card ghi mục đích, giới hạn, version/split, cấu hình chọn, thiết bị,
  thời gian và validation/test riêng.
- [x] Model card có bảng Costa bên dưới và nguồn gốc từng khẳng định.
- [x] Nêu NVD là snapshot hiện tại, mô tả/nhãn có thể cập nhật sau published;
  MinHash có thể bỏ sót và sản phẩm vẫn giao nhau giữa các split.
- [x] Manifest artifact thật có SHA-256, version và dependency; không ghi hash giả.
- [x] N1 chạy lại cấu hình N3 đã chọn, metric khớp; tạo artifact phiên bản riêng,
  kiểm checksum và inference sau giải nén. Đây là retraining, chưa kiểm joblib gốc
  N3 vì chưa nhận file. Xem `reports/p2_reproduction_n1.md`.
- [x] Commit N2/N3 đã merge và push develop đến `fe99cdd`; gói ZIP N1 có checksum.
  Chưa ghi thay lời xác nhận hai bạn đã tải ZIP N1 mới.

Không kiểm tra ô metric full-run/test/second-machine chỉ từ smoke test hoặc từ số
được ghi trong kế hoạch. Khi thiếu release v1, giữ các mục đó chưa hoàn thành.

## 5. Bước D — kiểm tra thiết bị và D05

- [x] Kiểm tra CPU, RAM, GPU, Python và dependency hiện tại bằng truy vấn đọc.
- [x] Ghi trạng thái thật vào [reports/phase2_hardware.json](../reports/phase2_hardware.json).
- [x] Trạng thái cuối: N1 chạy thay N3, DistilBERT đã hoàn tất; xem [báo cáo](../reports/p2_distilbert_run.md). Probe N3 bên dưới là lịch sử trước quyết định này.
- [x] N1 chốt D05: một epoch, RTX 3050/CUDA, ngân sách tối đa 6 giờ máy, ước tính từ smoke.
- [x] Đã xác minh backend, chạy smoke rồi train thật;
  dùng cùng ID/labels/evaluator, lưu checkpoint revision/tokenizer phù hợp.

Máy kiểm tra có Ryzen 7 7730U **8 nhân/16 luồng**, RAM vật lý **15,4 GiB**,
Windows 11 và AMD Radeon (TM) Graphics. Trường AdapterRAM của Win32 báo 512 MiB;
đây không phải bằng chứng về VRAM dùng huấn luyện hoặc backend tăng tốc. Python
**3.13.16**; tại lúc probe, Torch và Transformers chưa được cài, không tìm thấy
module. Chưa đo smoke train nên thời gian train dự kiến để **null**, không giả định
tên Radeon đồng nghĩa với GPU dùng được cho Torch.

Giới hạn kế hoạch có hai loại: tối đa **4 giờ thao tác kỹ thuật**; đề xuất tối đa
**6 giờ máy train tổng**, tối đa **2 lượt gồm smoke**, tối đa **3 epoch/lượt**.
Chưa cài Torch/Transformers, chưa tải checkpoint và chưa train DistilBERT trong probe.

## 6. Đối chiếu Costa et al. (2022) từ nguồn gốc

Ấn phẩm: *Predicting CVSS Metric via Description Interpretation*, IEEE Access 10,
59125–59134, DOI [10.1109/ACCESS.2022.3179692](https://doi.org/10.1109/ACCESS.2022.3179692).
Thông tin xuất bản được xác nhận bởi
[trang viện nghiên cứu của tác giả](https://www.it.pt/Publications/PaperJournal/33219).
Đã đọc phần III.A, IV và V của
[toàn văn bài gốc do tác giả đăng](https://www.researchgate.net/publication/361207514_Predicting_CVSS_Metric_via_Description_Interpretation),
đồng thời đối chiếu [repository chính thức](https://github.com/Joana-Cabral/CVSS_Prediction).

| Mục | Costa et al. — đã xác minh | Thí nghiệm Phase 2 N3 |
|---|---|---|
| Dữ liệu | NVD đến 04/2021; 79.810 bản ghi có CVSS v3 | Gói v1 đã khóa 67.242 ID |
| Input | Mô tả lỗ hổng | Chỉ `description` tiếng Anh |
| Target | Tám metric AV/AC/PR/UI/S/C/I/A; bài ghi CVSS version 3 | CVSS 3.1, label map cố định |
| Model | BERT, DistilBERT, RoBERTa, ALBERT, DeBERTa | Dummy và TF-IDF + tám Logistic Regression; DistilBERT chờ D05 |
| Split | Train 63.848/test 15.962 (80/20) | Train 28.815/validation 19.606/test 18.821 theo split thời gian v1 |
| Metric | Accuracy, F1, balanced accuracy từng metric | Macro-F1 toàn label map, accuracy, F1/support từng lớp, exact-vector, Base MAE/RMSE và coverage |
| Tiền xử lý | Bài thử lemmatization, stemming và mở vocabulary; kết hợp lemmatization + 5.000 từ tốt nhất trong thí nghiệm của họ | Quy tắc cố định của baseline; nhánh DistilBERT dự kiến không lemmatize |

Nguồn mô hình và metric: phần III.A (trang 59127–59128); số mẫu và split: phần IV
(trang 59129); kết luận tiền xử lý: abstract/phần V. **Chưa xác minh** bài dùng riêng
v3.1, split ngẫu nhiên hay thời gian, seed, validation riêng hoặc cách average F1.
Không gọi F1 của bài là macro-F1, không khẳng định cùng giao thức, không suy ra
exact-vector/Base MAE/RMSE của bài. Không so trực tiếp điểm số giữa hai dataset.
Đây là nghiên cứu từ mô tả CVE, không phải tái lập DeepCVA commit-level.
