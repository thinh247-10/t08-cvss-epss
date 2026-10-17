# Model card — Phase 2, Người 3

Ngày chạy: **15/10/2026 (Asia/Saigon)**. Kết quả dưới đây lấy từ lần chạy thật trên
`t08-v1.0-20261010`, không phải smoke test. TF-IDF đã được chọn bằng validation,
lưu/nạp lại, khóa hash rồi đánh giá test cuối. Không điều chỉnh mô hình sau khi xem test.

## Mục đích và giới hạn sử dụng

Ước lượng tám metric CVSS 3.1 AV/AC/PR/UI/S/C/I/A từ mô tả tiếng Anh; ghép vector
và tính Base Score bằng `src.environmental.cvss_base.calculate_base_score` của N2.
Đây là hỗ trợ đọc mức nghiêm trọng. Kết quả không thay CVSS nguồn, không dự đoán
EPSS/KEV và không tự quyết định thứ tự vá. Description mới không có ground truth
thì chỉ hiển thị ước lượng, không hiển thị accuracy.

## Dữ liệu và giao thức

Gói nhận từ `D:/Downloads/Quản trị mạng-Đồ án/phase1_v1_20261010.zip`, đúng
38.599.819 byte và SHA-256
`215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.
Verifier offline đã báo `PHASE1 RELEASE OK`, kiểm đủ 14 file. Input duy nhất là
`data/processed/phase1_v1_20261010/ml_cohort.parquet`; SHA-256
`eaa7f845596cc8b1a0ac802a792f2b495006cec87acc7cab28434fcb8905fdb6`.

| Cohort | Train | Validation | Test |
|---|---:|---:|---:|
| Toàn miền ML | 28.815 | 19.606 | 18.821 |
| Web/mobile được nhận scope | 219 | 69 | 108 |

Split giữ nguyên theo `published`: train năm 2023, validation nửa đầu 2024,
test nửa cuối 2024. Không chia hoặc khử trùng lại; không sửa ID/nhãn trong gói.
**Cả 8 CVE mobile đều ở train.** Validation/test scoped chỉ có Web; chưa đo được
chất lượng dự đoán riêng trên mobile. Scope là chính sách sản phẩm có giới hạn,
không phải mẫu bao phủ toàn bộ lỗ hổng Web/mobile.

Chỉ `description` là feature. ID, ngày, sản phẩm, scope, nhãn/vector/điểm nguồn,
EPSS và KEV không được đưa vào vectorizer/classifier. Label map cố định:
AV=N/A/L/P; AC=L/H; PR=N/L/H; UI=N/R; S=U/C; C/I/A=N/L/H.
Macro-F1 dùng mọi lớp, kể cả support 0, với `zero_division=0`.

## Mô hình, lựa chọn và chi phí

Dummy: tám `DummyClassifier(strategy="most_frequent")` fit train. Baseline:
một TF-IDF chung fit train, word unigram/bigram, `min_df=2`, tối đa 50.000 feature;
tám Logistic Regression riêng, `class_weight="balanced"`, `solver="lbfgs"`,
`max_iter=1000`, `tol=0.0001`, seed 42. Head chỉ một lớp dùng constant Dummy có log;
lần train v1 này không cần fallback. Train rỗng/vocabulary rỗng/version sai là lỗi.

Tiêu chí khai báo trước: trung bình macro-F1 của tám metric trên validation toàn
miền; nếu chênh lệch không quá 0,000001 thì chọn thời gian train thấp hơn, sau đó
thứ tự khai báo. Hai cấu hình chỉ khác `C`; không xem test trong vòng chọn.

| C | Validation mean macro-F1 | Thời gian train (giây) | Kết quả |
|---:|---:|---:|---|
| 1,0 | 0,750431 | 19,807 | Được chọn |
| 0,5 | 0,744926 | 15,922 | Không được chọn |

Thời gian mỗi lượt gồm chuẩn bị input, TF-IDF, Dummy và tám head; không gồm
verifier/evaluator. Tổng hai lượt khoảng 35,729 giây, là số đo trên máy này.
Máy chạy: Ryzen 7 7730U, 8 nhân/16 luồng, RAM vật lý 15,4 GiB, Windows 11,
Python 3.13.16. Các biến `OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS`,
`MKL_NUM_THREADS` đều đặt 4 cho hai lệnh chạy chính thức. Baseline chạy CPU.
Chi tiết thiết bị ở [phase2_hardware.json](../reports/phase2_hardware.json).

Quy tắc `mask_explicit_cvss_v1` cố định che vector CVSS có tiền tố, vector v3
đủ tám metric không có tiền tố, vector v2 cũ và số điểm CVSS được nêu tường minh.
Train và inference dùng cùng hàm, không xóa từ như remote/authenticated.

| Split | Dòng được che | Dòng chứa vector được che | Dòng chứa score được che |
|---|---:|---:|---:|
| Train | 313/28.815 | 306 | 302 |
| Validation | 226/19.606 | 219 | 222 |
| Test | 153/18.821 | 147 | 144 |

Một dòng có thể chứa cả vector lẫn score. Đây là số khớp quy tắc regex cố định,
không khẳng định đã phát hiện mọi cách diễn đạt điểm/nhãn trong ngôn ngữ tự nhiên.
Test chỉ được quét cấu trúc mô tả trước khóa; prediction/metric test được tạo sau khóa.

## Validation — dùng chọn cấu hình

| Mô hình | Cohort | n | Mean macro-F1 | Exact vector | Base MAE | Base RMSE |
|---|---|---:|---:|---:|---:|---:|
| Dummy | Toàn miền | 19.606 | 0,298628 | 0,101755 | 2,936030 | 3,391720 |
| Dummy | Scoped Web | 69 | 0,278970 | 0,043478 | 3,388406 | 3,727804 |
| TF-IDF | Toàn miền | 19.606 | 0,750431 | 0,383709 | 1,118805 | 1,837327 |
| TF-IDF | Scoped Web | 69 | 0,616601 | 0,231884 | 1,639130 | 2,474420 |

## Test cuối — sau khi khóa

| Mô hình | Cohort | n | Mean macro-F1 | Exact vector | Base MAE | Base RMSE |
|---|---|---:|---:|---:|---:|---:|
| Dummy | Toàn miền | 18.821 | 0,298403 | 0,102279 | 2,900553 | 3,355398 |
| Dummy | Scoped Web | 108 | 0,289889 | 0,083333 | 3,257407 | 3,645037 |
| TF-IDF | Toàn miền | 18.821 | 0,752142 | 0,386536 | 1,078030 | 1,769874 |
| TF-IDF | Scoped Web | 108 | 0,654889 | 0,351852 | 1,750926 | 2,833023 |

Coverage điểm là **100%** cho mọi ô: 19.606/19.606 và 69/69 ở validation;
18.821/18.821 và 108/108 ở test. Mỗi mô hình có **0 prediction invalid** và
**0 target invalid**. Mẫu số exact-vector là toàn bộ target hợp lệ; prediction
lỗi nếu có vẫn tính sai. MAE/RMSE chỉ dùng cặp score hợp lệ và luôn đi kèm coverage.
Evaluator ghép theo CVE ID và kiểm version/split; không dựa vào thứ tự dòng.

Accuracy/F1 từng metric, precision/recall/F1/support từng lớp và confusion matrix
của cả hai mô hình nằm trong [model_metrics.json](../reports/model_metrics.json).
[Notebook đã có output](../notebooks/02_model_eval.ipynb) hiển thị riêng validation,
test và các lớp support 0. Điểm trung bình không thể hiện toàn bộ lỗi từng lớp;
exact-vector toàn miền chỉ khoảng 38,65%, dù mean macro-F1 đạt 0,7521.

## Phân tích lỗi validation và giới hạn dữ liệu

Đã xuất 12.083 lỗi validation và chọn 10 ID lỗi đầu theo thứ tự CVE để đọc mô tả,
đối chiếu target/prediction. [Phân tích 10 ca](../reports/validation_error_analysis.md)
giải thích sai PR/UI, Scope và C/I/A, điều kiện mô tả thiếu và nguy cơ diễn giải
sai điều kiện khai thác. Các ca không phải mẫu đại diện; có nhiều mô tả XSS gần
nhau. CVE-2015-10123 sai PR/UI nhưng vẫn cùng Base 8,8: MAE bằng 0 không có nghĩa
đúng vector. Không dùng lỗi test để sửa model hoặc chọn ca phân tích.

File [validation_errors_n2.csv](../reports/validation_errors_n2.csv) và báo cáo
được chuẩn bị cho N2; **chưa có xác nhận N2 đã nhận hoặc review độc lập**.
Phân tích trong repo là hỗ trợ đọc mô tả/nhãn, không xác minh lại advisory hay
khẳng định mọi nhãn nguồn đều đúng.

NVD là snapshot hiện có: mô tả/nhãn có thể được cập nhật sau `published`, nên
không phải backtest trên thông tin lịch sử tại thời điểm công bố. Nhãn nhiều nguồn
có thể không nhất quán. MinHash/Jaccard có thể bỏ sót gần trùng, có giới hạn bucket.
**5.944 nhóm sản phẩm giao nhau giữa split**; đây là đánh giá thời gian có thể
gặp lại sản phẩm, chưa chứng minh tổng quát hóa sang sản phẩm chưa thấy.

## Đối chiếu Costa et al. (2022)

Đã đọc phần III.A, IV/V của [bài gốc do tác giả đăng](https://www.researchgate.net/publication/361207514_Predicting_CVSS_Metric_via_Description_Interpretation),
đối chiếu [repository tác giả](https://github.com/Joana-Cabral/CVSS_Prediction) và
[trang xuất bản của viện nghiên cứu](https://www.it.pt/Publications/PaperJournal/33219).
DOI: [10.1109/ACCESS.2022.3179692](https://doi.org/10.1109/ACCESS.2022.3179692).

| Mục | Costa et al. | Lần chạy này |
|---|---|---|
| Dữ liệu | NVD đến 04/2021, 79.810 CVE | V1, 67.242 CVE |
| Input | Mô tả lỗ hổng | Chỉ description tiếng Anh |
| Nhãn | Tám metric, CVSS v3 | Tám metric, CVSS 3.1 |
| Model | BERT/DistilBERT/RoBERTa/ALBERT/DeBERTa | Dummy, TF-IDF + tám LR |
| Split | Train 63.848/test 15.962, 80/20 | Thời gian 28.815/19.606/18.821 |
| Metric | Accuracy, F1, balanced accuracy | Macro-F1 cố định lớp, exact vector, Base MAE/RMSE, coverage |

Chưa xác minh bài dùng riêng v3.1, cách tạo split, seed, validation riêng hoặc
cách average F1. Không gọi F1 của bài là macro-F1, không so điểm trực tiếp khi
dataset/giao thức khác nhau. Đây không phải tái lập DeepCVA commit-level.

## DistilBERT và các xác nhận bên ngoài — lịch sử trước khi N1 chạy

DistilBERT: **`not_run`**, D05 **`pending`**. Torch/Transformers chưa cài;
backend tăng tốc và thời gian máy chưa xác nhận. Không suy ra GPU dùng được từ
tên Radeon; chưa có smoke đo tốc độ nên chưa có ước tính train có căn cứ.
Đề xuất giới hạn vẫn là 4 giờ thao tác kỹ thuật, tổng 6 giờ máy train,
2 lượt gồm smoke và tối đa 3 epoch/lượt. Chưa tải checkpoint; không tạo metric
DistilBERT giả. N1 cần chốt thiết bị/ngân sách nếu tiếp tục nhánh mở rộng.

## Artifact và lệnh đã chạy

`models/baseline.joblib`: **7.474.244 byte**, chứa Dummy, vectorizer, tám classifier,
label map, config đã giải quyết, seed, phiên bản thư viện và audit preprocessing.
Model TF-IDF: `tfidf-v1-candidate-1`; Dummy: `tfidf-v1-candidate-1-dummy`.
SHA-256 artifact:
`9b55da5616f725ed400824564400059b1b9fb07cee8db6ff13da7adefb087299`.

Khóa tại **18:55:44 ngày 15/10/2026** giờ Việt Nam, trước test bắt đầu
**18:56:34**; test hoàn thành **18:57:06**. Hash/config/dataset và dấu thời gian
UTC đầy đủ nằm trong `models/phase2_lock.json` và
[manifest bàn giao](handoffs/phase-2-model.json). Config đã khóa không sửa lại.

`data/processed/predictions.csv`: **76.854 dòng**, hai mô hình × (19.606 validation
+ 18.821 test). Đúng khóa `(cve_id, model_version)`, đủ version/split/usage,
tám `pred_*`, vector/score/validity/error. Không có prediction train trong bảng đánh giá.
Model và prediction giữ ngoài Git theo `.gitignore`.

Các lệnh thực tế, chạy tại gốc repo bằng PowerShell:

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
$env:OMP_NUM_THREADS = '4'
$env:OPENBLAS_NUM_THREADS = '4'
$env:MKL_NUM_THREADS = '4'
.\.venv\Scripts\python.exe -u -m src.model.run_phase2 select
.\.venv\Scripts\python.exe -u -m src.model.run_phase2 final
.\.venv\Scripts\python.exe -m src.model.verify_handoff --output reports/phase2_local_reproduction.json
.\.venv\Scripts\python.exe -m src.model.predict --description 'An unauthenticated remote attacker can execute arbitrary code by sending a crafted network request.'
```

**161 kiểm thử đạt.** Save/load đã được đối chiếu prediction giống nhau.
Verifier Phase 2 xác minh hash, version/dependency và 5 mẫu validation × 2 mô hình
khớp toàn bộ 12 trường nhãn/vector/score/validity/error. Báo cáo
[phase2_local_reproduction.json](../reports/phase2_local_reproduction.json) có
`runtime_versions_match=true`. Demo ở trên trả vector 9,8 và `prediction_usage=demo`;
đây không phải phép đo accuracy.

Trên máy thứ hai, nhận code/gói artifact, đặt đúng đường dẫn và cài:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt -r requirements-model.txt
.\.venv\Scripts\python.exe -m src.model.verify_handoff --output reports/p2_reproduction_n1.json
```

Chỉ nạp joblib đáng tin cậy của nhóm. Manifest chứa hash/version, dependency pin
và mô tả/expected prediction của 5 mẫu validation để N1 đối chiếu offline.
**Chưa có kết quả trên máy thứ hai**; kiểm tra tại máy N3 không thay xác nhận đó.
Lệnh select/final dùng cho checkout chưa có artifact/lock. Với bản hiện tại đã
khóa, CLI từ chối train ghi đè hoặc chạy test lại; không xóa lock để né kiểm tra.
Commit/push/PR và việc chuyển artifact cho N1/N2 chưa được thực hiện trong phiên này.
## Cập nhật tích hợp N1 — 17/10/2026

N1 đã train lại cấu hình cố định C=1.0, lưu artifact phiên bản riêng và đối chiếu
toàn bộ metric với báo cáo N3: khớp. Gói ZIP mới đã được giải nén, xác minh
checksum và inference. Đây là lần retraining, chưa xác minh joblib gốc của N3.
Xem [báo cáo N1](../reports/p2_reproduction_n1.md) và
[hướng dẫn nhận gói](phase-2-n1-chay-thay-n3.md).

N2 đã review 13 CVE validation, phủ lỗi cả tám metric; hai CVE thuộc scope Web.
Bảng lỗi của model mới khớp bảng gốc nên phân tích này vẫn áp dụng. Điểm cần
chú ý: “remote” không xác định PR; tên XSS không tự quyết định Scope; tác động
đọc và ghi dữ liệu cần phân biệt. Đây là mẫu có chủ đích, không đại diện tỷ lệ
lỗi toàn tập và không phải attribution đã kiểm chứng. Xem
[review bảo mật N2](../reports/p2_validation_security_review.md).

Phần trên giữ báo cáo lần chạy gốc N3; các tên model/hash và ghi chú chưa nhận
artifact trên máy thứ hai thuộc lần chạy đó. Tại thời điểm cập nhật baseline này, DistilBERT chưa chạy.

## Kết quả DistilBERT cuối ngày 17/10/2026

N1 đã chạy thay N3 một encoder chung và tám đầu phân loại, một epoch cố định trên
28.815 mẫu train. Version `distilbert-v1-n1-20261017`, cùng split đóng băng, không dùng
EPSS/KEV làm input. Mô hình đã lưu và nạp lại từ gói giải nén bằng CPU.

Test toàn ML: mean macro-F1 **0,7317**, exact vector **33,05%**, Base MAE **1,1339**;
TF-IDF tương ứng **0,7521 / 38,65% / 1,0780**. Trên 108 mẫu Web test,
DistilBERT có MAE **1,5093** so với TF-IDF **1,7509**, nhưng macro-F1 và exact vector
thấp hơn. Không có mẫu mobile validation/test; không suy rộng kết quả sang mobile.

Đây là một epoch/một seed và được thực hiện sau khi đã biết kết quả baseline;
không phải so sánh mù hoặc tái lập nguyên vẹn bài Costa. Không điều chỉnh cấu hình theo test.
Giới hạn truncation 256 token và dữ liệu/nhãn vẫn áp dụng. Xem [protocol và số đo](../reports/p2_distilbert_run.md),
[bảng so sánh](../reports/p2_model_comparison.csv), [bàn giao cuối](phase-2-completion.md).
