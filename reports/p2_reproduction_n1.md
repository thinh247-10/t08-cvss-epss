# N1 chạy baseline thay N3 — 17/10/2026

> Cập nhật sau lần chạy: đã merge N3 tại `94782a0` và N2 tại `df49544` vào
> develop. Bộ test trên bản sau merge: **175/175 đạt, 39,482 giây**. Các ghi chú
> “chưa merge” bên dưới ghi trạng thái tại lúc tạo artifact, trước bước tích hợp.

**Đã chạy thật thành công.** N1 huấn luyện lại cấu hình baseline N3 đã chọn,
không tìm lại siêu tham số. Đây là artifact mới; chưa nhận/xác minh joblib gốc N3.

## Nguồn và quy trình

- N3: `a5c0c16d862059819c2b10f973e91827796ac30e`; bản kết hợp N2 `add095a`
  trong `data/processed/reviews/p2_combined_20261017` (175 test đã đạt ở lần review).
- Dataset `t08-v1.0-20261010`: 14 file đúng manifest; 28.815 train,
  19.606 validation, 18.821 test. Không đổi scope, nhãn, split hay bản release.
- TF-IDF + 8 Logistic Regression, C=1.0, seed 42, preprocessing N3;
  chỉ fit train, không đưa CVSS/EPSS/KEV vào feature.
- Thời gian train đo được: **43,2835 giây**. Khóa model/config/dataset trước test.
- Python 3.14.3; scikit-learn 1.9.1; các dependency ghi trong manifest.
- Model mới: `tfidf-v1-n1-reproduction-20261017` và bản Dummy tương ứng.

## Kết quả thực tế

| TF-IDF | Số mẫu | Trung bình macro-F1 8 metric | Exact vector | Base MAE |
|---|---:|---:|---:|---:|
| Validation toàn ML | 19.606 | 0,750431 | 38,3709% | 1,118805 |
| Test toàn ML | 18.821 | 0,752142 | 38,6536% | 1,078030 |
| Validation trong scope | 69 | 0,616601 | 23,1884% | 1,639130 |
| Test trong scope | 108 | 0,654889 | 35,1852% | 1,750926 |

Các tập trong scope validation/test ở release v1 chỉ có Web, không có mobile.
Không dùng số đo toàn ML để tuyên bố hiệu quả riêng cho Web/mobile.

**Toàn bộ trường metric trong `scopes` của Dummy và TF-IDF giống báo cáo N3**,
bao gồm từng metric/confusion matrix, cả validation/test và cả hai phạm vi.
12.083 dòng lỗi validation khớp theo CVE ID trên mọi cột trừ model_version.
Điều này hỗ trợ tính tái lập kết quả; không chứng minh hash joblib gốc N3.

Đã xuất **76.854 dòng prediction** = 38.427 mẫu giữ lại × 2 mô hình.
Save/load trên 5 mẫu validation đạt. Verifier kiểm 40 file đúng hash/size,
5 mẫu × 2 model khớp đủ nhãn/vector/score/validity/error, runtime dependency khớp.
Giải nén ZIP vào thư mục mới và chạy verifier trong tiến trình Python mới: đạt.
Không train lại hay đánh giá test lại trong bước kiểm ZIP.

## Artifact bàn giao

Thư mục: `data/processed/p2_n1_reproduction_20261017/`.

- `models/baseline.joblib`: model đã train.
- `models/phase2_lock.json`: khóa model/config/dataset và dấu thời gian đánh giá.
- `data/processed/predictions.csv`: prediction validation/test của cả hai model.
- `reports/model_metrics.json`: metric đầy đủ.
- `reports/comparison_to_N3.json`: đối chiếu metric tự động.
- `reports/reproduction_verification.json`: kiểm hash và inference.
- `docs/handoffs/phase-2-model.json`: manifest bàn giao.
- `src/`, `config/model.yaml`, `requirements-model.txt`: mã nguồn/cấu hình/runtime.

ZIP: `data/processed/p2_n1_reproduction_20261017.zip`, **7.863.175 byte**.

SHA-256 ZIP:
`ce2d97a5a631818e06acba839bf5d7e63df15518b19ca816b3a49b85765a7e19`.

SHA-256 model:
`c68d530ff7818f5d469da647246e787517d9d213b59286d9a6f67dd647d05265`.

ZIP giữ nguyên byte các file, xử lý được vấn đề LF/CRLF cho gói mới. Không sửa
manifest lịch sử hoặc giả định gói cũ của N3 đã được sửa. Dữ liệu thô và API key
không nằm trong ZIP. Config chứa đường dẫn dataset trên máy N1; inference không
cần dataset, còn người huấn luyện lại phải nhận release v1 và cấu hình đường dẫn.

## Tích hợp nhận xét N2 và giới hạn

N2 đã review 13 CVE validation, trong đó 2 CVE Web thuộc scope v1, phủ lỗi cả
8 thành phần. Bảng lỗi của lần chạy mới giống bảng N3 nên nhận xét N2 vẫn áp dụng:
không suy PR từ chữ “remote”, không tự suy Scope từ tên XSS, và cần phân biệt
tác động đọc/ghi với suy đoán thực thi mã. Đây là mẫu review có chủ đích, không
đại diện tỷ lệ lỗi toàn bộ tập. Xem `reports/p2_validation_security_review.md`
trong bản mã nguồn N2; chưa coi diễn giải đó là xác minh advisory hay attribution.

**Phần chạy baseline thay N3 đã xong.** DistilBERT chưa chạy, D05 chưa chốt;
code N2/N3 chưa merge vào develop. Việc chạy này không tự đánh dấu toàn Phase 2
hoàn tất. Hướng dẫn dùng gói và script: [chạy thay N3](../docs/phase-2-n1-chay-thay-n3.md).
