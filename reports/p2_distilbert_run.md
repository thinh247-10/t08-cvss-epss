# DistilBERT — kết quả chạy thật trên máy N1

Ngày 17/10/2026. Model `distilbert-v1-n1-20261017`, dataset
`t08-v1.0-20261010`. **Đã hoàn thành smoke, một epoch train, validation và test.**

## Giao thức và tài nguyên

- Checkpoint `distilbert/distilbert-base-uncased`, revision
  `12040accade4e8a0f71eabdb258fecc2e7e948be`; hash từng file trong báo cáo môi trường.
- Encoder chung, tám head AV/AC/PR/UI/S/C/I/A; đầu vào chỉ là description.
- Trọng số lớp chỉ tính từ 28.815 mẫu train. Max length 256; batch 8;
  accumulation 4; một epoch; seed 42; AdamW 2e-5, weight decay 0,01;
  warmup 10%; FP16. Không lemmatize, che chuỗi CVSS theo policy baseline.
- RTX 3050 Laptop 6 GB; Python 3.14.3; Torch 2.13.0+cu130; Transformers 4.57.1.
- Smoke: 20 batch / 160 mẫu train, 3,863 giây; save/load khớp.
- Full train: **3.602 batch, 410,490 giây (6,84 phút)**; không có AMP update bị bỏ.
- Peak allocation PyTorch: 1.650.975.232 byte (~1,54 GiB). Đây không phải toàn bộ
  bộ nhớ GPU của hệ điều hành/driver.
- Toàn bộ full run: **2.103,306 giây (~35,06 phút)**, gồm xác minh, tokenization,
  train, validation/test và lưu file. Không bao gồm cài thư viện/tải checkpoint.

Đã khai báo một epoch trước train, không tìm siêu tham số. Nhánh này thực hiện
sau khi baseline đã có test report; không tuyên bố test còn mù đối với toàn nhóm.
Không dùng điểm test để thay config, chọn checkpoint hoặc chạy lại thí nghiệm.

Khóa model lúc `2026-10-17T06:31:54.882520Z`; test bắt đầu
`2026-10-17T06:31:55.424625Z`, hoàn tất `2026-10-17T06:55:17.437469Z`.
SHA-256 model: `2c1cf7b36c2f28127a767fd797221ec85864f1ac79174fe79afb412faff22507`.
Giờ trên là UTC; giờ Việt Nam cộng 7.

## Kết quả

| Phạm vi | Tập | N | Mean macro-F1 8 metric | Exact vector | Base MAE |
|---|---|---:|---:|---:|---:|
| Toàn ML | Validation | 19.606 | 0,734138 | 33,6887% | 1,185744 |
| Toàn ML | Test | 18.821 | 0,731746 | 33,0535% | 1,133882 |
| Trong scope | Validation | 69 | 0,527830 | 15,9420% | 1,659420 |
| Trong scope | Test | 108 | 0,619580 | 27,7778% | 1,509259 |

Không có prediction invalid; đủ **38.427 dòng** cho validation + test.
F1/accuracy từng metric, từng lớp/support, confusion matrix, coverage và RMSE:
`reports/p2_distilbert_results.json`. Không gọi macro-F1 là accuracy chung.

TF-IDF tốt hơn trong lần chạy này về mean macro-F1 và exact vector ở cả hai
phạm vi. Trên 108 CVE Web test, DistilBERT có Base MAE thấp hơn (1,5093 so với
1,7509) dù exact vector thấp hơn: sai tám thành phần không đồng nghĩa sai điểm
Base theo cùng một mức. Không suy ra ưu thế tổng quát của kiến trúc từ một seed,
một epoch và cohort nhỏ; cũng không kết luận model sâu luôn kém baseline.

Giữ TF-IDF là baseline chính đã được chọn và tái lập trước đó; DistilBERT là
thí nghiệm bổ sung. Không dùng kết quả của mô hình nào thay CVSS quan sát trong
thí nghiệm ranking chính của Phase 3.

## Truncation và giới hạn bảo mật

| Tập | Số mô tả bị cắt ở 256 token | Tổng |
|---|---:|---:|
| Train | 451 | 28.815 |
| Validation | 1.222 | 19.606 |
| Test | 1.125 | 18.821 |

Thông tin quyền, thao tác người dùng hoặc tác động có thể ở phần văn bản bị cắt.
Đây là giới hạn cần báo, chưa chứng minh là nguyên nhân từng lỗi. Dataset hiện
tại không phải snapshot lịch sử tại ngày published; near-duplicate có giới hạn
recall; sản phẩm giao nhau giữa split. Scope validation/test chỉ có Web, không
có mobile: không tuyên bố hiệu năng trên mobile từ bảng này.

Đã xuất thêm 10 lỗi validation theo ID vào
`reports/p2_distilbert_validation_errors.csv`. Review 13 ca của N2 cho baseline
vẫn được giữ riêng, không ghi thay xác nhận N2 đã review model DistilBERT mới.

## Bằng chứng và cách chạy

- `reports/p2_distilbert_environment.json`: CUDA, dependencies, revision và hash pretrained.
- `reports/p2_distilbert_smoke.json`: số đo gate trên train.
- `reports/p2_distilbert_lock.json`: khóa trước test.
- `data/processed/p2_distilbert_20261017/`: model/tokenizer, prediction, metric,
  declaration, log từng 100 batch và manifest nguyên byte.
- `notebooks/02_model_eval_n1.ipynb`: đã thực thi cả bảng baseline và DistilBERT;
  chỉ đọc metric đã khóa, không train hoặc đánh giá lại test.
- Bộ test sau thêm DistilBERT: **178/178 đạt**; kiểm gradient encoder/tám head,
  loss/trọng số, contract và lưu/nạp safetensors offline.
- [Hướng dẫn kỹ thuật và lệnh](../docs/phase-2-distilbert-run.md).
