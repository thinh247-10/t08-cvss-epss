# Phase 3 — N3: tác động sai số AI lên thứ hạng severity

Phân tích phụ RQ1; không trộn với RQ2 (396 CVE quan sát). Quy tắc được chốt trong module trước khi chạy: validation/test riêng, giao ID ranking–ML; cùng tập có observation và prediction hợp lệ của cả hai model. Base giảm rồi CVE ID tăng; delta=observed_rank−predicted_rank (dương: dự đoán xếp sớm hơn). Tau-b trên điểm gốc, không phải rank đã phá hòa. Chỉ tính Jaccard khi K<N.

K chốt trước chạy: 10, 20, 50. Coverage từng model = prediction hợp lệ / ID giao đủ điều kiện; common coverage = ID có observation và cả hai prediction hợp lệ / ID giao đủ điều kiện. Không bù giá trị thiếu bằng 0. N<2: giữ dòng hợp lệ để truy vết nhưng rank/tau/Jaccard là N/A.

```powershell
.\.venv\Scripts\python.exe -m src.analysis.prediction_rank_impact --help
& C:\Users\LOQ\Desktop\t08-cvss-epss\t08-cvss-epss\.venv\Scripts\python.exe -m src.analysis.prediction_rank_impact --tfidf data/processed/p2_n1_reproduction_20261017/data/processed/predictions.csv --distilbert data/processed/p2_distilbert_20261017/predictions.csv
```

Join audit: `{"ranking_ids": 396, "ml_ids": 67242, "ranking_missing_from_ml": 0, "ranking_missing_from_ml_ids": [], "train_excluded": 219, "heldout_ids": 177}`.

| Split | Model/version | Eligible | Common N | Valid/missing/invalid | Model coverage | Common coverage | Lost to common | Tau-b | J@10 | J@20 | J@50 |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| validation | tfidf-v1-n1-reproduction-20261017 | 69 | 69 | 69/0/0 | 1.000000 | 1.000000 | 0 | 0.237847 | 0.111111 | 0.333333 | 0.639344 |
| validation | distilbert-v1-n1-20261017 | 69 | 69 | 69/0/0 | 1.000000 | 1.000000 | 0 | 0.243516 | 0.111111 | 0.428571 | 0.666667 |
| test | tfidf-v1-n1-reproduction-20261017 | 108 | 108 | 108/0/0 | 1.000000 | 1.000000 | 0 | 0.211954 | 0.333333 | 0.333333 | 0.333333 |
| test | distilbert-v1-n1-20261017 | 108 | 108 | 108/0/0 | 1.000000 | 1.000000 | 0 | 0.243259 | 0.333333 | 0.481481 | 0.449275 |

Chi tiết coverage, miền dữ liệu và lý do N/A:

- validation: invalid observed=0; domain counts={'web': 69, 'mobile': 0}; common IDs được lưu đầy đủ trong JSON.
- validation/tfidf: validity={'valid': 69}; tau N/A reason=None; Jaccard N/A reasons={}; mean absolute rank delta=17.913043.
- validation/distilbert: validity={'valid': 69}; tau N/A reason=None; Jaccard N/A reasons={}; mean absolute rank delta=16.521739.

- test: invalid observed=0; domain counts={'web': 108, 'mobile': 0}; common IDs được lưu đầy đủ trong JSON.
- test/tfidf: validity={'valid': 108}; tau N/A reason=None; Jaccard N/A reasons={}; mean absolute rank delta=28.685185.
- test/distilbert: validity={'valid': 108}; tau N/A reason=None; Jaccard N/A reasons={}; mean absolute rank delta=26.462963.

Coverage và lý do loại từng dòng: [metrics](../data/processed/p3_n3/prediction_rank_metrics.json), [exclusions](../data/processed/p3_n3/prediction_rank_exclusions.csv). [Bảng đối chiếu](../data/processed/p3_n3/predicted_rank_comparison.csv) giữ rank/score/version từng CVE.

Domain counts ở trên được đếm từ ML cohort, không suy diễn nhãn mobile từ backend. Không thêm train để đủ 396. Đây là độ thay đổi thứ tự severity do ước lượng Base; không đo hiệu quả vá, xác suất khai thác hay tác động vận hành. Không chọn model thắng, chỉnh cấu hình từ test, retrain hoặc chạy lại inference. Dùng artifact N1; không tuyên bố byte-identical với model N3 cũ. Ties phụ thuộc ID ở cutoff.

Input/hash/bytes và command thực tế được lưu trong JSON. Counts khác dự kiến (nếu có): []
Nếu số join khác 69/108, xem join audit (ranking không có trong ML, train bị loại) và hash/version đầu vào; không bổ sung ID để ép đạt số dự kiến.

Chỉ dùng score prediction đã lưu; kiểm vector/score là kiểm tính hợp lệ artifact bằng Base scorer hiện có, không gọi src.model.evaluate, train hoặc inference. Dummy bị loại theo model_version chính xác.

| Input | Bytes | SHA-256 |
|---|---:|---|
| data/processed/phase1_v1_20261010/ranking_cohort.parquet | 171785 | `07bdaba5b21e2f21161b1339704e68924d8f4bfa34118b8eb02ec8b51affdfff` |
| data/processed/phase1_v1_20261010/ml_cohort.parquet | 21858636 | `eaa7f845596cc8b1a0ac802a792f2b495006cec87acc7cab28434fcb8905fdb6` |
| data/processed/p2_n1_reproduction_20261017/data/processed/predictions.csv | 12359308 | `6af4021db182ca24421f8f457e881410e272366f0dde5b30b2abacefd0fd95b1` |
| data/processed/p2_distilbert_20261017/predictions.csv | 5757046 | `3fa8e432a9ad84043fd323c3a088f6ec2f5624e97df050af3bc1f393d93c5f86` |
