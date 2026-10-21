# Kiểm tra/tái tạo Phase 3 trên máy N1 — 21/10/2026

N2 được tích hợp từ `59c86b5`, N3 từ `ade5a28`. Không có thay đổi người dùng khác,
ngoại trừ file untracked `a` được giữ nguyên. Không force push hoặc sửa release v1.

## Lệnh thực chạy và kết quả

```powershell
.\.venv\Scripts\python.exe -m src.analysis.compare_rankings --output data/processed/p3_n2/rankings.csv
.\.venv\Scripts\python.exe -m src.analysis.ranking_metrics --rankings data/processed/p3_n2/rankings.csv --config config/phase3.yaml --output-dir data/processed/p3_n2
.\.venv\Scripts\python.exe -m src.analysis.context_priority --master data/processed/phase1_v1_20261010/cves.parquet --mapping config/phase3_mapping.yaml --inventory config/assets.yaml --config config/phase3.yaml --output-dir data/processed/p3_n2
.\.venv\Scripts\python.exe -m scripts.check_environmental_first --output data/processed/p3_n2/environmental_first_check.json
.\.venv\Scripts\python.exe -m scripts.package_phase3_context --source-dir data/processed/p3_n2 --output data/processed/p3_n1_context_reproduced_20261021.zip
.\.venv\Scripts\python.exe -m src.analysis.plots --rankings data/processed/p3_n2/rankings.csv --output-dir reports/figures/phase3 --tables-dir data/processed/p3_n3 --config config/phase3_plots_n1.yaml --n2-dir data/processed/p3_n1_context_verified_20261021/p3_n2 --context-dir data/processed/p3_n1_context_verified_20261021/p3_n2 --context-contract data/processed/p3_n1_context_verified_20261021/docs/phase-3-artifact-contract.md --context-schema p3-context-artifacts-v1 --context-version phase3-context-v2 --queue-policy-version context-v1
.\.venv\Scripts\python.exe -m src.analysis.prediction_rank_impact --tfidf data/processed/p2_n1_reproduction_20261017/data/processed/predictions.csv --distilbert data/processed/p2_distilbert_20261017/predictions.csv
.\.venv\Scripts\python.exe scripts/check_phase3_environmental_n3.py --scores data/processed/p3_n2/environmental_scores.csv --context-version phase3-context-v2
.\.venv\Scripts\python.exe scripts/execute_phase3_notebook.py
.\.venv\Scripts\python.exe scripts/verify_phase3_integration.py
```

Lệnh package chạy khi tracked working tree sạch sau merge, trước sửa tích hợp.
Đã giải nén ZIP vào staging `data/processed/p3_n1_context_verified_20261021`.
Hash ZIP tái tạo `c458581e82d4771adb4a22e97fef948ca056e5ca190f467b9f6e6e6c72c0a231`;
68.580byte. Đây không phải ZIP gốc N2 r2 68.133byte.
Oracle lần chạy này thực tế21/10; script gốc ghi cứng19/10 trong JSON lịch sử,
đã sửa code để những lần sau ghi ngày UTC thực. Không sửa checksum gói lịch sử.

## Kiểm thử

Lần đầu full suite lỗi import matplotlib do N1 chưa cài dependency của N3.
Đã cài `requirements-analysis.txt`, pip check OK. Full suite sau đó253test/42,797s,
OK skipped4. Sau sửa import Git và skip rõ fixture thiếu:29test/2,908s,OK skipped3.
Các test skipped là đường dẫn received/r1 trên máy N3; đã chạy thật pipeline v2,
Decimal crosscheck9,8 và verifier độc lập trên output mới, không chỉ dựa vào test giả lập.

`scripts/verify_phase3_integration.py` kiểm ranking hash, ID nguồn, tau-b đếm cặp,
từng Jaccard/recall,150 top50 ID, đủ15 queue/mapping,8 patch,2 client review/nullrank,
đúng context plot, hashes input/output/code. Kết quả `p3_integration_verification.json`.

N1 đã xem7PNG: scatter,2 trangtop50,overlap,recall,context,queue. Tất cả đọc được,
context8cặp/queue15cặp đã cập nhật; không còn hình6cặp của r1. Các CVE bị chồng điểm
trên scatter được chú thích, không giả số điểm phân biệt=396. So alltop50 bằng verifier.
Notebook chạy6cell/2,415s, không train/evaluate lại. Không đo thời gian họp/diễn tập giả.

## Kết luận review

Chấp nhận logic chính N2/N3 sau đồng bộ version. Không nhận xét “mọi case đã được
kiểm trên hệ thống thật”: chỉ đối chiếu source/logic, unit tests và artifact snapshot.
Case N1: [PgHero](../docs/cases/p3-web-n1.md); case N3:
[flutter_downloader](../docs/cases/p3-mobile-n3.md). Nguồn vendor trong các case
được tách khỏi giả định inventory. Đọc lại PgHero#439, Discourse reset-link và range/CSP
conflict để xác minh không tự đổi CVSS hoặc đánh affected khi còn điều kiện thiếu.

Tổng hợp cuối: [nghiệm thu](../docs/phase-3-completion.md). Tái chạy trên máy nhận
và demo6phút là nhiệm vụ Phase4, chưa được đánh dấu hoàn thành tại đây.
