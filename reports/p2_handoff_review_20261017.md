# Kiểm tra bàn giao Phase 2 — 2026-10-17

## Kết luận

**N2 đạt phần việc Phase 2 đã bàn giao, có thể tích hợp.** Không phát hiện lỗi chặn
trong ranking/scorer qua kiểm code, dữ liệu thật và test. N3 vẫn ở commit đã review
ngày 15/10; chưa có bản sửa vấn đề checksum text hoặc artifact model tại workspace N1.
Chưa đánh dấu toàn bộ Phase 2 hoàn thành.

Lần này chỉ kiểm tra và ghi nhận: chưa merge branch, chưa commit/push, chưa sửa code
hai bạn, chưa train lại hoặc chạy lại test cuối của mô hình.

## 1. Nguồn đã nhận

- Người dùng gửi `Downloads/p2_n2_handoff.md` và `Downloads/rankings.csv`.
- Đã lưu nguyên byte tại `data/raw/handoffs/n2_phase2_received_20261017/`.
- Biên nhận: [n2-phase2-receipt-20261017.json](../docs/handoffs/n2-phase2-receipt-20261017.json).
- Sau fetch, N2: `origin/feat/p2-cvss-scorer`, đầu branch `add095a`.
- N3: `origin/feat/p2-nlp-baseline`, đầu branch vẫn là `a5c0c16`.
- N2 ghi PR #6 base develop trong file bàn giao. Review này xác minh code qua
  branch Git; không coi mô tả trạng thái PR ngày 15/10 là kiểm UI GitHub ngày 17/10.

## 2. Ranking đã xác minh độc lập

| Kiểm tra | Kết quả |
|---|---|
| File nhận | 48.438 byte |
| SHA-256 | `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67` |
| ID / số dòng | 396 duy nhất, trùng chính xác tập ID ranking cohort v1 |
| KEV | 3; cờ boolean khớp nguồn |
| CVSS/EPSS | Khớp giá trị nguồn; đối chiếu số thực với sai số tối đa 1e-12 |
| Version/cohort | `t08-v1.0-20261010` / `t08-v1.0-20261010:ranking` |
| EPSS date | `2026-09-29` trên toàn bộ dòng |
| Policy | `cvss-epss-kev-first-v1` |
| Ba cột rank | Mỗi cột đủ vị trí 1–396, đúng thứ tự/tie-break của contract |

Đã tự sort lại từ `ranking_cohort.parquet` theo ba chính sách, so từng ID/rank;
không chỉ kiểm bảng có đủ số dòng. Đã chạy CLI N2 với input/metadata v1 và output
riêng `data/processed/reviews/p2_combined_20261017/rankings_reproduced.csv`.
File tái tạo **giống nguyên byte và SHA-256** bản N2 gửi.

## 3. Scorer, case và lỗi validation

- N2 tái dùng `calculate_base_score`, không tạo scorer thứ hai; test bổ sung
  Scope U/C, PR N/L/H, zero impact, Roundup và vector invalid.
- Bảng năm case trong `docs/analysis-results.md` khớp Base/EPSS/cả ba rank của
  artifact. Năm case thuộc train, không KEV trong snapshot; không giả làm mẫu validation.
- Báo cáo lỗi N2 có 13 CVE duy nhất, đều thuộc validation v1 và bảng lỗi N3.
  Đối chiếu nhãn nguồn với gói v1 không sai khác; các prediction sai phủ cả tám metric.
- Có đúng hai CVE được scope v1 nhận Web trong 13 case. Không nhận mobile train
  làm lỗi validation mobile. N2 phân biệt label nguồn với suy luận nghiệp vụ,
  không tự sửa ground truth hoặc kết luận nguyên nhân model khi chưa có attribution.
- Các case nêu tài sản giả định và điều kiện affected; client giữ `review_required`.
  Environmental và hàng đợi theo tài sản vẫn là việc Phase 3, chưa bị trình bày như đã chạy.
- Lần này đối chiếu code/artifact và tính nhất quán báo cáo; chưa xác minh lại mọi
  advisory bên ngoài hoặc tái hiện lỗ hổng thực tế.

## 4. Kiểm tích hợp code hai bạn

N2 thay 8 file, N3 thay 23 file so với develop; không có file thay đổi giao nhau.
Đã tạo bản kết hợp riêng tại `data/processed/reviews/p2_combined_20261017/`, dùng
code N3 rồi thêm đúng 8 file N2. Đây là kiểm tích hợp nội dung, chưa phải Git merge.

Tại bản kết hợp, dùng `.venv` N1 (Python 3.14.3, dependencies N3 đã cài):

```text
python -m unittest discover -s tests -q
Ran 175 tests in 38.446s
OK
```

Tất cả test đạt, gồm scorer/ranking N2, baseline/evaluator N3 và kiểm tra cũ.
Đây là unit test/smoke trên fixture, không phải tái chạy model trained của N3.

## 5. Việc còn lại của cả nhóm

1. N2: phần bàn giao đã được N1 tiếp nhận kỹ thuật qua lần kiểm này. N3 cần tổng
   hợp `reports/p2_validation_security_review.md` vào model card; chưa ghi thay xác nhận N3.
2. N3: commit vẫn `a5c0c16`, vấn đề LF/CRLF trong [review 15/10](p2_commit_review_20261015.md)
   còn áp dụng. Sửa cách đóng gói/bảo toàn byte file hash trước khi gửi gói hoàn chỉnh.
3. Nhận `models/baseline.joblib`, `data/processed/predictions.csv` và mọi file được
   manifest tham chiếu, kèm config/lock gốc. Các artifact này chưa có tại đường dẫn
   chuẩn của workspace N1. Không force-add chúng lên Git.
4. N1 tái chạy verifier/inference khi đã nhận gói, ghi kết quả thật và chênh lệch
   Python/runtime. Không dùng 175 test đạt thay cho bước chạy model thật này.
5. Chốt D05/DistilBERT và trạng thái cuối; chuẩn bị Phase 3 từ ranking đã xác minh.

Không cần N2 tải lại API, làm lại ranking hoặc viết lại scorer cho lần bàn giao này.
