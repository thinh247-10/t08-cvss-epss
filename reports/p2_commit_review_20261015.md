# Kiểm tra commit Phase 2 của N2/N3 — 2026-10-15

## Kết luận

N3 đã có phần baseline/evaluation đáng kể; bộ test chạy đạt trên máy N1. Chưa
xác nhận bàn giao model hoàn chỉnh do thiếu artifact ngoài Git và lỗi checksum
text khi nhận code trên Windows. Chưa merge hoặc sửa code N3 trong lần review này.
N2 chưa có commit Phase 2 trên remote được kiểm tra, nên chưa thể đánh giá phần mới.

## 1. Phạm vi và commit

- Fetch `origin` thành công và đọc danh sách `ls-remote --heads origin`.
- `develop`: `fb4794b`.
- N3: `origin/feat/p2-nlp-baseline`, commit
  `a5c0c16d862059819c2b10f973e91827796ac30e` (hoangngocanh06).
- N2: chưa thấy `feat/p2-cvss-scorer` hoặc branch Phase 2 khác. Branch
  `feat/p1-scope-assets` vẫn ở `1a03bf8` ngày 07/10; đây là công việc Phase 1.
  Không kết luận N2 chưa làm: có thể mới commit local hoặc push sang repo khác.
- Review N3 tại bản xuất riêng `data/processed/reviews/n3_a5c0c16/`;
  giữ nguyên branch `develop`, dataset v1 và file `a`.

## 2. Phát hiện cần xử lý trước bàn giao hoàn chỉnh

### R1 — P2: checksum text phụ thuộc LF/CRLF, verifier có thể chặn gói hợp lệ

Vị trí: `src/model/run_phase2.py:171` đưa `requirements-model.txt` vào manifest;
`src/model/verify_handoff.py:143` kiểm kích thước và SHA-256 theo byte tuyệt đối.
Repo hiện không có quy tắc giữ line ending cho file này, máy N1 dùng
`core.autocrlf=true`. Bản nhận qua Git có CRLF trong khi manifest ghi hash LF.

| Kiểm tra `requirements-model.txt` | Giá trị |
|---|---|
| Manifest | 324 byte |
| Bản xuất qua Git trên N1 | 334 byte |
| SHA-256 mong đợi | `5b15065d96dbce624ec050740e760de662b0ddd75b401ccda1ca54ef9e7126bc` |
| SHA-256 thực nhận | `f743f09fb59e2f6d6411ca88c3b6090554d563e275d9dab67f899148d9690e6a` |
| Chuẩn hóa CRLF về LF để chẩn đoán | Khớp hash mong đợi |

Đã dùng chính `verify_handoff` với manifest thử chỉ chứa entry file này, trước
bước load model, tái hiện:

```text
ValueError: Handoff checksum/size mismatch: requirements-model.txt
```

`config/model.yaml` cũng khớp `lock.config_sha256` chỉ khi chuyển về LF. Verifier
handoff hiện không kiểm config này, nhưng `_validate_lock` của workflow có kiểm;
phải bảo toàn config khóa khi bàn giao. Không chạy lại test cuối chỉ để vượt khóa.

Hướng sửa: N3 bảo toàn chính xác byte các file được hash, ví dụ ZIP bàn giao đủ
file/manifest và quy tắc `.gitattributes` phù hợp cho requirements/config LF.
Không áp dụng LF hàng loạt cho các report có hash đã khóa khác line ending.
Không bỏ kiểm hash hoặc sửa hash theo máy nhận để che khác biệt. Thêm test mô phỏng
nhận gói trên Windows và xác minh toàn bộ artifact sau khi sửa cách đóng gói.
Không cần train lại nếu model/config thí nghiệm không thay đổi.

### R2 — Chưa đủ artifact để tái chạy trên máy N1

Hai file manifest tham chiếu chưa có trong bản Git hoặc tại đường dẫn bàn giao
chuẩn của workspace khi kiểm:

- `models/baseline.joblib` — N3 báo 7.474.244 byte,
  SHA-256 `9b55da5616f725ed400824564400059b1b9fb07cee8db6ff13da7adefb087299`.
- `data/processed/predictions.csv` — N3 báo 76.854 dòng.

Đây là file ignored cần gửi riêng, không phải yêu cầu force-add lên Git. N3 nên
gửi ZIP đủ mọi file trong manifest, kèm `models/phase2_lock.json` và config đã khóa.
Chưa có hai artifact trên thì chưa xác nhận tái tạo prediction hay test metrics
trên máy N1. Không dùng báo cáo local reproduction của N3 thay bằng chứng máy thứ hai.

## 3. Những phần đã kiểm đạt

### Code và kiểm thử

- Feature thực tế là description; TF-IDF và tám classifier chỉ fit train.
- Chọn hai giá trị C trên validation; test đi qua bước khóa artifact/config/dataset.
- Dùng scorer chung; output có version, split, validity/error.
- Evaluator join theo ID, kiểm ID/version/split, báo toàn miền và scoped riêng,
  giữ support 0, denominator và coverage/lỗi.
- Dummy và fallback một lớp có triển khai; save/load và inference có test.
- Cài đúng `requirements-model.txt` vào `.venv` N1; Python 3.14.3 khác Python
  3.13.16 của N3, chưa coi là tái tạo nguyên môi trường.
- Chạy tại bản review riêng bằng Python `.venv` N1:
  `python -m unittest discover -s tests -q` → **161 test, OK, 12,944 giây**.
  Lần đầu trong sandbox bị quyền thư mục tạm/dependency chưa sẵn sàng; đã chạy
  lại ngoài sandbox sau khi dependency khả dụng. Không ghi lỗi môi trường đó thành lỗi N3.
- Không chạy `run_phase2 select/final`, không retrain hoặc mở thêm vòng tuning test.

### Nhất quán dữ liệu và báo cáo

- `validation_errors.csv`: 12.083 dòng, 12.083 ID duy nhất, tất cả thuộc validation v1.
- Description, tám nhãn nguồn, vector, Base Score, split và dataset version khớp
  dữ liệu v1 ở toàn bộ 12.083 dòng; mỗi dòng có ít nhất một nhãn dự đoán khác nguồn.
- Ba file có trong Git (`model_selection.json`, `validation_errors_n2.csv`,
  `model_metrics.json`) khớp kích thước/hash trong manifest ở bản kiểm tra.
- Notebook có 12 code cell đã lưu execution count, không có output lỗi. Đây là
  kiểm output đã lưu; chưa chạy lại notebook với artifact của N3.
- Model card công bố đúng giới hạn: mobile chỉ có train, nguồn là snapshot hiện tại,
  có product overlap, gần trùng có thể bỏ sót, DistilBERT `not_run`.

## 4. Số đo N3 báo cáo — chưa tái tạo từ model trên N1

| Model / test cohort | n | Mean macro-F1 | Exact vector | Base MAE |
|---|---:|---:|---:|---:|
| Dummy / toàn miền | 18.821 | 0,298403 | 0,102279 | 2,900553 |
| TF-IDF / toàn miền | 18.821 | 0,752142 | 0,386536 | 1,078030 |
| TF-IDF / scoped Web | 108 | 0,654889 | 0,351852 | 1,750926 |

Các số đọc từ `reports/model_metrics.json` trên commit N3. Không diễn đạt
macro-F1 0,7521 thành “đúng 75% vector”; exact vector toàn miền khoảng 38,65%.

Đối chiếu tài liệu: [trang viện của tác giả](https://www.it.pt/Publications/PaperJournal/33219)
xác nhận tên bài Costa et al., DOI và hướng nghiên cứu DistilBERT; liên kết tới
[repository tác giả](https://github.com/Joana-Cabral/CVSS_Prediction) là đúng.
Lần review này chưa xác minh lại toàn bộ bảng số liệu bài gốc trong model card.

## 5. Việc cần giao lại

1. N2 cung cấp branch/link commit Phase 2 đã push; nếu chỉ commit local thì push branch.
2. N3 gửi artifact ngoài Git và sửa vấn đề line ending/checksum trong gói bàn giao.
3. N1 chạy verifier với model thật, ghi rõ chênh lệch Python/runtime và kết quả.
4. N2 nhận prediction validation để làm phần phân tích bảo mật theo kế hoạch.
5. Chốt D05 trước khi làm DistilBERT; chưa đánh dấu cả Phase 2 hoàn thành.

Review này không yêu cầu thêm vòng review độc lập và không tự gửi tin nhắn cho thành viên.
