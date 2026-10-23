# Bàn giao Phase 4 Người 3 — 23/10/2026

Phần triển khai demo local đã hoàn thiện. Bản này bổ sung nhận tài liệu N2,
ghép thao tác, kiểm nội dung theo lời thoại, hướng dẫn máy nhận và gói dự phòng.
Không xác nhận thay N1/N2 hoặc gán thời gian chạy máy tính thành diễn tập người thật.

## Đã xử lý thêm sau lần rà soát

- Nhận nguyên bản `reports/demo-script-security.md`, `docs/demo-qa.md` và báo cáo
  N2 từ commit `43ce98028a817eff7643581a26e48cd9fd233408`. Hash trong
  [receipt nhận N2](../docs/handoffs/p4-n2-received-by-n3-20261023.json).
  Lần rà trước chỉ kiểm checkout nên chưa thấy tài liệu trên remote branch;
  nay đã có bản local. Báo cáo N2 vẫn giữ nguyên trạng thái chưa duyệt demo N3.
- Ghép notebook với các ví dụ N2: CVE-2023-23752, PgHero/ADMIN-01 và API-02,
  Discourse/API-01, MOB-02 và AI validation CVE-2023-38709. Context rank/sensitivity
  đọc trực tiếp artifact đã xác minh, không tính lại policy.
- [Script N3](demo-script-n3.md) chỉ rõ cell, lời dẫn và câu nói phù hợp live/saved;
  có phiếu ghi thời lượng thực tế đang trống vì chưa diễn tập.
- [Hướng dẫn máy nhận](../docs/demo-receiver-n3.md) có đúng lệnh, input, expected,
  lỗi và fallback; là bản N3 để N1 tiếp nhận, chưa gọi là runbook N1 đã duyệt.
- Sửa CLI in thiếu chuỗi trong danh sách (bao gồm giả định asset); giữ prediction
  saved nếu model bị mất sau load; ID AI ngoài cohort trả thông báo thay traceback.
- Runner ghi trạng thái Git thực và hash code; không hard-code working tree dirty.
- Gói fallback chứa HTML độc lập, notebook output, 7 PNG, CSV, lời thoại và Q&A.
  Không chứa model, `.env`, API key hoặc dữ liệu Phase 1/2 đầy đủ; xem receipt gói.

## Kiểm kỹ thuật

[Kiểm nội dung N3](p4_n3_content_checks.json): **13/13 đạt**, socket bị chặn,
224 file input không đổi. Đây là self-check theo bản N2, không phải chữ ký N2.
Kiểm count/rank/missing/mobile/AI; PgHero rank 2/1/8/2, Discourse Base/Env/queue
8.1/8.8/2; AI quan sát/dự đoán 7.3/9.1, validation 69/test 108.

Kết quả unit/smoke mới: **29 tests OK**, [log](p4_demo_delivery_tests.log),
[lệnh và exit code](p4_demo_delivery_test_result.json). Notebook giữ 7 cell/7 PNG;
thời gian/load/code hashes/mode ở [execution](p4_demo_execution.json).
Log 85 tests trước đó vẫn giữ làm bằng chứng lịch sử, không gán thành lần chạy mới.

## Git và tái chạy

Đã tạo branch `feat/p4-demo`, commit triển khai
`d09b752cae512872c5336ebac621452c8016428b`. Chỉ commit file của demo và tài liệu N2
nhận nguyên bản; giữ thay đổi có sẵn khác ngoài commit. Repo chưa cấu hình danh tính
Git nên commit dùng tác giả Codex, không đổi cấu hình Git toàn máy. Trạng thái
push/PR theo receipt cuối; không merge `develop` hoặc `main` thay N1.

Đã clone sạch commit trên vào `data/processed/p4_n3_clean_20261023`, dùng cùng
Python/venv và input verified của máy N3. **6 lệnh đạt**, checkout sạch trước/sau:
runner live/saved/no-AI đều 7 cell/7 PNG, hai CLI case/AI và 26 fixture tests.
Bằng chứng [clean checkout](p4_n3_clean_checkout.json),
[live](p4_n3_clean_live.json), [saved](p4_n3_clean_saved.json),
[no AI](p4_n3_clean_no_ai.json). Đây không phải máy vật lý thứ hai, môi trường
dependency cài mới hoặc runbook N1 đã duyệt.

Gói fallback **2.754.860 bytes**, **55 file**, SHA-256
`097176740d0c15aa26740db9395694b238f1b9bfc2410c203acdc2f8f6b85ee8`.
Đã mở ZIP, kiểm lại toàn bộ hash/bytes và parse HTML: 7 ảnh inline,
không script/stylesheet bên ngoài. Xem [receipt](p4_demo_fallback_receipt.json).
Đây là kiểm cấu trúc HTML và dữ liệu, không giả là screenshot trình duyệt.

## Còn cần hành động thật của nhóm

Người dùng xác nhận chỉ có handoff Phase 3, chưa có bằng chứng ngoài repo cho các mục sau:

| Mục | Ai hoàn tất | Bằng chứng cần nhận |
|---|---|---|
| Duyệt nội dung màn hình | N2 | Case/expected/actual, version/commit, feedback và kết luận |
| Runbook tích hợp chính thức | N1 | Runbook đã chốt; N3 chạy lại theo bản đó |
| Diễn tập khoảng 6 phút | Người trình bày/nhóm | Ngày/người nói, thời gian từng đoạn/tổng, mode và lỗi |

Không tự đánh dấu ba mục này pass. Toàn bộ phần code/artifact/hướng dẫn của N3
đã chuẩn bị để thực hiện chúng mà không thêm tính năng hoặc đổi snapshot.
