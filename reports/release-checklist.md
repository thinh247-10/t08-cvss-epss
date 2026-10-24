# Checklist Phase 4 — tích hợp 24/10/2026

**Chưa đóng Phase4: còn xác nhận runbook máy nhận và diễn tập người thật.**

| Hạng mục | Owner | Trạng thái / bằng chứng |
|---|---|---|
| Nhận Phase1/2/3 đúng phiên bản/hash | N1/N2/N3 | Đã có receipt và verifier; loader kiểm lại trước đọc |
| Tích hợp N2/N3 | N1 | N3 4c15746, N2 55fa749; merge872f79b |
| Lời thoại, Q&A, playbook | N2 | Đã có; p4_security_acceptance mục5 xác nhận kiểm demo |
| CLI/notebook/AI và dự phòng | N3 | Đã chạy trên N3/N2/N1; observed và predicted tách riêng |
| Paths/runbook/script chung | N1 | config/demo.yaml, docs/runbook.md, reports/demo-script.md |
| Chạy ba mode sau tích hợp | N1 | Xem p4_n1_live/saved/no-ai.json và p4_reproduction.md |
| Test sau tích hợp | N1 | Xem p4_n1_tests.txt; test smoke default có thể skip do path khác, notebook dùng config thật |
| Máy nhận chạy demo | N2 | Đã có JSON thực chạy, Python3.13.12 |
| Máy nhận thử runbook cuối | N2 hoặc N3 | PENDING: thử các lệnh runbook/launcher mới, gửi command và output |
| Diễn tập khoảng6phút | Cả nhóm | PENDING: nói và thao tác thật, đo giờ, ghi lỗi và thử fallback |
| Gói/model/dữ liệu thay đổi | N1 | Không thay release, không train lại, không cần gửi lại Phase1/2/3 |

Các log và báo cáo ngày21–23/10 giữ nguyên làm lịch sử. Trạng thái “chưa push”
trong báo cáo N3 cũ đã được thay thế bởi commit4c15746 và merge872f79b.
N2 content acceptance đã có ở55fa749; không còn chờ N2 giao code/nội dung.

## Nhóm làm tiếp

1. Pull develop sau khi N1 push; giữ dữ liệu đã nhận.
2. N2/N3 sửa ba path trong YAML cho đúng máy, chạy summary và ba mode theo runbook.
3. Ghi commit, phiên bản Python, output/lỗi; không gửi `.env` hoặc `.venv`.
4. Chia lời nói theo script chung, diễn tập đủ sáu đoạn. Ghi giờ thực tế vào script.
5. Khi hai mục pending có bằng chứng, cập nhật checklist rồi chốt Phase4.

Chưa đánh dấu Phase4 hoàn thành hoặc nghiệm thu buổi diễn tập thay nhóm.
