# Phase 4 — tổng hợp chạy lại

Ngày tích hợp 24/10/2026. N3 `4c15746`, N2 `55fa749`, merge `872f79b`.
Dataset `t08-v1.0-20261010`, context `phase3-context-v2`, policy `context-v1`.

## Máy nhận N2

Bằng chứng do N2 bàn giao, đã đọc đối chiếu; N1 không tự chạy trên máy N2:
[nghiệm thu mục 5](p4_security_acceptance.md),
[19 kiểm tra](p4_n2_demo_checks_20261023.json),
[live](p4_n2_demo_live_20261023.json),
[saved](p4_n2_demo_saved_20261023.json),
[no-AI](p4_n2_demo_no_ai_20261023.json).
Python3.13.12/Windows11, 29 test đạt theo báo cáo. Ba mode đều 7cell/7PNG;
live13.8401s, saved6.3415s, no-AI2.7655s. Socket guard chặn DNS;
không tuyên bố card mạng bị tắt. Live/saved giữ224file, no-AI119file.
Code được xuất từ N3, runner ghi commit unavailable đúng với snapshot archive.

## Máy N1 sau tích hợp

Chạy bằng `.venv/Scripts/python.exe scripts/run_demo.py --mode <live|saved|no-ai>`.
Đường dẫn thật nằm trong `config/demo.yaml`; output không ghi đè release.
JSON mới: `p4_n1_live.json`, `p4_n1_saved.json`, `p4_n1_no-ai.json` trong reports.
Các log ghi phiên bản Python/dependencies, code hash, model hash, số cell/hình,
giây chạy, guard và hash input. Commit phản ánh HEAD lúc chạy; launcher/runbook
có thể chưa commit lúc ghi log, không coi đây là clean checkout của commit cuối.

Model TF-IDF SHA256:
`c68d530ff7818f5d469da647246e787517d9d213b59286d9a6f67dd647d05265`.
Phase3 ZIP SHA256:
`df03b51e7a9572d8ac055f40e6343a3fc827efd286a2e7cb2c862a2776d9cd0a`.
AI validation CVE-2023-38709 phải mode live và predicted9.1/observed7.3;
mobile CVE-2023-41387 giữ review/null. Không chạy lại training.

## Giới hạn bằng chứng

Kết quả N1: live32.7395s, saved2.6855s, no-AI1.1407s; cả ba pass7cell/7PNG,
guard_verified=true, input224/224/119file không đổi. Test tích hợp65 mục:
62 đạt,3 smoke mặc định skip; các mode dữ liệu thật kiểm bằng launcher.
Xem [log tóm tắt lệnh đã chạy](p4_n1_tests.txt).

N2 đã chạy demo trên máy nhận trước khi runbook mới được viết. Cần xác nhận dùng
runbook cuối; không giả log cũ chứng minh lệnh launcher mới đã chạy trên máy khác.
Thời gian thực thi không thay thế diễn tập trình bày. Các trường pending do runner
N3 ghi cố định là lịch sử của runner; trạng thái hiện hành ở release-checklist.
