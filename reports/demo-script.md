# Script chung — demo dự kiến 6 phút

Tích hợp 24/10/2026 từ [lời thoại N2](demo-script-security.md) và
[thao tác N3](demo-script-n3.md). Đây là lịch dự kiến, chưa có giờ diễn tập thật.
Chuẩn bị theo [runbook](../docs/runbook.md), mở notebook đã chạy trong
`data/processed/p4_demo_n1/live.ipynb`. Người điều khiển N1; N2 giải thích bảo mật;
N3 giải thích AI. Có thể một người trình bày toàn bộ nếu nhóm thống nhất.

| Thời gian | Thao tác | Ý cần nói |
|---|---|---|
| 0:00–0:45 | Summary/scatter, code cell 2 | 396 CVE, 3 KEV; snapshot cố định, inventory giả định. EPSS ngày 29/09, KEV phát hành 30/09, tải 01/10 UTC. |
| 0:45–2:00 | Hai trang top-50, cell 3 | CVE-2023-23752 Base 5.3 nhưng EPSS cao và có KEV. CVSS/EPSS top-50 chung 10; Jaccard 0.111. KEV recall 1/3 so với 3/3 chỉ là đối chiếu snapshot nhỏ. |
| 2:00–3:30 | Web, cell 4 | PgHero ADMIN-01 Base 7.5→Env9.3; queue8→sensitivity2 trên cùng 8 cặp. API-02 thiếu product/version vẫn review. Discourse API-01 Base8.1→Env8.8. |
| 3:30–4:30 | Mobile, cell 5 | MOB-02 Base9.1/Env9.8 vẫn review, rank N/A vì client chưa có policy phù hợp; không có nghĩa bỏ qua vá. |
| 4:30–5:20 | AI, cell 6 | CVE-2023-38709 validation: observed7.3 khác predicted9.1. Hiện 8 metric/vector riêng. TF-IDF model N1 đã khóa. Không train hoặc điều chỉnh theo test. |
| 5:20–6:00 | Queue/kết luận, cell 7 | 15 cặp tài sản, 8 patch/7 review. Xác minh applicability, bối cảnh và tín hiệu khai thác trước quyết định; CVSS cao chưa đủ để vá trước. |

Khi chạy live dùng `scripts/run_demo.py --cli predict CVE-2023-38709 --live`.
Chỉ nói “vừa dự đoán” sau khi lệnh trả mode live. Mở notebook/HTML cũ hoặc saved
thì nói “kết quả đã lưu”. Nếu lỗi live, dùng saved đã chuẩn bị, không đổi model.
Không lấy thời gian chạy notebook vài giây làm thời lượng diễn tập.
Q&A: [15 câu hỏi](../docs/demo-qa.md). Không-KEV không chứng minh chưa từng bị khai thác;
KEV-first dùng trực tiếp KEV nên recall không phải đánh giá độc lập của policy đó.

## Ghi sau diễn tập

- Ngày/commit/máy/người trình bày: chưa thực hiện.
- Thời gian bắt đầu/kết thúc/tổng: chưa đo.
- Lỗi chuyển màn hình, giải thích hoặc dự phòng: chưa ghi nhận.
- Điều chỉnh và lần chạy lại: chờ nhóm bổ sung dữ kiện thật.
