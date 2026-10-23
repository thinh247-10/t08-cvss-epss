Demo Phase 4 cần mở đúng release trên máy nhận mà không gọi API hoặc train.
Thay đổi này thêm loader/CLI chỉ đọc, notebook đã chạy và runner chặn socket;
giữ context-v2, nullable, client review và tách CVSS quan sát khỏi AI.

Ví dụ validation CVE-2023-38709 hiển thị Base quan sát 7.3 và TF-IDF dự đoán 9.1,
đủ tám metric/vector/model/mode; thiếu AI vẫn mở summary, bối cảnh và hình.
Lời thoại/Q&A N2 được nhận nguyên bản từ 43ce980, ghép thao tác và case vào notebook.
Có hướng dẫn máy nhận N3 và ZIP dự phòng HTML/PNG/CSV có receipt, không chứa model/data lớn/secret.

Validation: 29 tests demo pass; 13 đối chiếu nội dung theo N2 pass; clone sạch
commit triển khai d09b752 chạy live/saved/no-AI, 7 cell/7 PNG mỗi mode;
26 fixture tests và hai CLI flow pass. Gói fallback kiểm 55 file và 7 ảnh inline.
Log: reports/p4_n3_delivery.md, reports/p4_n3_clean_checkout.json.

Chưa có xác nhận N2 đã xem màn hình, runbook N1 đã chốt, hoặc diễn tập người thật
6 phút. Đây là PR bàn giao kỹ thuật cho N1/N2, không phải nghiệm thu Phase 4 toàn nhóm.
Không đổi scorer, ranking, split, snapshot, model hoặc merge develop/main.
