# Case Web N1 — PgHero CVE-2023-22626 / ADMIN-01

Ngày kiểm nguồn 21/10/2026. Đây là kịch bản inventory giả định, không phải đo hệ thống thật.
[Issue chính thức PgHero #439](https://github.com/ankane/pghero/issues/439) xác nhận
EXPLAIN có thể lộ dữ liệu qua lỗi truy vấn, ảnh hưởng 0.1.1–3.0.1 và sửa ở 3.1.0.
Đọc file máy chủ còn phụ thuộc quyền superuser của database user; không giả định quyền này.

ADMIN-01 dùng PgHero 3.0.1, internal. Mapping affected có điều kiện version;
cần kiểm quyền truy cập dashboard và database. Nguồn vector v1 giữ PR:N dù advisory
nói người dùng PgHero: ghi khác biệt phạm vi, không tự đổi nhãn để hợp bối cảnh.
API-02 không biết product/version nên cùng CVE vẫn needs_review và không có rank.

Trong context-v2, Base 7.5 tăng thành Environmental 9.3 do CR:H (C:H),
modified metrics vẫn X. Base rank 2 → Environmental rank 1 trên cùng 8 cặp patch.
Nhưng policy chính KEV→exposure→Environmental xếp ADMIN-01 sau các cặp internet;
policy sensitivity Environmental trước exposure đưa nó lên sớm hơn.
Đây là ảnh hưởng của lựa chọn policy, không chứng minh internet luôn nguy hiểm hơn internal.
Các con số chính xác/rank hành động đọc từ `context_comparison.csv` và `priority_queue.csv`.

Hành động đề xuất: xác minh phiên bản/quyền, giới hạn quyền dashboard và database,
chuẩn bị nâng bản còn hỗ trợ có fix; kiểm dashboard/EXPLAIN theo chức năng bình thường,
backup cấu hình và thử rollback trước rollout. Không dùng truy vấn lấy dữ liệu/file để demo.
Internal không đồng nghĩa an toàn, không đủ căn cứ thay MAV; Environmental không là xác suất khai thác.
Kết hợp case mobile của N3 cho thấy applicability và đường tấn công phải được kiểm trước
khi một con số được chuyển thành lịch vá.
