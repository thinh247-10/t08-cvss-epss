# Phân tích 10 lỗi validation — Phase 2, Người 3

Dataset: `t08-v1.0-20261010`. Model: `tfidf-v1-candidate-1`, TF-IDF + tám Logistic
Regression, `C=1.0`. Model đã được chọn và khóa trước khi soạn phân tích này;
không dùng nhận xét bên dưới để sửa cấu hình hoặc chọn lại model từ test.

Nguồn duy nhất cho dữ kiện từng CVE là mô tả và nhãn/prediction trong
[validation_errors_n2.csv](validation_errors_n2.csv), SHA-256
`fe7e466ec7375f5b09f53b9f4164645fab172c030f583c6db152cf50dea3c599`.
Đây là **10 ID lỗi đầu theo thứ tự cve_id**, từ 12.083 dòng lỗi validation ở
[validation_errors.csv](validation_errors.csv). Không phải mẫu ngẫu nhiên hay
thống kê đại diện; nhiều bản ghi dùng mô tả XSS tương tự. Không đọc lỗi test.
Năm trong CVE ID không được dùng để gán lại split đã khóa theo published.

PR mô tả quyền **của người tấn công trước khi khai thác**; UI xét sự tham gia của
người dùng khác; Scope xét việc vượt phạm vi của cơ chế quản lý quyền. Một mô tả
chỉ nói tấn công từ xa chưa xác định được PR. C/I/A là hậu quả khi khai thác thành
công, không phải xác suất sự kiện xảy ra. Các khái niệm này đối chiếu với
[đặc tả CVSS v3.1 của FIRST, mục 2.1–2.3](https://www.first.org/cvss/v3.1/specification-document).

Trong bảng, nhãn viết **nguồn → prediction**, và Δ là điểm dự đoán trừ điểm
nguồn. Nhãn nguồn là mốc đánh giá đã khóa của dataset; phân tích mô tả không đủ
để khẳng định đã kiểm chứng độc lập nhãn đó hoặc để tự sửa nhãn.

| CVE | Metric sai | Base nguồn → dự đoán | Δ |
|---|---|---|---:|
| CVE-2010-10011 | PR:N→L | 7,5 → 6,5 | −1,0 |
| CVE-2012-6664 | I:H→N | 9,1 → 7,5 | −1,6 |
| CVE-2014-125110 | PR:L→N; S:U→C; C:N→L | 3,5 → 6,1 | +2,6 |
| CVE-2014-125111 | PR:L→N; S:U→C; C:N→L | 3,5 → 6,1 | +2,6 |
| CVE-2015-10123 | PR:N→L; UI:R→N | 8,8 → 8,8 | 0,0 |
| CVE-2015-10129 | PR:N→H; C:H→L | 5,9 → 2,2 | −3,7 |
| CVE-2015-10131 | PR:L→N; S:U→C; C:N→L | 3,5 → 6,1 | +2,6 |
| CVE-2015-10132 | PR:L→N; S:U→C; C:N→L | 3,5 → 6,1 | +2,6 |
| CVE-2016-15038 | C:N→H; I:L→H; A:L→H | 6,5 → 9,8 | +3,3 |
| CVE-2016-20021 | C:H→N | 9,8 → 9,1 | −0,7 |

## 1. CVE-2010-10011 — suy diễn thêm yêu cầu quyền

Mô tả Acritum Femitter Server nêu path traversal và khả năng tấn công từ xa,
nhưng không nói người tấn công phải đăng nhập. Prediction thêm PR:L so với PR:N
nguồn, giảm Base 1,0 điểm. Việc đọc mô tả cho thấy **thiếu dữ kiện về quyền**,
chưa đủ chứng minh model đã nhầm một từ cụ thể. Trong diễn giải bảo mật, lỗi này
có thể khiến người xem tưởng tài khoản hợp lệ là điều kiện bắt buộc. N2 cần kiểm
advisory/quy tắc xác thực của chức năng bị ảnh hưởng để xác nhận PR, không suy
ra từ chữ remote. Cụm nói exploit đã công bố không được biến thành EPSS/KEV.

## 2. CVE-2012-6664 — bỏ sót tác động ghi file

Mô tả TFTP Server của Distinct Intranet Servers nói rõ cả đọc **hoặc ghi file
tùy ý**, qua hai lệnh get/put. Prediction giữ C:H nhưng gán I:N, trong khi nguồn
I:H. Hậu quả ghi dữ liệu trái phép là dấu hiệu trực tiếp liên quan Integrity;
mô hình bỏ lỡ khác biệt giữa chỉ đọc và có ghi trong một câu nhiều nhánh. Base
giảm 1,6 điểm. Cần kiểm quyền ghi/phạm vi file thực tế khi review độc lập; không
tự thêm tác động Availability hoặc thực thi mã chỉ từ chữ arbitrary files.

## 3. CVE-2014-125110 — áp mẫu XSS rộng hơn thông tin mô tả

Mô tả wp-file-upload chỉ rõ callback/file và XSS, nhưng không mô tả xác thực,
nạn nhân hoặc phạm vi dữ liệu đọc được. Model dự đoán không cần quyền, Scope
changed và mất bí mật mức Low; nguồn giữ PR:L, S:U, C:N. Ba sai khác làm Base
tăng 2,6 điểm. Đây là giả thuyết **mô hình khái quát từ mẫu XSS quen thuộc**,
không phải kết luận nhân quả từ trọng số từ vựng. N2 cần xác minh người gửi yêu
cầu có phải tài khoản quyền thấp, mã chạy trong phạm vi nào và có đọc được dữ
liệu mới hay không; tên XSS đơn lẻ không giải quyết được ba câu hỏi đó.

## 4. CVE-2014-125111 — mô tả chức năng thiếu chi tiết

Mô tả Wp-Insert ghi chức năng chưa xác định và XSS từ xa. Prediction có cùng
bộ sai PR/S/C như ca trước, làm Base 3,5 thành 6,1. Việc không nêu điều kiện đăng
nhập trong mô tả không chứng minh PR:N; dữ kiện phân biệt S:U/C và C:N/L cũng
chưa có. N2 cần xem đường xử lý đầu vào và đối tượng thực thi nội dung. Báo
cáo giữ sai khác với nhãn nguồn, đồng thời ghi **mô tả không đủ rõ**, tránh
khẳng định model hay nguồn đúng tuyệt đối chỉ bằng tên loại lỗ hổng.

## 5. CVE-2015-10123 — lẫn người tấn công với người dùng nạn nhân

Mô tả phân biệt người tấn công từ xa không cần xác thực với người dùng đã xác
thực phải xem dữ liệu trên trang quản trị để kích hoạt buffer overflow. Nguồn
PR:N/UI:R phù hợp với phân biệt vai trò đó; prediction PR:L/UI:N làm mất điều
kiện tương tác và gán quyền của nạn nhân sang người tấn công. Đây là tình huống
đặc biệt rõ về hạn chế hiểu quan hệ/chủ thể. **Hai vector khác nhau vẫn cùng
Base 8,8**: MAE bằng 0 ở ca này không đồng nghĩa dự đoán đúng hoặc diễn giải
điều kiện khai thác đúng. Exact-vector và metric từng đầu ra vì vậy cần thiết.

## 6. CVE-2015-10129 — quyền và mức tác động bị suy diễn

Mô tả planet-freo có tên file trong thư mục admin và đối số auth, đồng thời ghi
độ phức tạp cao. Model giữ đúng AC:H, nhưng chuyển PR:N thành H và C:H thành L,
hạ Base 3,7 điểm. Tên file/đối số là dấu hiệu ngữ cảnh, chưa chứng minh người
tấn công cần quyền quản trị; mô tả cũng không định lượng mức lộ bí mật. Cần
kiểm cơ chế so sánh/xác thực và dữ liệu có thể đọc trong advisory. Không thể
đánh đồng chức năng xác thực bị lỗi với yêu cầu người tấn công đã có quyền cao.

## 7. CVE-2015-10131 — tên hàm admin không xác định PR

Mô tả TFO Graphviz Plugin nêu admin_page_load/admin_page và XSS. Prediction
lại là PR:N/S:C/C:L, khác PR:L/S:U/C:N nguồn, tăng Base 2,6 điểm. N2 cần xác
minh ai được gọi chức năng và ai xem nội dung, thay vì quyết định PR từ tên
hàm admin hoặc từ việc tấn công có thể từ xa. Có thể mô tả đã lược bỏ kiểm
tra quyền và phạm vi ảnh hưởng. Không dùng ca này làm bằng chứng mọi XSS đều
có Scope changed hoặc đều làm lộ bí mật.

## 8. CVE-2015-10132 — cùng loại lỗi nhưng chưa có chi tiết điều kiện

Mô tả WP-Spreadplugin xác định tham số Spreadplugin và XSS, nhưng không nêu
quyền gọi trang, người dùng phải thao tác gì hoặc dữ liệu có thể lộ. Model
vẫn tạo PR:N/S:C/C:L thay PR:L/S:U/C:N, tăng Base 2,6 điểm. N2 cần đối chiếu
đường đi của tham số tới nơi hiển thị và ranh giới bảo mật. Bốn ca XSS trong
queue cho cùng mẫu lỗi là quan sát về **mẫu 10 ID này**, không được suy rộng
thành tần suất lỗi XSS trên toàn validation hoặc toàn bộ Web/mobile.

## 9. CVE-2016-15038 — khuếch đại đồng thời ba tác động

Mô tả NUUO NVRmini 2 nêu path traversal trong deletefile.php, đối số filename;
không nói đọc được toàn bộ bí mật hoặc phá hủy hoàn toàn dịch vụ. Nguồn là
C:N/I:L/A:L, prediction thành H/H/H khiến Base 6,5 tăng lên 9,8. Tên thao tác
delete gợi ý cần kiểm khả năng xóa/sửa file và gián đoạn, nhưng **không tự
chứng minh tác động High**. N2 cần xác minh các file được truy cập, quyền của
tiến trình và hậu quả trực tiếp. Không thay mức tác động bằng chữ critical
trong mô tả hoặc bằng việc đã có exploit công bố.

## 10. CVE-2016-20021 — bỏ sót tác động gián tiếp từ mã được thực thi

Mô tả Gentoo Portage nói công cụ emerge-webrsync tải chữ ký nhưng không kiểm
tra chữ ký của mã được thực thi; chỉ cấu hình dùng công cụ đó mới ảnh hưởng.
Model giữ I:H/A:H nhưng gán C:N thay C:H nguồn, làm Base giảm 0,7 điểm. Đây
là ví dụ cần suy luận chuỗi hậu quả từ tính xác thực của mã đến các tài nguyên
mà mã được phép truy cập, dù mô tả không dùng từ đọc/rò rỉ. Mức Confidentiality
thực tế vẫn cần kiểm quyền thực thi và biên tài nguyên; báo cáo không tự khẳng
định mọi trường hợp thiếu kiểm chữ ký đều có C:H. Điều kiện cấu hình còn hữu
ích cho applicability, không được bỏ qua khi đưa ra quyết định vá cụ thể.

## Bàn giao và giới hạn diễn giải

Queue và bản phân tích đã được tạo để N2 review độc lập. **Trạng thái N2 đã
nhận/đọc/xác nhận: chưa có bằng chứng**, giữ `pending_independent_review` trong
manifest; không gọi phân tích do công cụ hỗ trợ này là xác nhận của N2.
Những giả thuyết về nguyên nhân lỗi chưa có kiểm chứng attribution/ablation.

Các ca cho thấy sai PR/UI có thể bù nhau trong Base, các mô tả XSS có thể thiếu
điều kiện phân biệt và hậu quả từ ghi file/thực thi mã cần được hiểu theo ngữ
cảnh. Đây là nhận xét mô tả sau khóa, không phải lý do tuning lại model. Không
có lỗi schema/inference trong 10 dòng; đây là lỗi nhãn dự đoán so với nhãn nguồn.

CVSS Base ước lượng severity. Điểm này cùng các metric kỹ thuật không trực tiếp
đo xác suất bị khai thác; việc ưu tiên vá còn cần dữ liệu quan sát, EPSS/KEV và
bối cảnh tài sản theo hợp đồng dự án. Không suy diễn thông tin khai thác thực
tế từ câu chữ trong description và không trộn prediction vào ranking chính.
