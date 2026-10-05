# Phạm vi Web/mobile của T08

## 1. Mục tiêu

Đồ án tập trung vào các CVE có liên quan đến nền tảng Web và ứng dụng di động.

Mục tiêu của việc xác định phạm vi là tạo một cohort nhất quán để so sánh thứ tự ưu tiên theo CVSS, EPSS và KEV, đồng thời hỗ trợ phân tích bối cảnh tài sản.

Đồ án không khai thác CVE, không viết PoC và không thực hiện pentest trên hệ thống thật.

## 2. Đối tượng được nhận vào phạm vi

### 2.1. Web

Một CVE có thể được gắn `web` khi có bằng chứng cho thấy thành phần bị ảnh hưởng đóng vai trò trong hệ thống Web, ví dụ:

- CMS hoặc plugin CMS
- Web framework
- Application server
- Web/API backend
- Thành phần server-side phục vụ ứng dụng Web

Việc một CVE có `AV:N` không đủ để kết luận CVE đó thuộc Web.

### 2.2. Mobile

Một CVE có thể được gắn `mobile` khi có bằng chứng cho thấy thành phần bị ảnh hưởng nằm trực tiếp trong hoặc hỗ trợ phía client của ứng dụng di động, ví dụ:

- ứng dụng Android/iOS
- mobile SDK
- thư viện nhúng trong ứng dụng mobile
- framework hoặc thành phần client phù hợp
- WebView component nếu advisory thể hiện rõ đường tác động tới ứng dụng

Backend phục vụ ứng dụng mobile không tự động được coi là CVE mobile-client.

### 2.3. Có thể thuộc cả Web và mobile

Một CVE có thể có cả hai nhãn khi cùng một thành phần có vai trò rõ ràng với cả Web và mobile.

Không nhân đôi CVE trong master dataset; dùng nhiều giá trị trong `domain_tags`.

## 3. Đối tượng ngoài phạm vi

Các đối tượng sau thường không thuộc cohort Web/mobile chính nếu không có bằng chứng liên hệ trực tiếp với bài toán ứng dụng:

- kernel
- device driver
- firmware
- thiết bị phần cứng
- thành phần hệ điều hành chung không có đường tác động rõ tới ứng dụng Web/mobile

Các CVE này vẫn có thể tồn tại trong master dataset nhưng có `scope_status=excluded`.

## 4. Trường hợp chưa đủ căn cứ

Dùng `scope_status=needs_review` khi:

- mô tả CVE quá ngắn
- sản phẩm là thư viện đa dụng và chưa biết ngữ cảnh triển khai
- advisory không chỉ rõ vai trò sản phẩm
- thiếu CPE/reference đủ để xác minh
- có bằng chứng xung đột

`needs_review` không được coi là đã thuộc cohort chính.

## 5. Bằng chứng dùng để xác định scope

Ưu tiên kiểm tra:

1. vendor advisory
2. CPE hoặc product/version
3. CVE description
4. reference URL từ nguồn chính thức

Mỗi quyết định scope phải có `scope_reason`.

Nếu có nguồn hỗ trợ, URL được lưu vào `scope_evidence` dưới dạng danh sách URL.
Nếu chưa có bằng chứng đủ mạnh, không để một keyword thay cho evidence; chuyển
trạng thái sang `needs_review` và ghi rõ thông tin còn phải xác minh.

Keyword hoặc CWE chỉ giúp tìm ứng viên, không đủ để xác nhận phạm vi.

## 6. Quy tắc gán nhãn

### included

Dùng khi có đủ bằng chứng cho thấy CVE thuộc Web, mobile hoặc cả hai.

- `in_scope=true`
- `scope_status=included`

### excluded

Dùng khi đã có căn cứ cho thấy CVE ngoài phạm vi Web/mobile của nghiên cứu.

- `in_scope=false`
- `scope_status=excluded`

### needs_review

Dùng khi chưa đủ bằng chứng kết luận.

- `in_scope=false`
- `scope_status=needs_review`

## 7. Phân biệt các tập dữ liệu

### Ranking cohort

Chỉ gồm CVE:

- `in_scope=true`
- không Rejected
- có CVSS v3.1 hợp lệ
- có EPSS đúng snapshot
- có trạng thái KEV xác định

Ba ranking CVSS-first, EPSS-first và KEV-first phải dùng cùng một tập CVE.

### ML cohort

Cần:

- description hợp lệ
- đủ 8 metric CVSS v3.1
- không Rejected

ML cohort có thể rộng hơn ranking cohort nếu cần đủ dữ liệu huấn luyện.

### Context / case study

Chỉ ánh xạ CVE với tài sản khi có bằng chứng sản phẩm và phiên bản phù hợp.

Trường hợp chưa rõ phải giữ `needs_review`.

## 8. Chính sách ranking dự kiến

### CVSS-first

Sắp theo:

1. CVSS Base Score giảm dần
2. CVE ID tăng dần nếu hòa

### EPSS-first

Sắp theo:

1. EPSS giảm dần
2. CVE ID tăng dần nếu hòa

### KEV-first

Sắp theo:

1. KEV trước
2. EPSS giảm dần
3. CVSS giảm dần
4. CVE ID tăng dần

KEV là trạng thái catalog, không phải thang điểm số.

## 9. Tình huống thử quy tắc

### Tình huống A — Web rõ ràng

Một CVE ảnh hưởng plugin của CMS dùng cho website bán hàng và có vendor advisory xác nhận.

Kết quả dự kiến:

- `domain_tags=["web"]`
- `in_scope=true`
- `scope_status=included`

### Tình huống B — Mobile SDK

Một CVE ảnh hưởng SDK được nhúng trong ứng dụng Android và advisory nêu rõ tác động tới ứng dụng.

Kết quả dự kiến:

- `domain_tags=["mobile"]`
- `in_scope=true`
- `scope_status=included`

### Tình huống C — Thư viện đa dụng

Một CVE ảnh hưởng thư viện có thể dùng trong Web, desktop hoặc mobile nhưng chưa có bằng chứng về cách triển khai.

Kết quả dự kiến:

- `domain_tags=[]`
- `in_scope=false`
- `scope_status=needs_review`

## 10. Giới hạn và điểm cần N1 tổng hợp

- Chưa có đề cương môn học trong repo tại thời điểm rà Phase 0; N1 cần đối chiếu
  đề cương thật trước khi coi các tỷ lệ/phạm vi trong kế hoạch là rubric chính thức.
- Mức độ bao phủ CVE mobile chưa được xác định trước khi chạy pilot.
- Không được chọn cohort dựa trên EPSS cao, KEV hoặc kết luận mong muốn.
- Missing EPSS không được xem là 0.
- Không có trong KEV không chứng minh CVE chưa từng bị khai thác.
- Dự đoán CVSS từ AI phải giữ riêng với CVSS quan sát từ nguồn.
- Quy tắc scope có thể được cập nhật sau pilot nhưng phải tăng phiên bản policy.
