# RQ3 — Bối cảnh hệ thống và CVSS Environmental Metrics

> Đây là phần bảo mật trọng tâm của đồ án. Base Score chỉ trả lời "lỗ hổng này
> nguy hiểm đến đâu nói chung"; Environmental Score trả lời "lỗ hổng này nguy hiểm
> đến đâu **với tổ chức của tôi**".

## 1. Vì sao Base Score là chưa đủ

CVSS Base Score được thiết kế để mô tả đặc tính **nội tại** của lỗ hổng, độc lập
với môi trường triển khai. Điều này có chủ đích: nhà cung cấp không thể biết khách
hàng của mình đặt phần mềm ở đâu.

Nhưng hầu hết tổ chức lại dùng thẳng Base Score để quyết định vá — bỏ qua hoàn toàn
nhóm Environmental mà chính đặc tả CVSS cung cấp sẵn. Hệ quả:

- Một lỗ hổng RCE `AV:N` trên máy chủ **không nối internet** vẫn bị chấm 9.8.
- Một lỗ hổng rò rỉ thông tin điểm 5.3 trên **hệ thống chứa dữ liệu thanh toán**
  vẫn bị xếp thấp hơn.

Cả hai đều là quyết định sai về mặt quản trị rủi ro.

## 2. Nhóm Environmental Metrics

### 2.1 Security Requirements — mức độ quan trọng của tài sản

| Metric | Ý nghĩa | Giá trị |
|--------|---------|---------|
| CR (Confidentiality Requirement) | Tính bí mật quan trọng đến đâu | Low / Medium / High |
| IR (Integrity Requirement) | Tính toàn vẹn quan trọng đến đâu | Low / Medium / High |
| AR (Availability Requirement) | Tính sẵn sàng quan trọng đến đâu | Low / Medium / High |

### 2.2 Modified Base Metrics — điều chỉnh theo kiến trúc thực tế

Ghi đè từng thành phần Base khi biện pháp phòng thủ đã thay đổi điều kiện khai thác:

| Metric | Trường hợp dùng |
|--------|-----------------|
| MAV | Dịch vụ chỉ truy cập được từ mạng nội bộ → `AV:N` hạ xuống `MAV:A` hoặc `MAV:L` |
| MAC | Có WAF/IPS chặn được pattern tấn công → `AC:L` nâng lên `MAC:H` |
| MPR | Đã bắt buộc xác thực trước khi tới dịch vụ → `PR:N` nâng lên `MPR:L` |
| MUI | Chính sách chặn macro/tệp đính kèm → thay đổi điều kiện tương tác người dùng |
| MC / MI / MA | Dữ liệu đã mã hoá, có backup, có HA → hạ mức tác động tương ứng |

**Lưu ý phương pháp luận:** việc điều chỉnh MAV/MAC/MPR phải dựa trên biện pháp
kiểm soát **đã triển khai và kiểm chứng được**, không phải giả định. Nếu không,
đây trở thành cách hợp lý hoá việc trì hoãn vá — một anti-pattern cần nêu rõ trong
phần bàn luận.

## 3. Tổ chức giả định

> Nhóm chọn **một** kịch bản dưới đây (hoặc tự thiết kế), mô tả đủ chi tiết để
> việc gán CR/IR/AR có căn cứ.

### Phương án A — Bệnh viện đa khoa

| Tài sản | Mô tả | CR | IR | AR | Vùng mạng |
|---------|-------|----|----|----|-----------|
| HIS (Hospital Information System) | Hồ sơ bệnh án điện tử | H | H | H | Nội bộ |
| PACS | Lưu trữ ảnh chẩn đoán | M | H | H | Nội bộ |
| Website đặt lịch khám | Public-facing | L | M | M | DMZ |
| Máy chủ in thẻ BHYT | Nội bộ, ít người dùng | L | M | L | Nội bộ |
| Thiết bị y tế nối mạng | Monitor, máy thở | L | H | H | Mạng cách ly |

Đặc điểm: tính **sẵn sàng** và **toàn vẹn** quan trọng hơn bí mật ở nhóm thiết bị
y tế (sai lệch dữ liệu hoặc mất kết nối có thể gây nguy hiểm tính mạng) — ngược lại
với trực giác thông thường "bảo mật = giữ bí mật".

### Phương án B — Ngân hàng thương mại

| Tài sản | Mô tả | CR | IR | AR | Vùng mạng |
|---------|-------|----|----|----|-----------|
| Core Banking | Sổ cái giao dịch | H | H | H | Vùng bảo vệ cao |
| Internet Banking | Public-facing | H | H | H | DMZ |
| ATM switch | Xử lý giao dịch thẻ | M | H | H | Mạng riêng |
| Hệ thống báo cáo nội bộ | BI, phân tích | M | L | L | Nội bộ |
| Website giới thiệu | Tĩnh, không dữ liệu | L | L | L | DMZ |

### Phương án C — Doanh nghiệp thương mại điện tử

(Nhóm tự hoàn thiện theo mẫu trên.)

## 4. Quy trình thực hiện

1. Chọn kịch bản, hoàn thiện bảng tài sản (5–10 mục là đủ).
2. Ghi rõ **giả định về kiến trúc**: có WAF không, phân vùng mạng ra sao, có MFA chưa.
   Mỗi giả định phải kéo theo được một điều chỉnh MAV/MAC/MPR cụ thể.
3. Chọn ~50 CVE thực tế phù hợp với stack công nghệ của tổ chức giả định.
4. Ánh xạ mỗi CVE vào tài sản bị ảnh hưởng.
5. Tính Environmental Score theo công thức CVSS v3.1 (xem `src/environmental/`).
6. So sánh xếp hạng Base vs Environmental.

## 5. Kết quả cần rút ra

Bảng và biểu đồ cần trả lời được:

- Có bao nhiêu CVE **tụt hạng** mạnh khi tính bối cảnh? Đó là công sức vá tiết kiệm được.
- Có bao nhiêu CVE **lên hạng** mạnh? Đó là rủi ro suýt bị bỏ sót.
- Top-10 theo Base và top-10 theo Environmental trùng nhau bao nhiêu phần trăm?
- Kết hợp thêm EPSS và KEV thì thứ tự thay đổi thế nào?

Con số cuối cùng cần nêu bật: **nếu tổ chức chỉ vá theo Base Score, họ đã bỏ sót
những lỗ hổng nào và tốn công vào những lỗ hổng nào?**

## 6. Hạn chế cần nêu trong báo cáo

- Tổ chức là giả định; CR/IR/AR do nhóm gán nên mang tính chủ quan.
- Trong thực tế, việc gán mức quan trọng cho tài sản cần phối hợp với bộ phận
  nghiệp vụ, không phải quyết định kỹ thuật thuần tuý.
- CVSS Environmental vẫn không tính đến khả năng bị khai thác — đó là lý do vẫn
  cần EPSS và KEV song song.
