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

Hai ví dụ này cho thấy Base Score đơn lẻ có thể chưa đủ để phản ánh ưu tiên
trong một bối cảnh tổ chức cụ thể.

## 2. Nhóm Environmental Metrics

### 2.1 Security Requirements — mức độ quan trọng của tài sản

| Metric | Ý nghĩa | Giá trị |
|--------|---------|---------|
| CR (Confidentiality Requirement) | Tính bí mật quan trọng đến đâu | Low / Medium / High |
| IR (Integrity Requirement) | Tính toàn vẹn quan trọng đến đâu | Low / Medium / High |
| AR (Availability Requirement) | Tính sẵn sàng quan trọng đến đâu | Low / Medium / High |

### 2.2 Modified Base Metrics — điều chỉnh theo điều kiện thực tế

Modified Base Metrics chỉ được thay đổi khi bối cảnh triển khai thực sự làm thay đổi
điều kiện khai thác hoặc mức tác động theo định nghĩa CVSS v3.1.

Không được suy diễn tự động từ một nhãn kiến trúc như "internal", "có WAF",
"có backup" hoặc "có mã hóa".

| Metric | Khi nào có thể xem xét điều chỉnh |
|--------|-----------------------------------|
| MAV | Chỉ thay khi vị trí mạng mà attacker cần có trong môi trường thực tế khác với Base metric. Dịch vụ ở mạng nội bộ không tự động có nghĩa là Adjacent hoặc Local. |
| MAC | Chỉ thay khi tồn tại điều kiện bổ sung thực sự làm tăng độ phức tạp khai thác theo định nghĩa CVSS. Có WAF/IPS không tự động đồng nghĩa `MAC:H`. |
| MPR | Chỉ thay khi đặc quyền cần thiết để khai thác trong môi trường thực tế khác với Base metric. Việc hệ thống có login không đủ để tự động thay đổi MPR. |
| MUI | Chỉ thay khi mức tương tác người dùng thực sự cần thiết trong môi trường khác với Base metric. |
| MC / MI / MA | Chỉ thay khi tác động thực tế tới Confidentiality / Integrity / Availability khác với Base impact và có căn cứ rõ ràng. Backup, HA hoặc mã hóa không tự động làm giảm các metric này. |

**Nguyên tắc:** nếu chưa đủ bằng chứng để thay đổi Modified Metric thì giữ giá trị
`Not Defined (X)` và mô tả control đó như một phần của context, không tự sửa vector.
**Phân biệt đánh giá thực tế và mô phỏng của đồ án:**

- Với hệ thống thật, điều chỉnh Modified Metrics dựa trên điều kiện triển khai và
  kiểm soát đã được xác minh; không trình bày một biện pháp dự kiến như đã có hiệu lực.
- Với tổ chức giả định của đồ án, được phân tích một kịch bản có điều kiện: ghi rõ
  giả định triển khai, nguồn mô tả điều kiện khai thác và lý do chọn từng metric theo
  đặc tả. Lưu lý do trong `modification_reason`, gắn `context_version` và ghi kết quả
  là mô phỏng, chưa kiểm chứng trên hệ thống thật. Giả định không thay thế bằng chứng
  về sản phẩm/phiên bản bị ảnh hưởng khi ánh xạ CVE với tài sản.
- Nếu điều kiện còn mơ hồ hoặc không giải thích được vì sao metric thay đổi, giữ
  Modified Metric ở `X`. Giá trị này kế thừa Base metric tương ứng, không phải giảm
  tác động về 0. Chỉ có nhãn WAF/internal/backup vẫn chưa đủ căn cứ để sửa vector.

Đối chiếu [FIRST CVSS v3.1, mục 4.2](https://www.first.org/cvss/v3.1/specification-document#4-2-Modified-Base-Metrics).
Điểm mô phỏng thấp hơn không tự chứng minh control có hiệu quả hoặc cho phép trì hoãn vá.

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

Đây là kịch bản được chọn cho đồ án. Inventory chi tiết nằm trong
[`config/assets.yaml`](../config/assets.yaml), gồm website bán hàng, hai API,
trang quản trị nội bộ và hai mobile client. Product/version hiện để trống cho tới
khi có advisory phù hợp; inventory không khẳng định hệ thống thật đã được kiểm thử.

## 4. Quy trình thực hiện

1. Dùng kịch bản thương mại điện tử và hoàn thiện inventory khoảng 5–6 tài sản.
2. Ghi rõ **giả định về kiến trúc**: có WAF không, phân vùng mạng ra sao, có MFA chưa.
Các giả định kiến trúc được dùng để mô tả bối cảnh tài sản. Chỉ khi giả định đó
thực sự làm thay đổi điều kiện khai thác theo đặc tả CVSS v3.1 và có căn cứ phù hợp
thì mới thay Modified Metric. Nếu chưa đủ căn cứ thì giữ metric ở `X`.

3. Chọn khoảng 10–20 cặp CVE–tài sản có bằng chứng sản phẩm/phiên bản phù hợp;
   phân tích sâu 3–5 case. Đây là tập context riêng, không phải top-50 toàn cohort.
4. Ánh xạ mỗi CVE vào tài sản bị ảnh hưởng và giữ `needs_review` nếu chưa đủ bằng chứng.
5. Tính Environmental Score theo công thức CVSS v3.1 (xem `src/environmental/`).
6. So sánh xếp hạng Base vs Environmental.

## 5. Kết quả cần rút ra

Bảng và biểu đồ cần trả lời được:

- Có bao nhiêu CVE **tụt hạng mạnh** khi tính bối cảnh? Đây là các trường hợp có thể
  được xem xét giảm mức ưu tiên tương đối trong kịch bản giả định.
- Có bao nhiêu CVE **lên hạng** mạnh? Đây là các trường hợp có thể được ưu tiên
  cao hơn sau khi xét thêm bối cảnh tài sản.
- Top-10 theo Base và top-10 theo Environmental trùng nhau bao nhiêu phần trăm?
- Kết hợp thêm EPSS và KEV thì thứ tự thay đổi thế nào?

Con số cuối cùng cần nêu bật: **nếu tổ chức chỉ dựa vào Base Score, những CVE nào có thể bị xếp ưu tiên khác
sau khi xét thêm bối cảnh tài sản?**

## 6. Hạn chế cần nêu trong báo cáo

- Tổ chức là giả định; CR/IR/AR do nhóm gán nên mang tính chủ quan.
- Trong thực tế, việc gán mức quan trọng cho tài sản cần phối hợp với bộ phận
  nghiệp vụ, không phải quyết định kỹ thuật thuần tuý.
- CVSS Environmental vẫn không tính đến khả năng bị khai thác — đó là lý do vẫn
  cần EPSS và KEV song song.

## 7. Ứng viên case study Phase 1 — chờ phân tích

Các case dưới đây được chọn có chủ đích để thử nhiều vai trò sản phẩm và điều kiện
applicability. Danh sách này **chưa phải kết luận về ưu tiên vá**. Cả năm CVE đều có
trong master 71.653 dòng của gói
`pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z`, nhưng master
hiện vẫn chờ áp dụng scope; vì vậy chưa được gọi là cohort ranking chính thức.

| CVE | Sản phẩm / vai trò | Advisory | Lý do chọn, chưa kết luận ưu tiên |
|---|---|---|---|
| CVE-2022-43538 | Aruba ClearPass Policy Manager — giao diện quản trị Web | [ARUBA-PSA-2022-020](https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2022-020.txt) | Minh họa lỗi thực thi lệnh trong giao diện quản trị Web và yêu cầu kiểm tra phiên bản triển khai. |
| CVE-2022-46177 | Discourse — nền tảng thảo luận Web | [GitHub Security Advisory](https://github.com/discourse/discourse/security/advisories/GHSA-5www-jxvf-vrc3) | Minh họa đường tấn công liên quan vòng đời email đặt lại mật khẩu và takeover tài khoản. |
| CVE-2023-22626 | PgHero — dashboard Web cho PostgreSQL | [Issue dự án PgHero](https://github.com/ankane/pghero/issues/439) | Minh họa tác động bí mật dữ liệu của một dashboard vận hành nội bộ. |
| CVE-2023-30470 | Hermes — JavaScript engine dùng trong React Native | [Meta advisory](https://www.facebook.com/security/advisories/cve-2023-30470) | Case mobile framework có điều kiện rõ: chỉ xét affected khi runtime thực thi JavaScript không tin cậy; advisory nói phần lớn ứng dụng React Native không bị ảnh hưởng. |
| CVE-2023-41387 | `flutter_downloader` — Flutter plugin trên iOS | [Changelog dự án](https://pub.dev/packages/flutter_downloader/changelog) | Case mobile client/plugin trực tiếp, có dải phiên bản đến 1.11.1 và bản sửa 1.11.2 để thử applicability theo phiên bản. |

Tiêu chí chọn case study khác với tiêu chí tạo cohort định lượng. Việc chọn các case
này không dựa vào EPSS cao hoặc trạng thái KEV, và không làm thay đổi scope của toàn
bộ dataset. Nếu một case sau này không đạt điều kiện cohort thì phải trình bày riêng
như ví dụ context bổ sung, không gộp vào top-K hoặc metric của cohort.

## 8. Applicability mẫu và tài sản giả định

Inventory vẫn là kịch bản thương mại điện tử giả định. Product/version được điền cho
năm tài sản chỉ để kiểm thử giao tiếp dữ liệu với advisory; không khẳng định đây là
hệ thống đã triển khai hoặc đã được kiểm thử. `API-02` tiếp tục để product/version
`null` vì chưa có căn cứ phù hợp; chưa biết không đồng nghĩa `unaffected`.

Năm cặp có bằng chứng phiên bản được lưu tại
`data/processed/cve_asset_mapping.csv`. Hai cặp mobile dùng `exposure=client`; dù
`applicability=affected`, policy hàng đợi ban đầu vẫn phải đặt chúng ở
`review_required` cho tới khi có quy tắc exposure client được version hóa. Mapping
không tự sửa Modified Metrics và không tự suy ra Environmental Score.
