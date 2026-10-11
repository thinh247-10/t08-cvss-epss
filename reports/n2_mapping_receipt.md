# Tiếp nhận mapping N2 gửi bổ sung

Ngày ghi nhận: **2026-10-11**, múi giờ Asia/Saigon. Người dùng cung cấp file
`cve_asset_mapping.csv` trong Downloads sau khi gói v1 đã được tạo.

## Bản gốc và kết quả kiểm tra

- Lưu nguyên byte tại `data/raw/handoffs/n2_mapping_received_20261011/cve_asset_mapping.csv`.
  File này nằm ngoài Git; không sửa bản trong Downloads.
- 2.273 byte, 5 dòng, 5 khóa CVE–asset duy nhất; đủ 10 cột theo schema cũ.
- Reviewer trong file: `CanhLai`; cả 5 dòng ghi `affected`.
- Version đúng gói N2 đã nhận:
  `pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z`.
- Cả 5 CVE tồn tại trong master cũ và v1; cả 5 asset ID hợp lệ. Tập khóa trùng
  5 cặp của mapping v1, nhưng nội dung và version không hoàn toàn giống nhau.
- SHA-256 thực nhận:
  `49a261f7f3880e0e07bebc1a47b4c6b69d748e27f11b2d72ffdbf1d3622256b2`.
- SHA-256 N2 từng ghi trong báo cáo:
  `19b508ff510ac4b5ef424bc78a30c71e734f82ec11758208061a3b11725930f6`.
  Hai giá trị không khớp, kể cả khi thử chuẩn hóa LF/CRLF. Chưa xác định nguyên nhân;
  không coi đây là bằng chứng file bị hỏng hoặc thay đổi trái phép. Dùng hash thực nhận
  cho bản lưu này, giữ hash báo cáo cũ như thông tin lịch sử.

Biên nhận máy đọc được: [n2-mapping-receipt-20261011.json](../docs/handoffs/n2-mapping-receipt-20261011.json).

## Đối chiếu với bản v1 đã hiệu chỉnh

| Cặp | Bản N2 gửi | Cách xử lý trong v1 |
|---|---|---|
| CVE-2018-25067 / WEB-01 | JoomGallery 3.3.3 | Giữ phiên bản giả định; tên product được ghi rõ Joomla với JoomGallery để khớp inventory |
| CVE-2022-46177 / API-01 | Discourse 2.8.13 | Giữ stable 2.8.13; ghi rõ dùng nhánh stable, tránh nhập nhằng mốc beta trong advisory |
| CVE-2023-22626 / ADMIN-01 | PgHero 3.0.4, suy từ “before 3.1.0” | Giữ hiệu chỉnh giả định sang 3.0.1 theo dải 0.1.1–3.0.1 của issue chính thức; không kết luận 3.0.4 an toàn chỉ vì ngoài dải được nêu |
| CVE-2023-30470 / MOB-01 | Hermes trước commit sửa, chạy JavaScript không tin cậy | Giữ điều kiện đó, bổ sung bật tối ưu hóa và URL commit sửa; không suy mọi ứng dụng React Native bị ảnh hưởng |
| CVE-2023-41387 / MOB-02 | flutter_downloader iOS 1.11.1; mô tả changelog là sửa SQLi | Giữ 1.11.1; diễn đạt đúng changelog là cập nhật bảo mật iOS, kèm điều kiện đầu vào/tấn công trong mapping v1 |

Nguồn đối chiếu đã dùng khi hoàn thiện v1:
[JoomGallery release](https://github.com/JoomGallery/JoomGallery/releases/tag/v3.3.4),
[Discourse advisory](https://github.com/discourse/discourse/security/advisories/GHSA-5www-jxvf-vrc3),
[PgHero issue #439](https://github.com/ankane/pghero/issues/439),
[Hermes commit](https://github.com/facebook/hermes/commit/da8990f737ebb9d9810633502f65ed462b819c09),
[flutter_downloader changelog](https://pub.dev/packages/flutter_downloader/changelog).

Đây là các tài sản giả định. `affected` cần đọc cùng điều kiện của từng cặp; không
tự tạo điểm Environmental hay thứ tự vá. Hai cặp `exposure=client` vẫn cần
`review_required` theo policy hàng đợi ban đầu.

## Kết luận bàn giao

Đã nhận được phần mapping riêng của N2. Không còn mô tả phần này là đang thiếu ở
thời điểm hiện tại. Các ghi chú “chưa nhận” ngày 2026-10-10 phản ánh lúc build v1.

Giữ bản N2 gửi làm nguồn lịch sử; tiếp tục sử dụng mapping có hiệu chỉnh trong
`data/processed/phase1_v1_20261010/cve_asset_mapping.csv` cho công việc tiếp theo.
Không chép đè hoặc chỉ đổi dataset_version của file cũ để giả làm bản v1.

Đã đối chiếu checksum và kích thước đủ 14 file release với manifest; checksum ZIP
cũng không đổi. Không cần build lại dataset, tải API hay train model cho việc nhận file này.
Biên nhận này không thay thế xác nhận N2/N3 đã đọc gói v1 trên máy riêng.
