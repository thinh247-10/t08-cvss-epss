# Case mobile N3 — CVE-2023-41387 / MOB-02

Đọc nguồn ngày **2026-10-21**. Đây là mobile client iOS nhúng plugin
`flutter_downloader`, không phải backend phục vụ mobile. Kịch bản giả định của
inventory `phase1-v1`: ứng dụng mua hàng dùng plugin **1.11.1**, `exposure=client`.
Không kiểm chứng trên ứng dụng hay thiết bị thật.

Theo [bản ghi NVD](https://nvd.nist.gov/vuln/detail/cve-2023-41387), SQL injection
ảnh hưởng plugin iOS đến 1.11.1, có thể dẫn tới lấy token phiên và ghi đè file trong
container ứng dụng. Nhánh local cần lưu ý hai cấu hình `UIFileSharingEnabled` và
`LSSupportsOpeningDocumentsInPlace`, khiến database nội bộ có thể bị người dùng
thiết bị sửa. [Changelog dự án](https://pub.dev/packages/flutter_downloader/changelog#1112)
ghi bản **1.11.2** có security update cho iOS. Đây là mốc sửa của case, không phải
khẳng định 1.11.2 là phiên bản mới nhất hoặc xử lý mọi lỗ hổng khác.

Đường tác động giả định là dữ liệu tải file do attacker kiểm soát đi vào plugin
và truy vấn/database của downloader; cần xác minh điểm nhận input, phiên bản native
được đóng gói và quyền truy cập database. Vector nguồn có PR:N/UI:N cho nhánh network;
không áp kết luận đó cho nhánh local vốn cần quyền truy cập dữ liệu trên thiết bị.
Không có bằng chứng mọi ứng dụng Flutter đều affected hoặc tác động vượt container.
Mapping r1 đánh dấu `affected` **theo giả định phiên bản**, còn đường tấn công thực tế
vẫn cần review. [Mapping N2](../../data/processed/p3_n2_context_20261019_r1_received/p3_n2/cve_asset_mapping.csv)
giữ rõ điều kiện và giới hạn này.

| Tín hiệu đóng băng | Giá trị / nguồn |
|---|---|
| Dataset / cohort | `t08-v1.0-20261010`; ranking 396 CVE |
| CVSS nguồn | `nvd@nist.gov`, Base **9.1**, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` |
| EPSS | **0.00874**, ngày 2026-09-29; xác suất, không phải percentile |
| KEV | false trong catalog phát hành 2026-09-30, tải 2026-10-01 UTC; dateAdded=N/A |
| CVSS / EPSS / KEV-first rank | **30 / 128 / 127**, theo [ranking đã kiểm](../../data/processed/p3_n3_input/rankings.csv) |
| ML split | **train**; không phải ví dụ lỗi validation/test |
| Environmental | **9.8**; N2 context `phase3-context-v1`, [bảng nguồn](../../data/processed/p3_n2_context_20261019_r1_received/p3_n2/environmental_scores.csv) |
| Queue | `review_required`, priority rank **N/A**; policy `context-v1` |

CR:H/IR:H phản ánh dữ liệu tài khoản và đơn hàng giả định; AR:M phản ánh gián đoạn
client. Temporal E/RL/RC và Modified metrics đều X vì chưa có bằng chứng kiểm soát
khác. C:N được giữ nguyên dù mô tả nhắc token theft: đây là bất nhất cần đối chiếu
nguồn, không tự sửa nhãn đóng băng. CR:H không biến C:N thành C:H. Kết quả 9.8 được
[đối chiếu độc lập theo FIRST](../../reports/p3_environmental_crosscheck_n3.md).

Hành động giao cho nhóm mobile giả định: xác minh dependency/build và luồng input;
chọn bản có fix, kiểm tương thích và regression tải file; rà hai cấu hình chia sẻ
file, dữ liệu/token trong container và kế hoạch rollback. Giữ nguyên reason N2:
`Exposure client/unknown has no numeric rule; verify attack path.` Không đổi exposure
thành internet để có rank. EPSS thấp/không có trong KEV không phải căn cứ trì hoãn
vá; severity rank và queue hành động là hai kết quả khác nhau.
