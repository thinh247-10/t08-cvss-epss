# Phase 3 — phân tích bảo mật và năm case của N2

Cập nhật 2026-10-20. Soạn và đối chiếu với hỗ trợ Codex cho N2; không thay xác nhận
độc lập của N1/N3. Tổ chức thương mại điện tử là giả định. Không khai thác CVE,
không đo hiệu quả vận hành hoặc thời gian vá thực tế.

## 1. Dữ liệu và các tập so sánh

Dataset t08-v1.0-20261010; context phase3-context-v2; inventory phase1-v1.
Tín hiệu/vector quan sát từ release v1; output hiện hành dưới data/processed/p3_n2/.
EPSS 2026-09-29; KEV phát hành 2026-09-30, tải 2026-10-01 UTC.
Không thay nhãn quan sát bằng CVSS advisory hoặc prediction AI.

Ranking chính có 396 CVE (388 Web/8 mobile), 3 KEV. Tau-b CVSS–EPSS từ điểm gốc
0.30569771817081276. Recall@10/20/50: CVSS=0/0/1⁄3; EPSS=1/1/1, mẫu số chỉ 3.
KEV-first recall=null vì policy dùng KEV trực tiếp; không-KEV không phải nhãn âm khai thác.
Đây là mô tả snapshot, không phải kiểm định dự báo 30 ngày hay quan hệ nhân quả.

Context v2 có 15 cặp được rà nguồn: 10 affected có điều kiện và 5 needs_review.
Environmental có 10 dòng, queue giữ đủ 15: 8 patch/7 review. Không có cặp được xác
nhận unaffected thực tế. Nhiều CVE cùng API-01: không coi là nhiều triển khai độc lập,
không quy số cặp thành số thao tác vá hoặc chi phí. Chín CVE bổ sung đều có trong
cohort v1; ranking 396 ID không đổi. Các giả định của năm case đầu giữ nguyên.

| Case / asset | Base | EPSS | CVSS rank | EPSS rank | KEV-first rank | Env | Queue / rank context |
|---|---:|---:|---:|---:|---:|---:|---|
| 2018-25067 / WEB-01 | 7.2 | 0.00640 | 152 | 185 | 184 | 7.2 | patch / 5 |
| 2022-46177 / API-01 | 8.1 | 0.00679 | 55 | 171 | 171 | 8.8 | patch / 2 |
| 2023-22626 / ADMIN-01 | 7.5 | 0.00831 | 75 | 134 | 134 | 9.3 | patch / 8 |
| 2023-30470 / MOB-01 | 9.8 | 0.01249 | 11 | 86 | 86 | 9.8 | review_required / null |
| 2023-41387 / MOB-02 | 9.1 | 0.00874 | 30 | 128 | 127 | 9.8 | review_required / null |

Cả năm KEV=false trong catalog khóa; không suy chưa từng khai thác. Chúng thuộc
ML train, không dùng thay lỗi validation/held-out. Global rank dùng 396 CVE;
context rank dùng 8 patch pairs, không trừ trực tiếp hai loại rank khác population.

## 2. JoomGallery — CVE-2018-25067 / WEB-01

**Nguồn và applicability.** Website bán hàng giả định dùng Joomla/JoomGallery 3.3.3,
exposure internet. [Release 3.3.4](https://github.com/JoomGallery/JoomGallery/releases/tag/v3.3.4)
và [commit sửa SQL injection](https://github.com/JoomGallery/JoomGallery/commit/dc414ee954e849082260f8613e15a1c1e1d354a1)
được đối chiếu 2026-10-19. Dải <=3.3.3 lấy từ mô tả v1; release note riêng không
chứng minh toàn bộ dải. Affected có điều kiện theo component/version giả định,
không phải phát hiện cài đặt trên hệ thống thật.

**Cơ chế và tác động.** Cấu hình sắp xếp ảnh đi vào truy vấn SQL ở thành phần quản trị.
Phải kiểm plugin đang bật, đường tới cấu hình, quyền quản trị và quyền database.
Vector quan sát CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H, Base 7.2:
PR:H không cho phép diễn giải mọi người dùng Internet đều khai thác được.
Dữ liệu sản phẩm/đơn hàng có thể chịu tác động theo quyền thực có, không mặc định
SQL injection cho phép điều khiển toàn bộ hệ thống thanh toán.

**Bối cảnh và kết quả.** CR:M vì một phần sản phẩm công khai, IR:H vì độ đúng đơn hàng,
AR:H vì kênh bán hàng cần sẵn sàng. Environmental 7.2, không đổi Base sau làm tròn.
E/RL/RC và mọi Modified metric giữ X. Full vector lưu ở environmental_scores.csv;
không tự giảm MAV/impact do có WAF hoặc backup. Global rank 152/185/184 khác với
context rank 5/8; EPSS thấp không chứng minh vá lãng phí.

**Hành động.** Chủ ứng dụng Web cùng DBA xác nhận phiên bản và quyền, chọn bản còn
hỗ trợ chứa fix (3.3.4 là mốc lịch sử, không phải khuyến nghị cài bản cũ). Thử trên
staging, backup cấu hình/database và kiểm restore; kiểm gallery, sắp xếp ảnh,
phân quyền và luồng đặt hàng bằng test hợp lệ. Sau vá xác nhận build/fix và smoke
test, lưu log; nếu hồi quy thì rollback có kiểm soát và mở lại đánh giá rủi ro.
Không chạy payload SQL injection trên dịch vụ thật trong phạm vi đồ án.

## 3. Discourse — CVE-2022-46177 / API-01

**Nguồn và applicability.** Dịch vụ tài khoản giả định dùng Discourse stable 2.8.13,
internet. [GHSA-5www-jxvf-vrc3](https://github.com/discourse/discourse/security/advisories/GHSA-5www-jxvf-vrc3)
đọc 2026-10-19 ghi stable <=2.8.13, patched >2.8.13. Beta prose/table có khác biệt,
nên chỉ dùng stable. Applicability affected theo version; chưa xác minh một tổ chức
thật sử dụng Discourse làm tài khoản cho website/mobile.

**Cơ chế.** Email reset gửi tới địa chỉ cũ còn hiệu lực sau khi đổi email chính;
attacker có quyền mailbox cũ có thể dùng link. Cần kiểm vòng đời token,
email_token_valid_hours và luồng thay email. Vector v1
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N, Base 8.1; advisory có Base 5.7 và
AC:H/PR:H. Giữ bất đồng nguồn trong giới hạn, không thay nhãn v1 để hợp lý hóa kết quả.

**Bối cảnh và kết quả.** CR/IR/AR:H cho tài khoản/token và khả năng đăng nhập;
AR:H là yêu cầu tài sản, không biến A:N của lỗi thành A:H. Environmental 8.8,
mọi Modified/Temporal X. Global rank 55/171/171; context v2 rank 2,
env-first rank 3. Context là mô phỏng có điều kiện, không chứng minh takeover
đã xảy ra. Nhiều CVE mới cùng API-01 có thể được xử lý trong một kế hoạch nâng cấp,
không coi từng dòng là một lần downtime độc lập.

**Hành động.** Chủ dịch vụ tài khoản rà token/mailbox và cấu hình trước, thử reset
bằng tài khoản kiểm thử không chứa dữ liệu thật. Chọn bản vendor còn hỗ trợ chứa
toàn bộ fix của các CVE đã rà; 2.8.14 chỉ là mốc fix riêng lỗi này, không đủ kết
luận sửa mọi CVE của context v2. Backup database/config/secrets theo quy trình tổ
chức, kiểm migration/restore, login/reset/email-change và tương thích client.
Giảm vòng đời token chỉ là biện pháp tạm theo vendor, không thay điểm hoặc đóng
ticket thay cho vá. Không gửi reset tới người dùng thật trong thí nghiệm.

## 4. PgHero — CVE-2023-22626 / ADMIN-01

**Nguồn và applicability.** Dashboard PostgreSQL nội bộ giả định PgHero 3.0.1.
[Issue #439](https://github.com/ankane/pghero/issues/439), đọc 2026-10-19, ghi
affected 0.1.1–3.0.1, fixed 3.1.0. Đây là căn cứ chọn 3.0.1, không suy từ
mô tả before 3.1.0 rằng mọi bản trung gian đều affected.

**Cơ chế.** EXPLAIN có thể đưa dữ liệu truy vấn vào lỗi. Phạm vi dữ liệu đọc phụ thuộc
role database; khả năng đọc file máy chủ cần quyền bổ sung, không giả định
superuser. Base CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N=7.5. Advisory mô tả
PgHero user còn nguồn PR:N; cần kiểm authentication/deployment trước diễn giải,
không tự sửa PR của v1. Mạng nội bộ không có nghĩa attacker phải ở cùng mạng liền kề.

**Bối cảnh và kết quả.** CR:H vì dữ liệu vận hành/khách hàng, IR:H vì vai trò quản trị,
AR:M vì dashboard hỗ trợ vận hành. Environmental 9.3 nhờ CR, không thêm I/A khi
vector nguồn là N; MAV vẫn X. Global rank 75/134/134; context rank 8 do policy ưu
tiên exposure trước, env-first rank 2. Base-only/Env-only ranks trên cùng 8 cặp
lần lượt 2 và 1. Thay đổi thứ tự là sensitivity theo giả định, không có nghĩa
được phép bỏ qua patch dashboard nội bộ.

**Hành động.** DBA xác nhận component/version, quyền EXPLAIN, role DB và quyền đọc
log lỗi; chọn bản còn hỗ trợ chứa fix từ 3.1.0. Kiểm thử truy vấn quản trị hợp lệ,
tương thích PostgreSQL, role tối thiểu và không lộ dữ liệu qua lỗi. Backup cấu
hình, kiểm restore và cửa sổ rollback. API-02 cũng có candidate cùng CVE nhưng
product/version null: giữ needs_review, không gán affected/unaffected và không
tính Env. Chưa biết stack là việc kiểm kê cần hoàn tất, không phải lý do an toàn.

## 5. Hermes — CVE-2023-30470 / MOB-01

**Nguồn và applicability.** Android client React Native giả định nhúng Hermes trước
commit da8990f737ebb9d9810633502f65ed462b819c09, có chạy JS không tin cậy với
optimization. [CNA của Meta](https://cveawg.mitre.org/api/cve/CVE-2023-30470)
và [fix commit](https://github.com/facebook/hermes/commit/da8990f737ebb9d9810633502f65ed462b819c09)
đối chiếu 2026-10-19; trang Meta web bị chặn, không tuyên bố đã đọc được trang đó.
Phần lớn app React Native không affected nếu không thỏa đường thực thi trên.

**Cơ chế.** Suy luận không an toàn khi sinh bytecode có thể gây use-after-free và
thực thi mã. Chỉ tên React Native hay có kết nối backend chưa đủ chứng minh
affected. Cần lấy build/commit engine, dependency lock, cấu hình tối ưu và luồng
JS thực tế. Vector v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H=9.8;
không mặc định tác động client lan sang backend hoặc mọi thiết bị đều vulnerable.

**Bối cảnh và kết quả.** CR/IR:H cho tài khoản/đơn hàng, AR:M cho sẵn sàng client.
Environmental 9.8, mọi Modified/Temporal X. Global rank 11/86/86.
Dù có score và giả định affected, queue giữ review_required, rank null vì client
chưa có numeric exposure policy. Review không có nghĩa được hoãn vô thời hạn;
nó yêu cầu xác minh attack path trước quyết định có trách nhiệm.

**Hành động.** Nhóm mobile xác nhận commit fix trong engine thực đóng gói; không đoán
một version React Native được sửa chỉ từ số phiên bản framework. Chọn dependency
còn hỗ trợ chứa fix, rebuild và ký app theo quy trình thật, kiểm startup/login,
mua hàng, JS từ xa và tương thích engine trên thiết bị kiểm thử. Chuẩn bị staged
rollout, theo dõi crash và phương án dừng phát hành; không giả định có thể downgrade
store ngay hoặc client tự cập nhật tức thì. Chưa tích hợp case mobile riêng của N3;
case này do N2 tự hoàn thiện, không gán tác giả/xác nhận thay N3.

## 6. flutter_downloader — CVE-2023-41387 / MOB-02

**Nguồn và applicability.** iOS client Flutter giả định nhúng flutter_downloader
1.11.1. [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-41387) và
[changelog dự án](https://pub.dev/packages/flutter_downloader/changelog), đọc
2026-10-19: mô tả CNA ghi through 1.11.1; 1.11.2 có iOS security update.
Bảng product CNA không cụ thể, nên không suy dải từ bảng đó; đối chiếu mô tả và
dependency thực tế. Mốc fix lịch sử không thay việc chọn bản hiện còn hỗ trợ.

**Cơ chế.** SQL injection của downloader có thể ảnh hưởng token/file trong container.
Nhánh local còn phụ thuộc UIFileSharingEnabled và LSSupportsOpeningDocumentsInPlace.
Remote cần input tải do attacker kiểm soát; biết SDK tồn tại chưa chứng minh luồng
input đó reachable. Vector v1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H=9.1.
Mô tả có token theft còn nguồn C:N: ghi bất đồng, không tự đổi nhãn C.

**Bối cảnh và kết quả.** CR/IR:H, AR:M; Env=9.8, CR:H không tự biến C:N thành C:H.
Modified và Temporal X. Global rank 30/128/127. Queue review_required, rank null;
client không được gán internet hoặc exposure weight=0 để đưa vào cuối hàng.

**Hành động.** Nhóm mobile lấy lockfile/build SDK, kiểm platform iOS, quyền file-sharing
và luồng download, giữ dữ liệu xác thực khỏi log/test artifacts. Chọn bản còn hỗ
trợ chứa fix, kiểm download/pause/resume/storage và tương thích hệ điều hành;
test migration dữ liệu/rollback nếu có, staged rollout và tiêu chí dừng khi lỗi
file hoặc đăng nhập tăng. Không thực hiện SQLi/token theft để minh họa trên app
thật. Thời gian duyệt store/tỷ lệ cập nhật chưa đo, không hứa SLA phát hành đã đạt.

## 7. Kết luận và phần tích hợp còn chờ

Kết quả không chứng minh CVSS cao/EPSS thấp là vá lãng phí. CVSS đo severity;
EPSS/KEV và applicability/exposure bổ sung câu hỏi khác. Env có thể tăng score
mà queue chính vẫn xếp sau tài sản internet; client vẫn phải được xác minh.
Chỉ so Base/Env và hai context policies trên cùng 8 patch pairs.

Target 15 mapping đã đạt bằng nguồn cụ thể, không phải 15 cặp affected. Bốn CVE
Discourse mới giữ needs_review do SMTP/CSP hoặc xung đột source; API-02 unknown
là cặp thứ năm chưa tính Env. Không impute missing thành 0/false.

N1 đã tích hợp ngày 21/10: [case Web PgHero](cases/p3-web-n1.md),
[case mobile N3](cases/p3-mobile-n3.md), Decimal crosscheck MOB-02=9.8 và bộ hình
context-v2/8 patch pairs. Xem [nghiệm thu](phase-3-completion.md) và
[caption hiện hành](../reports/p3_figures.md). Báo cáo validation Phase 2 vẫn ở
reports/p2_validation_security_review.md, không trộn vào các case train.
