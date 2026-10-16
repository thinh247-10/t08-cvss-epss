# Khung phân tích bảo mật — Phase 2 N2

Ngày rà: 2026-10-12; người rà: CanhLai. Trạng thái: đã chuẩn bị khung năm case,
chờ phân tích Environmental/policy ở Phase 3. Đây là tổ chức thương mại điện tử
giả định, không có đánh giá hay khai thác trên hệ thống thật.

## 1. Dữ liệu và cách đọc

- Dataset `t08-v1.0-20261010`; context/inventory `phase1-v1`.
- Mapping nguồn: `data/processed/phase1_v1_20261010/cve_asset_mapping.csv`, SHA-256
  `55056d3a74bf1222f832d98caef651af2ecacd19f5194c74c6ad62a69a6b4afb`.
- Inventory: bản trong gói v1 và `config/assets.yaml` hiện tại.
- Tín hiệu quan sát lấy từ master v1; rank từ `data/processed/rankings.csv`,
  policy `cvss-epss-kev-first-v1`, cohort `t08-v1.0-20261010:ranking` (396 CVE).
- EPSS ngày 2026-09-29; KEV catalog phát hành 2026-09-30, tải 2026-10-01 UTC.
  Cả năm case không nằm trong catalog đã tải; điều này không chứng minh chưa bị khai thác.
- Năm case được chọn theo mapping và coverage Web/mobile; có chủ đích, không dùng
  để ước lượng tỷ lệ toàn bộ CVE hoặc lựa scope từ EPSS/KEV.
- Cả năm có `scope_status=included`, thuộc ranking cohort và ML split `train`.
  Vì vậy không dùng chúng làm ví dụ lỗi validation hoặc đánh giá held-out của NLP.

| CVE / tài sản | Base nguồn | EPSS | CVSS rank | EPSS rank | KEV-first rank |
|---|---:|---:|---:|---:|---:|
| CVE-2018-25067 / WEB-01 | 7.2 | 0.00640 | 152 | 185 | 184 |
| CVE-2022-46177 / API-01 | 8.1 | 0.00679 | 55 | 171 | 171 |
| CVE-2023-22626 / ADMIN-01 | 7.5 | 0.00831 | 75 | 134 | 134 |
| CVE-2023-30470 / MOB-01 | 9.8 | 0.01249 | 11 | 86 | 86 |
| CVE-2023-41387 / MOB-02 | 9.1 | 0.00874 | 30 | 128 | 127 |

Điểm/vector bên dưới là nhãn được chọn trong v1, nguồn `nvd@nist.gov`. Chênh lệch
rank chỉ mô tả artifact sơ bộ; chưa là kết luận trì hoãn vá hoặc hiệu quả policy.
Các URL dự án/vendor bên dưới được mở ngày 2026-10-12.

## 2. CVE-2018-25067 — WEB-01 / JoomGallery

- Phần mềm giả định: Joomla với JoomGallery 3.3.3, exposure `internet`.
- Bằng chứng: [release 3.3.4](https://github.com/JoomGallery/JoomGallery/releases/tag/v3.3.4)
  và [commit sửa SQL injection](https://github.com/JoomGallery/JoomGallery/commit/dc414ee954e849082260f8613e15a1c1e1d354a1).
  Release xác nhận phiên bản phát hành; mô tả CVE trong v1 xác định <=3.3.3 affected,
  sửa ở 3.3.4. Không coi release note ngắn là toàn bộ advisory.
- Cơ chế: dữ liệu cấu hình sắp xếp ảnh đi vào truy vấn SQL trong thành phần quản trị.
  Cần rà đường xử lý và quyền quản trị tương ứng; đây không phải kết luận mọi người
  dùng Internet đều khai thác được. Applicability `affected` theo mapping v1 khi
  đúng thành phần/phiên bản giả định, chưa kiểm tra trên hệ thống thật.
- Vector nguồn: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`.
  PR:H phản ánh quyền cao; tác động nguồn C/I/A đều H.
- CR:M vì dữ liệu sản phẩm có phần công khai; IR:H vì tính đúng đắn đơn hàng;
  AR:H vì website là kênh tiếp nhận đơn. Đây là yêu cầu tài sản, không chứng minh
  SQL injection đã ảnh hưởng toàn bộ hệ thống đơn hàng.
- Cần xác minh tiếp: plugin đang bật, quyền tới cấu hình và quyền database của ứng dụng.
  Nguồn chỉ ra phiên bản sửa 3.3.4; kế hoạch vá/kiểm tra tương thích chờ Phase 3.

## 3. CVE-2022-46177 — API-01 / Discourse

- Phần mềm giả định: Discourse stable 2.8.13 làm dịch vụ tài khoản, exposure `internet`.
- Nguồn: [GHSA-5www-jxvf-vrc3](https://github.com/discourse/discourse/security/advisories/GHSA-5www-jxvf-vrc3).
  Bảng affected của advisory ghi stable <=2.8.13; stable 2.8.14 nằm phía đã sửa.
  Prose và bảng phiên bản beta khác nhau, nên case này dùng stable theo mapping v1.
- Cơ chế: link reset gửi tới email cũ vẫn dùng được sau khi đổi email chính. Nếu
  mailbox cũ bị chiếm hoặc đổi chủ, link còn hiệu lực có thể dẫn tới takeover.
  Applicability `affected` theo version; đường tấn công còn phụ thuộc vòng đời token
  và quyền truy cập email cũ. Cần kiểm `email_token_valid_hours` trong kịch bản.
- Vector v1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`, Base 8.1.
  Advisory công bố vector AC:H/PR:H và 5.7. Ghi bất đồng nguồn để đối chiếu;
  giữ nguyên nhãn v1, không tự thay bằng điểm advisory để tính ranking.
- CR/IR/AR:H vì tài sản xử lý tài khoản và token, cần bảo vệ truy cập và duy trì
  đăng nhập. AR:H là yêu cầu nghiệp vụ; A:N trong vector là tác động của CVE.
- Cần xác minh email/token và tích hợp dịch vụ tài khoản; chưa chứng minh website
  và mobile client của một tổ chức thật dùng Discourse. Ưu tiên vá chờ Phase 3.

## 4. CVE-2023-22626 — ADMIN-01 / PgHero

- Phần mềm giả định: PgHero 3.0.1, dashboard PostgreSQL nội bộ, exposure `internal`.
- Nguồn: [issue chính thức #439](https://github.com/ankane/pghero/issues/439), xác nhận
  affected 0.1.1–3.0.1, sửa 3.1.0. Dùng 3.0.1 đã hiệu chỉnh trong v1.
- Cơ chế: người dùng PgHero lợi dụng EXPLAIN để làm kết quả truy vấn xuất hiện trong
  thông báo lỗi. Quyền database quyết định dữ liệu có thể đọc; quyền superuser còn
  có thể mở đường đọc file máy chủ. Không giả định database user có superuser.
- Applicability `affected` theo version; cần ghi riêng quyền truy cập dashboard và
  database. Vector nguồn: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.
  Advisory nói người dùng PgHero, còn nhãn nguồn là PR:N: cần đối chiếu cách triển
  khai/xác thực trước diễn giải, không sửa ground truth từ tên vai trò.
- CR:H vì có thể tiếp cận dữ liệu quản trị/khách hàng; IR:H vì quyền vận hành cao;
  AR:M vì dashboard hỗ trợ vận hành. Vector của lỗi này chỉ có C:H.
- Mạng nội bộ không đủ căn cứ thay MAV. Cần rà quyền database và quyền xem EXPLAIN;
  nguồn hướng tới bản sửa 3.1.0, quyết định vận hành chờ Phase 3.

## 5. CVE-2023-30470 — MOB-01 / Hermes trong React Native

- Phần mềm giả định: mobile client Android nhúng Hermes trước commit
  `da8990f737ebb9d9810633502f65ed462b819c09`, exposure `client`.
- Nguồn: [Meta advisory](https://www.facebook.com/security/advisories/cve-2023-30470)
  và [commit dự án](https://github.com/facebook/hermes/commit/da8990f737ebb9d9810633502f65ed462b819c09).
- Cơ chế theo advisory/mô tả v1: suy luận sai khi tối ưu bytecode có thể dẫn tới
  use-after-free và thực thi mã. Phải có JavaScript không tin cậy được thực thi
  với tối ưu bật; phần lớn ứng dụng React Native không bị ảnh hưởng.
- Mapping `affected` có điều kiện: kịch bản giả định thỏa cả build trước fix và
  đường thực thi untrusted JS. Chỉ biết ứng dụng dùng React Native chưa đủ.
  Cần xác minh commit/build engine, tùy chọn tối ưu và nguồn JS.
- Vector nguồn: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
- CR/IR:H vì client xử lý tài khoản và đơn hàng; AR:M vì sự cố client ảnh hưởng
  người dùng thiết bị. Chưa chứng minh tác động lan sang backend.
- Trạng thái policy dự kiến: **`review_required`**, priority rank để trống vì
  exposure client chưa có quy tắc số. Commit fix là mốc đối chiếu; chưa tự suy ra
  một phiên bản React Native đã sửa hoặc kết luận thứ tự vá.

## 6. CVE-2023-41387 — MOB-02 / flutter_downloader trên iOS

- Phần mềm giả định: Flutter client iOS nhúng `flutter_downloader` 1.11.1;
  exposure `client`.
- Nguồn: [changelog dự án](https://pub.dev/packages/flutter_downloader/changelog)
  ghi security update iOS ở 1.11.2. Dải affected <=1.11.1 và cơ chế chi tiết dùng
  mô tả CVE/mapping v1; changelog ngắn không chứng minh tất cả điều kiện khai thác.
- Cơ chế trong v1: SQL injection vào dữ liệu downloader có thể tác động token/file
  trong container ứng dụng. Kịch bản remote giả định ứng dụng nhận input tải file
  do attacker kiểm soát. Nhánh local còn cần kiểm các thuộc tính
  `UIFileSharingEnabled` và `LSSupportsOpeningDocumentsInPlace`.
- Mapping `affected` khi đúng component/version và điều kiện input giả định;
  cần xác minh luồng download và cấu hình iOS trước khi coi là đánh giá thực tế.
- Vector nguồn: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`.
  Mô tả có khả năng lấy token nhưng nhãn nguồn C:N: ghi điểm cần đối chiếu nguồn,
  giữ nguyên vector v1 cho phân tích quan sát.
- CR/IR:H do tài khoản và dữ liệu đơn hàng; AR:M do phạm vi gián đoạn client.
  Yêu cầu CR:H không tự biến tác động C:N thành C:H.
- Trạng thái policy dự kiến: **`review_required`**, priority rank để trống;
  rà bản sửa 1.11.2 và kiểm thử tương thích khi làm kế hoạch Phase 3.

## 7. Phần chờ phân tích và chờ N3

| Cặp | Environmental vector | Environmental score | Priority rank |
|---|---|---|---|
| CVE-2018-25067 / WEB-01 | — Chờ Phase 3 | — Chưa tính | — Chưa xếp hàng bối cảnh |
| CVE-2022-46177 / API-01 | — Chờ Phase 3 | — Chưa tính | — Chưa xếp hàng bối cảnh |
| CVE-2023-22626 / ADMIN-01 | — Chờ Phase 3 | — Chưa tính | — Chưa xếp hàng bối cảnh |
| CVE-2023-30470 / MOB-01 | — Chờ Phase 3 | — Chưa tính | — `review_required` cho client |
| CVE-2023-41387 / MOB-02 | — Chờ Phase 3 | — Chưa tính | — `review_required` cho client |

Modified Metrics chưa có bằng chứng thay đổi sẽ giữ X; Temporal không đánh giá
sẽ dùng E/RL/RC:X khi triển khai. Không suy các metric này từ exposure, EPSS hoặc KEV.

**Cập nhật 2026-10-15 — đã nhận lỗi validation từ N3:** branch
`feat/p2-nlp-baseline`, commit `a5c0c16`. N2 đã đối chiếu v1 và review 13 CVE
trong `reports/p2_validation_security_review.md`; phần này không còn chờ N3.
Prediction đầy đủ/model artifact cho reproduction của N1 vẫn là bàn giao riêng.
Đã đếm validation v1: 19.606 CVE, 69 Web, 0 mobile. Các case mobile ở train
không được dùng thay lỗi validation. N3 tổng hợp báo cáo review vào model card.
