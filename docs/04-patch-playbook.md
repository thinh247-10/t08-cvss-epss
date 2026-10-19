# RQ4 — playbook xác minh và ưu tiên vá Web/mobile

Phiên bản tài liệu 2026-10-20, áp dụng mô phỏng context-v2. Đây là quy trình đề xuất
cho tổ chức thương mại điện tử giả định, chưa được chạy trên hệ thống thật.
Không coi rank là lệnh tự động triển khai bản vá.

## 1. Trigger, chủ trách nhiệm và đầu vào

Trigger: CVE/advisory mới; đổi version/config/đường tiếp cận; KEV được xác nhận;
dấu hiệu xâm nhập; thiếu dữ liệu; hoặc hết hạn ngoại lệ đã duyệt.
Đồ án dùng snapshot khóa, không cập nhật API khi mở báo cáo; triển khai thật phải
ghi nguồn/ngày mới và tạo revision riêng trước khi đánh giá lại.

| Vai trò giả định | Trách nhiệm |
|---|---|
| Chuyên viên bảo mật | xác minh advisory/range, triage, lập evidence và lý do priority |
| Chủ ứng dụng Web/API | kiểm version/config, staging, tương thích và triển khai |
| DBA | quyền database, backup/restore, migration và rollback |
| Nhóm mobile | dependency/build engine, signing, thiết bị thử, staged rollout |
| Chủ nghiệp vụ/change approver | cửa sổ bảo trì, chấp nhận rủi ro/ngoại lệ, duyệt thay đổi |
| Vận hành/incident response | theo dõi, xác nhận sau vá; xử lý sự cố nếu có dấu hiệu xâm nhập |

Đây là vai trò thiết kế, không phải đã phân công hay đã được N1/N3 phê duyệt.
Đầu vào gồm CVE/asset, product/build/version, advisory và ngày đọc, điều kiện affected,
Base/vector nguồn, EPSS date, KEV trạng thái/ngày, inventory requirements và exposure.

## 2. Quyết định applicability trước score

1. So khớp component, platform, version/commit và điều kiện kích hoạt với bằng chứng.
2. Unaffected có căn cứ: not_applicable, rank null, lưu lý do và trigger đánh giá lại.
3. Chưa rõ version/config hoặc nguồn mâu thuẫn: review_required; không đổi thành unaffected.
4. Affected nhưng client/unknown exposure, thiếu score/EPSS/KEV: review_required.
5. Chỉ affected và đủ tín hiệu với exposure được policy hỗ trợ mới vào patch queue.

Missing giữ null, không thành 0/false. Với client cần kiểm deep link/tệp/nội dung từ xa,
JS trust path hoặc đầu vào download; client không tự là internet/isolated.
Nếu KEV present dù còn unknown, mở việc xác minh sớm có owner; không bỏ khỏi queue.
Nếu có dấu hiệu xâm nhập, phối hợp incident response trước và song song remediation,
không đợi một rank số thấp/cao hay gọi patch là đã loại bỏ xâm nhập.

## 3. Policy, ngưỡng và thời hạn

Policy context-v1: KEV → exposure → Environmental → EPSS → CVE/asset.
Sensitivity context-v1-env-first đổi exposure/Env, cùng eligible pairs.
Không nhân EPSS×Base để gọi là Environmental. Chỉ dùng observed CVSS ở luồng chính;
ước lượng AI nếu thử riêng phải có predicted/model_version và không thay missing nguồn.

Ngưỡng CVSS>=7.0 và EPSS>=0.10 được khai báo trước thống kê B, chỉ để minh họa.
Không tối ưu ngưỡng từ 3 KEV, không biến bảng 2x2 thành nhãn exploit/accuracy hoặc
SLA đã được chứng minh. Không tự đặt ngưỡng Environmental để tách thêm bốn mức
Critical/High/Medium/Low khi chưa có quyết định nghiệp vụ.

**Thời hạn đề xuất, hoàn toàn là giả định vận hành:** review có KEV/dấu hiệu đáng
ngờ cần được chủ bảo mật tiếp nhận trong ngày làm việc; review khác trong 2 ngày
làm việc; việc lập kế hoạch patch trong 5 ngày làm việc sau khi applicability được
xác nhận. Không ấn định ngày hoàn thành vá phổ quát cho mọi dịch vụ/client.
Change approver phải ghi deadline thực, owner, cửa sổ triển khai và ngoại lệ trước
khi thực thi. Các mốc này chưa được đo, không phải chuẩn FIRST/CISA hoặc SLA thực tế
nhóm đã đạt; không suy “7.2 phải vá trong X giờ” từ kết quả.

## 4. Quy trình staging, backup và rollout

- Ghi ticket theo CVE–asset, liên kết nhóm CVE chung một component. Dedupe thao tác:
  10 CVE API-01 có thể cần một kế hoạch upgrade, không tính là 10 cửa sổ downtime.
- Lấy version/build từ package manager/lockfile/image/SBOM và runtime; không dùng
  tên vendor chung làm bằng chứng. Đối chiếu advisory stable/beta đúng nhánh.
- Chọn bản còn hỗ trợ chứa tất cả fix cần thiết; mốc fix lịch sử trong case không
  mặc định là bản nên cài hiện nay. Kiểm dependency, migration và compatibility matrix.
- Chụp cấu hình, backup dữ liệu theo phân loại nhạy cảm, kiểm restore bằng môi
  trường thử; xác định tiêu chí rollback và điểm không thể downgrade migration.
  Không gửi secrets/token/backups riêng tư trong ZIP nghiên cứu.
- Test staging với dữ liệu/tài khoản giả: startup, login/reset/email change,
  API contract với mobile, gallery/order, EXPLAIN permissions hoặc download lifecycle.
  Không dùng payload khai thác hay load DoS trên hệ thống thật trong đồ án.
- Có change approval trước khi thực thi; rollout theo pha nếu hỗ trợ, quan sát
  error rate/crash/login/giao dịch và cảnh báo dữ liệu; dừng nếu vượt tiêu chí do
  chủ dịch vụ khai báo. Đây là kế hoạch, không báo monitoring thật đã diễn ra.
- Rollback theo runbook đã thử; ghi lại version trở về, residual exposure và ngoại
  lệ mới. Với mobile, không giả định store cho downgrade ngay; có thể dừng rollout
  và triển khai forward fix, giữ compatibility backend trong thời gian client cũ tồn tại.

## 5. Xác nhận sau vá và đóng ticket

Chủ ứng dụng/DBA/mobile xác nhận version/commit thực chứa fix, dịch vụ hoạt động,
migration hoàn tất, phân quyền giữ đúng, test hợp lệ pass và log không lộ secrets.
Bảo mật đối chiếu lại applicability/advisory, evidence trước/sau và residual risks;
nếu cần kiểm tra kỹ thuật sâu thì phải có ủy quyền/phạm vi kiểm thử riêng.

Không đóng ticket chỉ vì “upgrade command success”, score giảm, WAF có rule hoặc
dashboard xanh. Lưu ngày triển khai/kiểm tra và người duyệt thật khi có; trước đó
trạng thái vẫn planned/review. Chỉ đo thời gian vá/gián đoạn/hiệu quả từ log vận hành
thật, không suy số giờ tiết kiệm hoặc sự cố ngăn chặn từ rank delta.

## 6. Ngoại lệ và biện pháp tạm thời

| Trường hợp | Xử lý và điều kiện thoát |
|---|---|
| Chưa có patch | rà hướng vendor, tắt tính năng/cô lập có kiểm soát nếu phù hợp; owner, deadline kiểm lại và risk acceptance |
| Không downtime | thử rolling/blue-green nếu kiến trúc hỗ trợ; nếu không, xin maintenance window và duyệt residual risk |
| Patch hồi quy/migration không đảo được | dừng rollout, kích hoạt kế hoạch restore/forward fix; không downgrade mù |
| Client chờ store/người dùng cập nhật | xác minh build bị ảnh hưởng, staged rollout/forward fix; theo dõi adoption khi có dữ liệu |
| Range nguồn mâu thuẫn | lưu cả nguồn/ngày/version, xin làm rõ vendor; giữ review_required, không sửa nhãn snapshot |
| API-02 thiếu stack | chủ dịch vụ cung cấp product/build/version; giữ review, không coi nội bộ là miễn vá |
| Control mới dự kiến | ghi proposed, chưa sửa Modified metric; chỉ tăng context revision sau khi có bằng chứng |

Biện pháp WAF/rate limit/CSP/backup chỉ là tạm nếu có căn cứ theo advisory và được
chủ dịch vụ kiểm thử; không tự hạ MAC/MAV/impact hay tuyên bố thay thế patch.
Ví dụ Discourse SMTP/CSP cần kiểm cấu hình; restored default CSP không tự thay
status nếu chưa xác minh đường bị ảnh hưởng và version. Mọi ngoại lệ cần owner,
lý do, residual risk, người duyệt và ngày tái xét; không được để vô thời hạn.

## 7. Áp dụng vào artifact hiện tại

Context-v2 giữ 15 cặp: 8 patch và 7 review. Năm case chi tiết trong
docs/analysis-results.md; hàng review gồm hai client, API-02 và bốn candidate
SMTP/CSP/range-conflict. Không ép họ có priority rank để “đủ bảng”.

CVE-2023-23621/API-01 đứng đầu patch theo cả hai context policies. PgHero từ
context rank 8 lên sensitivity rank 2 khi đổi thứ tự exposure/Env: giải thích
độ nhạy chứ không coi internal luôn ít quan trọng hơn. Nhiều CVE cùng Discourse:
cần kế hoạch upgrade chung, nhưng xác nhận fix riêng từng CVE sau triển khai.

RQ2 vẫn 396 ID/3 KEV, không trộn với 8 patch pairs. Báo KEV coverage@K và overlap
như chỉ số mô tả; không-KEV không phải false positive. N1/N3 còn kiểm tích hợp,
case độc lập và caption hình; không tự đánh dấu phê duyệt/thực thi thay họ.
