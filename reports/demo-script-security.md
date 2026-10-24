# Lời thoại bảo mật — demo Phase 4 khoảng 6 phút

> Cập nhật 2026-10-23: N3 đã ghép thao tác vào `reports/demo-script-n3.md` trên
> branch `feat/p4-demo` commit `4c15746`. N2 đã chạy đủ các flow, kiểm vector AI
> và ba mode live/saved/no-AI; xem mục 5 báo cáo nghiệm thu. Các ghi chú chưa có
> demo/panel bên dưới ghi trạng thái lúc soạn 21/10, không còn là blocker kỹ thuật.
> Người thật diễn tập đo thời lượng và N1 chốt script chung vẫn pending.

Bản N2 ngày 2026-10-21, để N1 ghép script cuối và N3 ghép thao tác.
**Đã soạn, chưa diễn tập đo thời gian.** Các mốc dưới là ngân sách dự kiến,
không phải thời lượng đo. Không xác nhận notebook/CLI đã chạy.

## Chuẩn bị và nguồn dùng chung

- Dataset `t08-v1.0-20261010`, cohort 396 CVE; context `phase3-context-v2`,
  inventory `phase1-v1`, ranking policy `cvss-epss-kev-first-v1`, queue `context-v1`.
- Chỉ mở dữ liệu trong staging đã xác minh:
  `data/processed/p3_received_20261021/`. Trong các mục dưới, đường dẫn bắt đầu
  `data/processed/p3_n2`, `p3_n3`, `reports/figures/phase3` là tương đối với staging.
  Không mở nhầm output Phase 3 cũ còn trên máy.
- Dữ liệu/score/rank đã đối chiếu tại [báo cáo nghiệm thu mục 2](p4_security_acceptance.md).
  Receipt: [gói N1](../docs/handoffs/phase-3-complete-20261021.json).
- Màn hình mục tiêu là CLI/notebook N3. Chưa có demo trên checkout hiện tại:
  các tên view dưới là yêu cầu nội dung, không phải tên lệnh/cell đã triển khai.
  Khi N3 giao, lấy lệnh thật từ `docs/demo-commands.md`, không tự bịa lệnh.
- Mở sẵn ảnh top-50 cả hai trang, overlap, context và queue; chuẩn bị CSV read-only.
  Các file này là phương án trình bày dự phòng, không thay bằng chứng chạy demo offline.

## 0:00–0:45 — Phạm vi và câu hỏi (N1/N2)

**Mở:** view tổng quan; dự phòng `data/processed/p3_n2/ranking_metrics.json`
và [biên bản Phase 3](../docs/phase-3-completion.md).

**Lời thoại:**

> Nhóm xem xét câu hỏi: có nhiều lỗ hổng thì nên xác minh và vá cái nào trước?
> Tập so sánh gồm 396 CVE, với 388 Web và 8 mobile; chỉ có 3 CVE trong KEV.
> EPSS mang ngày 29/09/2026, KEV phát hành ngày 30/09 và tải ngày 01/10 UTC.
> Đây là các mốc nguồn khác nhau, không phải dữ liệu thời gian thực.
> Inventory tổ chức là giả định. Chúng em phân biệt mức độ nghiêm trọng,
> tín hiệu khai thác và quyết định hành động trên từng tài sản.

## 0:45–2:00 — Ba top-50 và overlap (N2)

**Mở:** `reports/figures/phase3/top50_three_policies_p1.png`, rồi
`top50_three_policies_p2.png` và `topk_overlap.png`.
Nguồn chính xác: `data/processed/p3_n3/top50_long.csv`,
`data/processed/p3_n2/overlap.csv`, `topk_metrics.csv`;
[caption](p3_figures.md).

**Chỉ vào:** CVE-2023-23752, Base 5.3, EPSS 0.99827, KEV=true,
EPSS/KEV-first rank 3. Đây là ví dụ ranking, không khẳng định asset nào affected.

**Lời thoại:**

> Ba cột dùng cùng 396 CVE. CVSS Base đo severity, EPSS là xác suất khai thác
> theo mô hình EPSS; KEV-first là chính sách đưa tín hiệu đã khai thác lên trước.
> Ví dụ CVE-2023-23752 có Base 5.3 nhưng đứng thứ ba theo EPSS và KEV-first.
> Vì thế chỉ sắp theo Base có thể trả lời khác câu hỏi ưu tiên xác minh khai thác.
> Hai trang chứa đủ vị trí 1 đến 50, không chỉ 25 dòng đầu.
> CVSS và EPSS chỉ chung 10 CVE trong top-50: Jaccard là 10 chia 90, khoảng 0.111.
> CVSS top-50 chứa 1 trong 3 KEV, EPSS chứa cả 3. Mẫu chỉ ba KEV nên không kết luận
> EPSS luôn tốt hơn hoặc đã kiểm định dự báo tương lai. Không dùng recall của
> KEV-first để chứng minh thắng vì chính sách này dùng KEV trực tiếp.
> Khi hòa Base, ID tăng dần phá hòa; đó không phải bằng chứng CVE đứng trước nguy hiểm hơn.

## 2:00–3:30 — PgHero và Discourse: severity khác queue (N2)

**Mở:** view bối cảnh/hành động; dự phòng `data/processed/p3_n2/context_comparison.csv`,
`priority_queue.csv`, `priority_queue_env_first.csv`, `environmental_scores.csv`.
Case: [PgHero của N1](../docs/cases/p3-web-n1.md),
[Discourse, mục 3](../docs/analysis-results.md).

**Chọn:** CVE-2023-22626 / ADMIN-01, rồi CVE-2022-46177 / API-01.

**Lời thoại:**

> Với PgHero, trước tiên phải xác nhận component, version và quyền truy cập.
> ADMIN-01 giả định dùng bản 3.0.1 trong mạng nội bộ. Base quan sát là 7.5;
> yêu cầu bảo mật dữ liệu CR:H làm Environmental tăng lên 9.3.
> Trên cùng tám cặp patch, severity rank từ Base thứ hai thành Environmental thứ nhất.
> Nhưng queue chính xếp nó thứ tám vì policy xét exposure trước Environmental.
> Đổi policy sensitivity để xét Environmental trước thì nó lên thứ hai.
> Đây là ảnh hưởng của giả định chính sách, không phải kết luận mạng nội bộ an toàn.
> Cùng CVE ở API-02 chưa biết product/version nên phải review, Environmental là N/A.
> Discourse API-01 giả định dùng stable 2.8.13, Internet; Base 8.1 tăng thành
> Environmental 8.8 với CR/IR/AR:H và đứng thứ hai trong queue chính.
> Vector quan sát khác advisory; chúng em giữ nguồn và nêu bất đồng, không tự đổi nhãn.
> Environmental là severity theo bối cảnh, không phải xác suất khai thác.

**Nguồn đã rà trong case:** PgHero issue #439; Discourse GHSA-5www-jxvf-vrc3.
Không mở mạng để cập nhật dữ liệu giữa demo; nguồn chi tiết có trong case.

## 3:30–4:30 — Mobile vẫn review dù điểm cao (N2)

**Mở:** CVE-2023-41387 / MOB-02 trong view bối cảnh/hành động;
dự phòng `data/processed/p3_n2/priority_queue.csv` và
[case mobile N3](../docs/cases/p3-mobile-n3.md).

**Lời thoại:**

> MOB-02 là client iOS giả định nhúng flutter_downloader 1.11.1,
> không phải backend được đổi tên thành mobile. Cần kiểm dependency thực đóng gói,
> luồng input download và cấu hình chia sẻ file cho nhánh local.
> Base nguồn là 9.1, EPSS 0.00874; Environmental bằng 9.8.
> Tuy vậy queue vẫn review_required và priority rank N/A vì policy chưa có
> quy tắc exposure số cho client. Không biến client thành Internet để có thứ hạng.
> Review là yêu cầu xác minh đường tấn công, không phải cho phép bỏ qua vá.
> Bản 1.11.2 là mốc fix lịch sử; triển khai thật phải chọn bản còn hỗ trợ chứa fix.
> CVE này nằm train, nên không có prediction held-out để đánh giá AI cho case này.

**Ghi chú người trình bày:** case N3 còn link r1 và tên context-v1 lịch sử.
Chỉ dùng narrative có nguồn; bảng số/context hiện hành lấy từ staging v2 đã kiểm.
Không mở đường dẫn r1 trong demo hoặc gọi nó là context hiện hành.

## 4:30–5:20 — AI hỗ trợ và sai số (N3)

**Mở:** panel observed/predicted riêng; dự phòng
`data/processed/p3_n3/predicted_rank_comparison.csv`, lọc
CVE-2023-38709, `split=validation`, `model=tfidf`.
Nguồn: [phân tích AI](p3_prediction_rank_impact.md).

**Lời thoại chuyển cho N3:**

> Đây là ví dụ validation, không phải case mobile vừa xem. CVE-2023-38709 có
> Base quan sát 7.3 nhưng TF-IDF dự đoán 9.1. Trong tập validation chung 69 CVE,
> severity rank quan sát là 25, dự đoán là 2: delta bằng 23.
> Sai số có thể làm đổi thứ tự severity; prediction không thay thế nhãn quan sát.
> Validation và test phải xem riêng, không dùng test để chỉnh mô hình.
> Đây là kết quả đã lưu, không phải inference vừa chạy; nó không đo hiệu quả vá.

**N3 bổ sung khi ghép demo:** hiện đủ 8 metric AV/AC/PR/UI/S/C/I/A và vector của
prediction đã xác minh từ gói Phase 2, cạnh vector quan sát tương ứng.
Gói comparison Phase 3 chỉ có score/rank, không suy ngược vector từ score 9.1.
Chưa xác minh file Phase 2/vector này trên máy N2 trong bước B, do đó chưa đánh dấu
panel vector đạt. Nếu chọn inference thật, N3 ghi mode/model version và dùng output
thực chạy; không nói output vừa chạy nếu đang mở CSV dự phòng.

## 5:20–6:00 — Quyết định và giới hạn (N1/N2)

**Mở:** queue đầy đủ và [patch playbook](../docs/04-patch-playbook.md).

**Lời thoại:**

> Kết quả là 15 cặp CVE–asset, không phải 15 hệ thống hay 15 lần nâng cấp độc lập.
> Có tám cặp patch và bảy cặp review; nhiều CVE cùng Discourse có thể chung kế hoạch vá.
> Trước hành động phải xác minh ảnh hưởng, chọn bản sửa phù hợp, backup và thử rollback,
> kiểm staging rồi xác nhận sau vá. Ngưỡng và SLA chỉ là đề xuất cho tổ chức giả định.
> Nhóm chưa đo giảm rủi ro hay thời gian vá thực tế. AI và các tín hiệu giúp người
> phân tích đặt câu hỏi; quyết định cuối vẫn cần bằng chứng tài sản và người chịu trách nhiệm.

## Gate diễn tập và bàn giao N1/N3

- [x] Sáu đoạn có nội dung, CVE, file/view và nguồn; không thêm CVE ngoài cohort.
- [x] Các số dùng trong lời thoại đối chiếu artifact hiện hành; không sửa ranking theo demo.
- [x] Case bảo mật chọn từ năm case đã có (PgHero, Discourse, MOB-02).
  Ví dụ validation AI riêng, không giả là một case mobile held-out.
- [ ] N3 xác nhận lệnh/cell thật và panel vector/score từ prediction đã verify.
- [ ] N1 ghép với script chung, chốt người dẫn và thao tác chuyển màn hình.
- [ ] Diễn tập đo thật: ghi ngày, người nói/thao tác, commit, mode, thời gian từng đoạn,
  tổng thời lượng, lỗi và phần cần rút. Hiện chưa có số đo.
- [ ] N2 nghiệm thu nội dung trên demo thực chạy ở bước D.

Chỉ hoàn thành phần soạn B; chưa gọi B hoàn tất diễn tập hoặc toàn Phase 4 hoàn tất.
