# Q&A bảo vệ demo — Phase 4

Bản N2 ngày 2026-10-21. Dùng dataset `t08-v1.0-20261010`, context
`phase3-context-v2`, inventory `phase1-v1`; đây là tổ chức giả định và snapshot
đã khóa, không phải khuyến nghị vận hành cho hệ thống thật. Số liệu được kiểm tại
[báo cáo nghiệm thu](../reports/p4_security_acceptance.md); chưa nghiệm thu demo N3.

## 1. Vì sao CVSS cao nhưng chưa chắc được vá trước?

CVSS đo severity, chưa xác nhận tài sản có component/version bị ảnh hưởng hoặc
đường tấn công có tồn tại. Queue của nhóm còn xét applicability, KEV, exposure,
Environmental và EPSS theo policy giả định. Chẳng hạn PgHero ADMIN-01 có Env 9.3
nhưng đứng thứ 8 trong queue chính; đây không phải quyền bỏ qua việc vá.

Nguồn: [case Web N1](cases/p3-web-n1.md), [playbook mục 2–3](04-patch-playbook.md).

## 2. EPSS là gì, 0.00874 có phải 0.874 percentile không?

EPSS là xác suất ước lượng một CVE bị khai thác trong 30 ngày tiếp theo tính từ
ngày chấm, không phải severity hay xác suất riêng cho hệ thống của nhóm.
Giá trị 0.00874 tương ứng 0.874%, còn percentile là vị trí tương đối của điểm
so với các CVE khác và là trường riêng. Nhóm dùng EPSS ngày 29/09/2026;
đối chiếu snapshot này không chứng minh dự báo tương lai đã được kiểm định.

Nguồn: [định nghĩa đã lưu trong tài liệu dự án](02-scoring-systems.md),
[bằng chứng snapshot, mục 2](../reports/p4_security_acceptance.md).

## 3. Không có trong KEV có nghĩa chưa từng bị khai thác không?

Không, false chỉ cho biết CVE không nằm trong catalog KEV của snapshot đã nhận.
KEV không phải danh sách đầy đủ mọi khai thác, nên không được coi các dòng false
là ground truth âm hoặc kết luận EPSS cao ở đó là false positive. Nếu có tín hiệu
xâm nhập trên hệ thống thật, cần xử lý incident song song xác minh/vá, không chờ rank.

Nguồn: [giải thích KEV](02-scoring-systems.md), [playbook mục 2](04-patch-playbook.md).

## 4. Vì sao EPSS và KEV có ba ngày khác nhau?

EPSS mang ngày chấm 29/09/2026, KEV phát hành lúc 30/09/2026 16:59:23.0688Z
và được tải lúc 01/10/2026 11:29:35.854976+00:00. Ngày phát hành catalog,
thời điểm tải và ngày chấm EPSS là ba khái niệm khác nhau, không phải lỗi tự động.
Nhóm công bố cả ba để người xem hiểu giới hạn và tái lập đúng input, không gọi
đây là một bộ dữ liệu đồng thời theo ngày hay cập nhật thời gian thực.

Nguồn: [nghiệm thu mục 2 — thời gian nguồn](../reports/p4_security_acceptance.md),
[caption](../reports/p3_figures.md).

## 5. EPSS Recall@50 đạt 3/3 thì có chứng minh EPSS luôn tốt hơn CVSS không?

Không, mẫu số chỉ 3 KEV trong 396 CVE, còn CVSS đạt 1/3 ở cùng K=50.
Đây là phép đối chiếu mô tả trên một snapshot/cohort, không đủ khái quát sang
tổ chức, thời gian hoặc CVE khác. Nhóm không có thí nghiệm đo hiệu quả vá hay
kiểm định dự báo tương lai để đưa ra kết luận đó.

Nguồn: [caption và giới hạn](../reports/p3_figures.md),
[kết quả ranking](../reports/p3_ranking_results.md).

## 6. Vì sao không dùng recall của KEV-first để chứng minh thắng?

KEV-first dùng chính is_kev để đưa CVE trong KEV lên trước, rồi EPSS, Base và ID
để sắp tiếp. Vì vậy dùng lại KEV làm nhãn đánh giá độc lập sẽ tạo kết luận vòng tròn.
Artifact giữ recall của policy này là null với lý do policy_uses_kev_directly;
giao diện phải hiện N/A, không biến thành 0 hoặc một cột thắng benchmark.

Nguồn: [artifact contract](phase-3-artifact-contract.md),
[UI contract](phase-4-ui-contract.md), [caption](../reports/p3_figures.md).

## 7. Vì sao mobile có Environmental 9.8 mà vẫn review?

MOB-02 là client iOS giả định có flutter_downloader 1.11.1, cần xác minh build,
luồng download và điều kiện truy cập dữ liệu cho từng nhánh tấn công.
Policy hiện tại chưa có quy tắc exposure số cho client nên giữ review_required,
priority rank null dù có Env 9.8. Review phải có owner và thời hạn xác minh,
không đồng nghĩa an toàn, được miễn vá hay tự gán exposure internet.

Nguồn: [case mobile N3 — narrative](cases/p3-mobile-n3.md),
[số liệu v2 đã kiểm](../reports/p4_security_acceptance.md),
[playbook](04-patch-playbook.md).

## 8. Environmental có phải xác suất khai thác hoặc Base nhân EPSS không?

Không, Environmental v3.1 là điểm severity theo yêu cầu C/I/A và các metric
môi trường/temporal được khai báo, không phải xác suất. Nhóm dùng CR/IR/AR từ
inventory giả định, còn Temporal và Modified metrics giữ X khi không có bằng chứng
để thay đổi. Không lấy exposure nội bộ, WAF hay backup làm lý do tự hạ MAV/impact.

Nguồn: [Environmental context](03-environmental-context.md),
[kiểm công thức](../reports/p3_environmental_check.md).

## 9. Vì sao 15 mapping không phải 15 hệ thống hoặc 15 lần vá?

Đơn vị mapping là cặp CVE–asset; một asset có thể xuất hiện ở nhiều CVE.
Nhiều dòng Discourse API-01 có thể được xử lý trong cùng một kế hoạch nâng cấp,
nhưng vẫn phải xác nhận fix cho từng CVE. Bộ v2 có 15 cặp, 10 điểm Environmental,
8 patch và 7 review, không được coi cả 15 là affected đã xác nhận thực tế.

Nguồn: [phân tích mục 1 và 7](analysis-results.md),
[playbook mục 4 và 7](04-patch-playbook.md).

## 10. Nếu AI sai thì sao, có thay CVSS quan sát bằng prediction không?

Không thay: observed và predicted phải có cột/vector và provenance riêng.
Ví dụ CVE-2023-38709 validation có observed Base 7.3, TF-IDF dự đoán 9.1,
severity rank 25 thành 2 trong tập chung 69 ID. Cần xem tám metric và bằng chứng
mô tả/advisory trước khi diễn giải sai khác, không sửa nhãn nguồn chỉ để hợp prediction.
Ranking chính 396 CVE vẫn dùng observed, còn nhận định nguyên nhân lỗi model chỉ
là giả thuyết khi chưa có attribution/ablation.

Nguồn: [review lỗi validation](../reports/p2_validation_security_review.md),
[AI rank impact](../reports/p3_prediction_rank_impact.md).

## 11. Vì sao TF-IDF tốt hơn DistilBERT ở metric này?

Phải nói rõ metric và population: trên validation toàn ML, mean macro-F1 là
0.750431 so với 0.734138, nhưng đây không chứng minh nguyên nhân hay ưu thế kiến trúc.
Trên 108 CVE Web test, DistilBERT lại có Base MAE thấp hơn: 1.509259 so với
1.750926, và phân tích rank test cũng cho tau-b cao hơn. Một seed, cấu hình
DistilBERT một epoch và dữ liệu hiện có chỉ cho phép báo kết quả lần chạy;
chưa đủ chứng minh thiếu train, truncation hay kiến trúc là nguyên nhân chênh lệch.

Nguồn: [báo cáo DistilBERT](../reports/p2_distilbert_run.md),
[bảng model comparison](../reports/p2_model_comparison.csv),
[AI rank impact](../reports/p3_prediction_rank_impact.md).

## 12. Vì sao không trình diễn prediction held-out cho MOB-02?

CVE-2023-41387 thuộc train trong release khóa nên không thể dùng prediction train
để giả một ví dụ validation/test. Giao scoped held-out hiện có 69 validation và
108 test, đều Web, nên chưa có căn cứ khái quát chất lượng mô hình sang mobile.
Demo giữ mobile ở phần case/context và dùng một CVE validation khác cho AI,
không ghép train vào chỉ để lấp đủ 396 prediction.

Nguồn: [case mobile](cases/p3-mobile-n3.md),
[UI contract](phase-4-ui-contract.md), [AI impact](../reports/p3_prediction_rank_impact.md).

## 13. Tại sao API-02 không có điểm và vì sao sort/filter không đổi rank nguồn?

API-02 chưa biết product/version nên applicability chưa đủ bằng chứng,
Environmental và priority rank phải là N/A có lý do, không phải 0.
Sort/filter chỉ đổi phần đang xem; rank gốc vẫn thuộc cohort hoặc population
được công bố và không tự tính lại sau lọc. Nếu muốn một phân tích trên population
mới, phải ghi rõ phạm vi và revision, không gọi đó là top-50 gốc.

Nguồn: [UI contract](phase-4-ui-contract.md),
[case PgHero](cases/p3-web-n1.md), [playbook](04-patch-playbook.md).

## 14. Chưa có patch hoặc không được downtime thì xử lý thế nào?

Chủ dịch vụ cùng bảo mật đánh giá biện pháp tạm có căn cứ vendor, khả năng rolling
hoặc cửa sổ bảo trì, rồi ghi owner, residual risk, người duyệt và hạn tái xét.
Nếu kiến trúc không cho zero downtime thì không hứa rolling sẽ giải quyết được,
còn khi chưa có patch thì không đóng ticket chỉ vì có WAF hay backup.
Mọi biện pháp tạm cần kiểm tác dụng/ảnh hưởng và điều kiện thoát ngoại lệ,
không tự đổi Modified metrics hoặc dữ liệu snapshot.

Nguồn: [playbook mục 4–6](04-patch-playbook.md).

## 15. Làm sao biết vá xong, các mốc SLA có bắt buộc không?

Phải xác nhận build chứa fix, kiểm version/applicability, regression, phân quyền,
migration và bằng chứng sau vá; lệnh upgrade thành công chưa đủ đóng ticket.
Backup phải có kế hoạch restore/rollback đã thử, còn mobile có thể cần dừng rollout
hoặc forward fix thay vì giả định store cho downgrade ngay.
Các mốc tiếp nhận/lập kế hoạch trong playbook là giả định do nhóm đề xuất,
không phải chuẩn bắt buộc hay SLA đã đạt; nhóm chưa đo mức giảm rủi ro thực tế.

Nguồn: [playbook mục 3–6](04-patch-playbook.md).

## Ghi chú cho người trình bày

Các nguồn dự án dẫn advisory/spec khi cần truy nguyên, không yêu cầu gọi mạng
trong demo. Case mobile N3 còn link r1/context-v1 lịch sử: số liệu hiện hành lấy
từ staging v2 và báo cáo nghiệm thu, không dùng link r1 để thay input mới.
Đây là nội dung chuẩn bị Q&A, không phải biên bản câu hỏi đã được diễn tập.
