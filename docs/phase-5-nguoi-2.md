# Phase 5 — Người 2: bảo mật, case và lập luận ưu tiên vá

Giao25/10/2026, dự kiến6giờ. Có thể viết ngay trên dữ liệu đã khóa.
Phase4 còn cần xác nhận runbook cuối và diễn tập thật, không ghi đã hoàn thành thay nhóm.

## 1. Nhận việc và branch

Đọc [kế hoạch chung](phases/phase-5-bao-cao-va-bao-ve.md),
[nghiệm thu Phase3](phase-3-completion.md), [checklist](../reports/release-checklist.md).
Giữ ownvenv; dùng lại Phase1/2/3 đúng receipt. Viết tài liệu không cần train,
APIkey hay Torch. Cần kiểm demo thì theo [runbook](runbook.md).

```powershell
git status --short
git switch develop
git pull --ff-only origin develop
git switch -c docs/p5-security-section
```

Lưu sửa riêng trước khi switch, không reset. Nếu branch đã có thì switch branch đó.
Không sửa `reports/final-report.md` hoặc `reports/slides-outline.md`: N1/N3 sở hữu.

## 2. File phải tạo

| File | Làm gì | Người nhận |
|---|---|---|
| `reports/sections/security.md` | Nội dung hoàn chỉnh cho phần bảo mật báo cáo: lý thuyết, ranking, context, 3–5case, kết luận/giới hạn | N1 ghép báo cáo |
| `reports/p5-security-slides.md` | Nội dung slide3–6, hình thật, lời nói, câu hỏi; tối đa2case trình bày trực tiếp | N3 ghép slide |
| `reports/p5-security-review.md` | Bảng claim→artifact/nguồn, lỗi phát biểu phát hiện và trạng thái sửa | N1/N3 kiểm trước nộp |

Chỉ sửa `docs/03-environmental-context.md`, `docs/04-patch-playbook.md` nếu phát
hiện thiếu/không nhất quán, ghi lý do. Không sửa số trong CSV hoặc thuật toán để khớp lời nói.

## 3. Bước A — phần báo cáo (2giờ)

Đọc `docs/01-research-questions.md` để dùng đúng tên RQ, và:
`docs/02-scoring-systems.md`, `docs/analysis-results.md`, `docs/cases/`,
`reports/p3_figures.md`, `reports/p3_review_n1.md`, `reports/p4_security_acceptance.md`.
Dữ liệu chuẩn là Phase3 integrated context-v2, không r1/stepB cũ.

Viết theo thứ tự:

1. Bài toán Web/mobile và lý do severity chưa quyết định ưu tiên vá.
2. CVSS, EPSS, KEV đo gì; KEV-first là policy, không phải điểm liên tục của KEV.
3. Cohort396,3KEV; ba rule sort/tie-break theo code và contract hiện hành.
4. Kết quả top10/20/50, overlap/Jaccard/tau-b, đọc mẫu số rõ ràng.
5. Bối cảnh tài sản: applicability, exposure, CR/IR/AR, Environmental và queue.
6. Case, hành động, giới hạn và trả lời RQ tương ứng bằng chứng.

Con số để kiểm lại: top50CVSS/EPSS chung10, Jaccard10/90; tau-b khoảng0.3057.
CVSS top50 chứa1/3KEV, EPSS3/3; KEV-first recall để N/A vì policy dùng trực tiếpKEV.
Không diễn giải3/3 là mô hình dự báo hoàn hảo. Các ngày EPSS/KEV khác nhau.
15mapping,10Env,8patch,7review là cặp CVE–asset; không phải15CVE hay15deployment.

## 4. Bước B — case và playbook (1giờ)

Chọn3–5case đã có bằng chứng, tối thiểu1Web và1mobile SDK/client/framework.
Gợi ý PgHero ADMIN-01, Discourse API-01, MOB-02, cùng trường hợp API-02 thiếu dữ kiện.
Không coi backend của app là case mobile client duy nhất.

Mỗi case có: CVE/component/version; advisory trực tiếp; điều kiện bị ảnh hưởng;
vector/Base/EPSS/KEV/ngày; tài sản giả định; Env/queue và mẫu số so sánh;
quyết định/việc phải xác minh; biện pháp vá hoặc ngoại lệ; giới hạn nguồn.
Phân biệt dữ kiện advisory và giả định inventory. Không tuyên bố đã exploit/pentest.

PgHero Base7.5→Env9.3; Base rank2/Env rank1, queue8/sensitivity2 trên cùng8cặp.
MOB-02 Base9.1→Env9.8 vẫn review/ranknull. API-02 thiếu product/version, không tự
đặt điểm0 hoặc unaffected. Không sửa Modified metrics chỉ vì asset internal/client.
Playbook cần có xác minh ảnh hưởng, bản còn hỗ trợ chứa fix, rollback, kiểm sau vá,
owner/hạn tái xét khi chưa vá. SLA là đề xuất giả định, chưa đo hiệu quả vận hành.

## 5. Bước C — slide và phản biện (2giờ)

Một giờ soạn `p5-security-slides.md`: slide3thiết kế,4ranking,5Web/mobile,
6context/hành động. Mỗi slide ghi một luận điểm, đường dẫn PNG/SVG thật,
caption/cohort/N, lời nói ngắn và câu hỏi dự kiến. Gửi N3 bản đầu sớm để dựng song song.
Không phải tạo bộ slide độc lập cạnh tranh với N3.

Một giờ tạo `p5-security-review.md`: bảng phát biểu, file/hình/row nguồn,
đúng/sửa/chờ, câu sửa. Rà những lỗi: KEVfalse=an toàn; CVSS=risk;
EPSS luôn thắng; KEV-first recall là validation độc lập; trộn rankingCVE và queueasset;
gọi snapshot là forecast; gọi tài sản giả định là hệ thống đã triển khai thật.
Dùng lại `docs/demo-qa.md`, thêm câu hỏi còn yếu; không chép tham khảo chưa đọc.
Nguồn chính thức cần mở kiểm trước khi trích; chuyển danh sách URL/DOI/luận điểm
và ngày thực truy cập cho N1 cập nhật references chung.

## 6. Bước D — runbook và diễn tập (1giờ)

Thử runbook cuối bằng path ownmachine, ghi commit/command/expected/actual
trong phần cuối `p5-security-review.md`. Log23/10 đã có không thay xác nhận runbook mới.
Chạy summary/ba mode nếu chưa làm; không tải lại dữ liệu. Gửi lỗi đầy đủ choN1.
Diễn tập nói case/ưu tiên vá bằng lời mình, ghi thời gian thật; toàn nhóm dùng script chung.
Review phần bảo mật trong báo cáo đã ghép và slide N3 trước nộp, ghi góp ý có vị trí.

## 7. Prompt IDE

```text
Tôi là N2, đọc docs/phase-5-nguoi-2.md. Viết reports/sections/security.md,
reports/p5-security-slides.md và reports/p5-security-review.md từ artifact thật.
Đọc RQ/contract/Phase3 integrated v2; mọi metric phải có cohort/N/ngày nguồn.
Giữ 3–5case có Web và mobile, tách dữ kiện và giả định, KEV-first không đánh giá vòng tròn.
Không sửa final-report/slides-outline, không train, không thay CSV/policy.
Đánh dấu thiếu chứng cứ, chưa tự ghi diễn tập hay chạy runbook pass nếu chưa chạy.
```

## 8. Commit và bàn giao

```powershell
git add reports/sections/security.md reports/p5-security-slides.md reports/p5-security-review.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(phase5): write security analysis and defense material"
git push -u origin docs/p5-security-section
```

PRbase develop. GửiN1/N3: branch+commit,3file, nguồn hình/số liệu, pending/lỗi.
Không cần ZIPdata mới. Nếu sửaplaybook thì add đúng file riêng sau diff.

- [ ] Nội dung đủ và đọc hiểu được, không chỉ dàn ý.
- [ ] 3–5case có nguồn/giả định; ranking và context đúngv2.
- [ ] Mọi con số truy nguyên được, không claim quá bằng chứng.
- [ ] N3 nhận nội dung slide, N1 nhận section và review.
- [ ] Runbook/diễn tập ghi đúng điều đã làm, chưa làm vẫn pending.
