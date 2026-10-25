# Phase 5 — Người 1: chủ biên, dữ liệu và gói nộp

Giao ngày25/10/2026. Ngân sách dự kiến6giờ; deadline và định dạng chính thức phải
lấy từ thông báo môn học. Bắt đầu viết ngay, đồng thời đóng các mục pending
trong [checklist Phase4](../reports/release-checklist.md). Chưa coi diễn tập đã xong.

## 1. Phân chia quyền sửa file

| Người | Branch | File chính |
|---|---|---|
| N1 | `docs/p5-final-integration` | `reports/final-report.md`, runbook, README, checklist, references |
| N2 | `docs/p5-security-section` | `reports/sections/security.md`, `reports/p5-security-slides.md`, `reports/p5-security-review.md` |
| N3 | `docs/p5-ml-slides` | `reports/sections/ml.md`, `reports/slides-outline.md`, slide và `reports/p5-ml-review.md` |

Chốt dùng `reports/sections/security.md` và `reports/sections/ml.md` theo kế hoạch
gốc; không tạo thêm các bản `p5-security-section.md`/`p5-ml-section.md` trùng nội dung.
N2 gửi nội dung slide riêng, N3 tổng hợp outline; chỉ N1 sửa báo cáo chính.

## 2. Chuẩn bị và giao việc (30phút)

Gửi hai hướng dẫn [N2](phase-5-nguoi-2.md), [N3](phase-5-nguoi-3.md).
Cả hai pull develop, dùng lại ZIP Phase1/2/3 đúng receipt; không cần gói mới,
không chia sẻ venv/APIkey. N1 hỏi nhóm/đọc thông báo và ghi vào đầu báo cáo:
ngày giờ nộp, template, số trang, tên thành viên/MSSV, định dạng file,
thời lượng nói/demo/Q&A, kênh nộp. Chưa biết thì ghi `CHỜ XÁC NHẬN`, không tự điền.

```powershell
git status --short
git switch develop
git pull --ff-only origin develop
git switch -c docs/p5-final-integration
```

Nếu có file sửa riêng, commit đúng phần đó trước khi chuyển branch; không reset,
không add file `a` hoặc log demo mới chỉ để làm sạch status. Branch đã tồn tại
thì dùng `git switch docs/p5-final-integration`, không tạo lại.

## 3. Viết khung và dữ liệu (1,5giờ)

Tạo `reports/final-report.md`: tóm tắt (viết cuối), bài toán/RQ, lý thuyết,
dữ liệu, phương pháp NLP, thiết kế ranking/context, kết quả, case/playbook,
giới hạn, tái lập, kết luận, tài liệu tham khảo và đóng góp.
Giữ nhãn “bản nháp” đến khi nhận đủ phần N2/N3. Không tự viết kết quả họ chưa giao.

Đọc trước:

- [Nghiệm thu Phase1](phase-1-completion.md), [data contract](data_contract.md),
  [nghiệm thu Phase2](phase-2-completion.md), [Phase3](phase-3-completion.md).
- `docs/handoffs/phase-1-v1.json`, `phase-2-complete-20261017.json`,
  `phase-3-complete-20261021.json`: tên gói, bytes, hash, version.
- Metadata trong các release thật; không dùng đường dẫn ví dụ `data/metadata.json`
  nếu file không tồn tại. Dẫn đúng đường dẫn dưới `data/processed/` hoặc staging.

Phần dữ liệu phải phân biệt master, ML và ranking: master71653; ML67242
(train28815/validation19606/test18821); ranking396 (388Web/8mobile), 3KEV.
Đối chiếu lại artifact trước xuất bản. Không gọi67242CVE là toàn bộ Web/mobile.
Scoped held-out validation69/test108 không có mobile; 8mobile ở train.
Khoảng thu thập theo ngày published, không theo năm trong CVE ID.
EPSS29/09/2026; KEV phát hành30/09 và tải01/10 UTC: ba mốc khác nhau.
Mô tả missing/null, CVSS3.1 và lựa chọn source; raw giữ các nguồn khác.

## 4. Tích hợp nội dung và kiểm nguồn (1,5giờ)

Nhận N2/N3 gồm commit, file, claim→artifact, phần còn thiếu.
Đọc diff trước khi merge, giải quyết trùng thuật ngữ và số liệu bằng artifact.
Ghép hai section vào final-report, không chỉ dán link thay nội dung báo cáo.
Đối chiếu đúng RQ trong `docs/01-research-questions.md`, không tự đánh lại số RQ.
Mỗi bảng ghi cohort/split/N/version; mỗi hình có caption và đường dẫn nguồn.

N1 cập nhật `docs/references.md` từ danh sách nguồn N2/N3 thực đọc. Không ghi
ngày truy cập mới nếu chưa mở nguồn, không khẳng định tái lập nguyên văn bài báo.
Thiếu bằng chứng thì yêu cầu tác giả sửa hoặc giới hạn phát biểu, không tự bịa số.
Định hướng65% bảo mật/25%AI/10%dữ liệu là ưu tiên nhóm, không phải rubric thầy.

## 5. Runbook, đóng gói và diễn tập (2giờ)

- Nhận log N2/N3 dùng đúng [runbook mới](runbook.md); ghi vào
  `reports/p4_reproduction.md` và checklist, phân biệt log trước/sau runbook.
- Ghép nội dung slide N3 với báo cáo; giữ nguyên figure/data/model đã khóa.
- Tạo `reports/submission-manifest.md`: tên file nộp, mục đích, version,
  vị trí tải dữ liệu/model nếu không kèm, checksum/bytes của gói, quyền truy cập.
- Gói nộp theo quy định thật; không mặc định phải nhét253MBmodel vào ZIP nếu
  môn chỉ yêu cầu link. Không đóng gói `.env`, `.venv`, cache hoặc file nháp `a`.
- Nếu yêu cầu DOCX/PDF, xuất từ bản đã khóa và mở kiểm bảng/hình/font/trang;
  Markdown hoàn chỉnh chưa tự động có nghĩa PDF hoàn chỉnh.
- Cùng nhóm diễn tập theo `reports/demo-script.md`; ghi thời gian thật, câu hỏi yếu,
  lỗi và lần sửa. Chưa diễn tập thì giữ pending, vẫn viết báo cáo được.
- Nộp qua kênh chính thức sau kiểm tra; chỉ ghi “đã nộp” khi có biên nhận thật.

## 6. Commit/push và bàn giao (30phút)

Chỉ add các file thực sự đã sửa:

```powershell
git add reports/final-report.md reports/submission-manifest.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(phase5): integrate final report and submission manifest"
git push -u origin docs/p5-final-integration
```

Runbook/README/references/checklist nếu sửa thì add riêng sau khi xem diff.
PRbase develop; không force-push/main/tag final tự động. Nộp và merge là hai việc khác nhau.

## 7. Prompt dùng trong IDE

```text
Đọc docs/phase-5-nguoi-1.md và kế hoạch Phase5. Tôi là N1.
Viết khung reports/final-report.md và phần dữ liệu từ release/receipt thật.
Không sửa phần riêng N2/N3, không train hoặc thu thập lại. Đánh dấu chỗ chờ
thông báo môn học và sections chưa giao. Tích hợp khi có commit bàn giao;
mọi con số phải có cohort/split/version và nguồn kiểm. Ghi checklist đúng trạng thái.
Không tự đánh dấu diễn tập, chạy máy khác hoặc nộp bài thành công.
```

## 8. Điều kiện hoàn tất

- [ ] Báo cáo đầy đủ RQ, nguồn, kết quả/giới hạn và đóng góp thật.
- [ ] N2/N3 đã kiểm phần chuyên môn sau khi ghép.
- [ ] Runbook máy nhận và diễn tập có bằng chứng.
- [ ] Slide/báo cáo/artifact cùng version, không placeholder.
- [ ] Quy cách và quyền truy cập gói nộp đã kiểm; biên nhận khi thực sự nộp.
