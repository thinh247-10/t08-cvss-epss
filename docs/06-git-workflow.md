# Hướng dẫn chia branch, commit, push và review cho nhóm T08

> Áp dụng cho nhóm 3 người trong [kế hoạch 30 ngày](05-ke-hoach-phan-cong.md).
> Repo đang có `main` và branch local `feat/data-pipeline`. Branch hiện tại phù hợp để Người 1 tiếp tục pipeline Phase 1; không cần xóa hay tạo lại chỉ vì tên ngắn hơn quy ước mới.

## 1. Mô hình branch của nhóm

```text
main                 Bản ổn định để demo/nộp
  └── develop        Nhánh tích hợp kết quả đã được review
       ├── feat/...  Tính năng
       ├── fix/...   Sửa lỗi
       ├── test/...  Kiểm tra/đánh giá
       ├── docs/...  Tài liệu, báo cáo, slide
       └── chore/... Cấu hình, dependency, đóng gói
```

- `main`: chỉ nhận PR từ `develop` ở cuối Phase 4 hoặc khi đóng bản nộp. Không code trực tiếp.
- `develop`: nhận PR nhỏ từ branch công việc. Phải luôn đọc được artifact/schema hiện tại.
- Branch công việc: tạo từ `develop`, một owner, một mục tiêu, thường sống 1–3 ngày.
- Không dùng một branch riêng cho mỗi người suốt cả tháng. Branch quá dài sẽ khó review và dễ xung đột.
- Không force-push lên `main` hoặc `develop`. Không commit API key, `.env`, raw dataset hay model lớn.

Nếu nhóm không muốn duy trì `develop`, có thể mở PR trực tiếp vào `main`, nhưng vẫn giữ nguyên nguyên tắc branch ngắn và review chéo. Với ba người làm song song, `develop` được khuyến nghị.

## 2. Ai dùng branch nào trong từng phase?

Tên dưới đây là tên mặc định. Khi một task lớn có hai đầu ra độc lập, tách thêm branch thay vì để PR quá lớn.

| Phase | Người 1 — Data/nhóm trưởng | Người 2 — Security | Người 3 — ML/demo |
|---|---|---|---|
| 0 | `chore/p0-project-contract` | `docs/p0-security-scope` | `chore/p0-model-config` |
| 1 | `feat/p1-data-pipeline` hoặc tiếp tục `feat/data-pipeline` hiện có | `feat/p1-scope-assets` | `test/p1-data-audit` |
| 2 | `fix/p2-dataset-split` | `feat/p2-cvss-scorer` | `feat/p2-nlp-baseline` |
| 2 tùy chọn | — | — | `feat/p2-distilbert` sau khi baseline được merge |
| 3 | `test/p3-ranking-quality` | `feat/p3-ranking-context` | `feat/p3-security-plots` |
| 4 | `chore/p4-repro-runbook` | `docs/p4-playbook-cases` | `feat/p4-demo` |
| 4 tùy chọn | `chore/p4-docker` | — | `feat/p4-streamlit` |
| 5 | `docs/p5-final-integration` | `docs/p5-security-section` | `docs/p5-ml-slides` |

Các branch Phase 5 tránh sửa cùng dòng trong `reports/final-report.md`:

- Người 2 viết phần bàn giao ở `reports/sections/security.md` trên branch của mình.
- Người 3 viết `reports/sections/ml.md` và `reports/slides-outline.md`.
- Người 1 merge hai branch, sau đó tích hợp vào `reports/final-report.md` trên `docs/p5-final-integration`.

Nếu nhóm không muốn tạo `reports/sections/`, N2/N3 có thể gửi PR chỉ sửa phần được phân công trong báo cáo, nhưng phải báo N1 trước khi cả hai cùng mở file.

## 3. Thiết lập `develop` một lần

Người 1 thực hiện khi các thay đổi đang làm đã được commit hoặc tạm cất an toàn. Không chạy lệnh chuyển branch khi đang có file sửa dở mà chưa hiểu chúng thuộc task nào.

```powershell
git switch main
git pull --ff-only origin main
git switch -c develop
git push -u origin develop
```

Hai thành viên còn lại lấy nhánh tích hợp:

```powershell
git fetch origin
git switch -c develop --track origin/develop
```

Nếu local đã có `develop`:

```powershell
git switch develop
git pull --ff-only origin develop
```

Trên GitHub, bật bảo vệ nếu nhóm có quyền:

- Chặn push trực tiếp vào `main`.
- Yêu cầu ít nhất một review trước khi merge.
- Yêu cầu branch không còn conflict và kiểm tra bắt buộc đã qua.
- Có thể áp dụng cùng quy tắc cho `develop`; nhóm ba người chỉ cần một reviewer.

## 4. Bắt đầu một task mới

Ví dụ Người 2 bắt đầu bộ tính CVSS ở Phase 2:

```powershell
git switch develop
git pull --ff-only origin develop
git switch -c feat/p2-cvss-scorer
```

Trước khi code, ghi task theo mẫu trong kế hoạch. Chỉ sửa file thuộc task hoặc file dependency đã thống nhất. Kiểm tra thay đổi thường xuyên:

```powershell
git status --short
git diff
```

Không chạy `git add .` theo thói quen khi repo có nhiều người. Stage đúng file của task:

```powershell
git add src/environmental/cvss_environmental.py tests/test_cvss.py
git diff --cached
git commit -m "feat(cvss): implement v3.1 base score calculator"
```

Quy ước commit:

| Tiền tố | Dùng cho | Ví dụ |
|---|---|---|
| `feat` | Chức năng mới | `feat(data): collect EPSS snapshot by date` |
| `fix` | Sửa lỗi | `fix(ranking): preserve ties in tau-b input` |
| `test` | Kiểm tra | `test(data): cover duplicate keys during join` |
| `docs` | Tài liệu/báo cáo | `docs(scope): define mobile inclusion evidence` |
| `chore` | Config/dependency/build | `chore(model): pin reproducible training seed` |
| `refactor` | Đổi cấu trúc không đổi hành vi | `refactor(model): share prediction serializer` |

Mỗi commit nên trả lời được một ý. Không commit message như `update`, `fix code`, `final final`.

## 5. Push branch và mở Pull Request

Push lần đầu:

```powershell
git push -u origin feat/p2-cvss-scorer
```

Các lần sau trên cùng branch:

```powershell
git push
```

Mở PR trên GitHub với:

- Base branch: `develop`.
- Compare branch: branch công việc vừa push.
- Một người review theo bảng phân công phase.
- Link task/ID, ví dụ `P2-N2-1`.

Mẫu tiêu đề:

```text
[P2-N2-1] Implement CVSS v3.1 Base scorer
```

Mẫu nội dung PR:

```markdown
## Vấn đề
Model evaluation cần tính Base Score từ vector dự đoán bằng cùng một implementation đã kiểm chứng.

## Thay đổi
- Parse vector CVSS:3.1 và kiểm tra metric bắt buộc.
- Tính Base Score, xử lý Scope và Roundup.
- Thêm ca kiểm tra đối chiếu độc lập.

## Input / output
- Input: vector CVSS v3.1.
- Output: điểm 0–10 hoặc lỗi có lý do.

## Đã kiểm tra
- [ ] Test liên quan đã qua.
- [ ] Đã đối chiếu ít nhất một vector với FIRST calculator/spec.
- [ ] Không đổi data contract.

## Artifact / ảnh hưởng
- Không tạo dataset mới.
- N3 có thể dùng hàm này để tính MAE/RMSE sau khi merge.
```

Reviewer kiểm logic, input/output, cách chạy và giới hạn. Reviewer không chỉ bấm Approve vì code chạy.

## 6. Cập nhật branch khi `develop` đã thay đổi

Trước khi mở PR, lấy thay đổi mới:

```powershell
git fetch origin
git rebase origin/develop
```

Nếu branch đã được nhiều người cùng dùng hoặc nhóm chưa quen rebase, dùng merge an toàn hơn:

```powershell
git fetch origin
git merge origin/develop
```

Sau rebase, push có thể cần cập nhật lịch sử branch cá nhân:

```powershell
git push --force-with-lease
```

Chỉ dùng `--force-with-lease` trên branch công việc do mình sở hữu và đã báo người cùng làm. Không dùng trên `main`/`develop`. Người mới dùng Git nên chọn merge để tránh rewrite history.

Khi có conflict:

1. Mở từng file có marker `<<<<<<<`, `=======`, `>>>>>>>`.
2. So với data contract và quyết định phase; không chọn mù “Accept Current/Incoming”.
3. Chạy lại kiểm tra liên quan.
4. `git add <file-da-sua>` rồi `git rebase --continue` hoặc commit merge.
5. Nhờ đúng owner review nếu conflict nằm trong schema, công thức CVSS hoặc ranking policy.

## 7. Quy tắc cho file dùng chung

| File/phạm vi | Người tổng hợp | Quy tắc tránh conflict |
|---|---|---|
| `docs/data_contract.md`, `config/project.yaml`, README, requirements | N1 | N2/N3 đề xuất qua PR; N1 merge và thông báo thay đổi interface |
| `config/assets.yaml`, docs 03/04, context/ranking policy | N2 | N1/N3 không đổi nghĩa nghiệp vụ trong lúc sửa hiển thị |
| `config/model.yaml`, model card, prediction schema implementation | N3 | Đổi schema cần N1/N2 review và sửa contract trước |
| `src/analysis/plots.py` ở Phase 3 | N3 code, N2 review/owner kết quả | Chỉ một branch sửa tại một thời điểm |
| `reports/final-report.md` | N1 tích hợp | N2/N3 viết section riêng hoặc báo trước vùng dòng sẽ sửa |

Thay schema, snapshot, split hoặc ranking policy phải là PR riêng hoặc được nêu rõ trong PR. Không âm thầm đổi cùng một PR làm đẹp giao diện.

## 8. Merge, đồng bộ và xóa branch

Sau khi PR được review và checks qua, ưu tiên **Squash and merge** vào `develop` để lịch sử gọn. Tên squash commit dùng đúng tiêu đề task.

Sau merge, owner đồng bộ local:

```powershell
git switch develop
git pull --ff-only origin develop
git branch -d feat/p2-cvss-scorer
```

Nếu GitHub chưa xóa remote branch:

```powershell
git push origin --delete feat/p2-cvss-scorer
```

Chỉ xóa branch khi PR đã merge và commit nhìn thấy trong `develop`. Không dùng `-D` để ép xóa branch còn thay đổi chưa merge.

## 9. Đưa bản nghiệm thu lên `main`

Cuối Phase 4, Người 1 mở PR:

```text
develop → main
Title: [Release candidate] T08 reproducible analysis and demo
```

Cả N2 và N3 review:

- N2 xác nhận case, ranking, context và playbook đúng nghĩa.
- N3 xác nhận model/artifact/demo đúng version.
- N1 chạy runbook trên checkout sạch và chốt release checklist.

Sau khi merge, tạo tag cho bản demo ổn định:

```powershell
git switch main
git pull --ff-only origin main
git tag -a v0.9-demo -m "Reproducible T08 demo"
git push origin v0.9-demo
```

Ngày 28, sau khi báo cáo và slide được duyệt, mở PR `develop → main` lần cuối rồi tag bản nộp:

```powershell
git tag -a v1.0-submission -m "T08 course submission"
git push origin v1.0-submission
```

Chỉ tạo tag sau khi bản tương ứng đã nằm trên `main`. Nếu sửa lỗi sau tag, tăng `v1.0.1`; không di chuyển tag đã dùng để nộp.

## 10. Khi artifact quá lớn để push Git

- Commit code, config không chứa secret, schema, sample nhỏ, metadata, figure và báo cáo.
- Raw NVD/EPSS/KEV, Parquet lớn, model `.bin`/`.pt` giữ ngoài Git theo `.gitignore`.
- Mỗi PR ghi `dataset_version`, `model_version`, checksum và cách lấy artifact.
- Không dùng GitHub branch như nơi truyền `.env` hoặc API key.
- Trước ngày nộp, một thành viên khác phải tải đúng artifact theo runbook và đối chiếu checksum.

## 11. Checklist trước mỗi lần push

- [ ] Đang ở đúng branch: `git branch --show-current`.
- [ ] Branch được tạo/cập nhật từ `develop` mới nhất.
- [ ] `git status --short` không có file ngoài task bị stage.
- [ ] `git diff --cached` đúng phần muốn commit.
- [ ] Không có `.env`, key, raw data hoặc model lớn.
- [ ] Đã chạy kiểm tra phù hợp với thay đổi.
- [ ] Commit message có loại, phạm vi và hành vi rõ.
- [ ] PR vào `develop`, có owner/reviewer và tiêu chí Done.
- [ ] Thay đổi schema/snapshot/split/policy đã được thông báo.

## 12. Xử lý branch hiện tại `feat/data-pipeline`

Branch hiện tại trỏ cùng commit khởi đầu với `main` nhưng workspace đang có tài liệu chưa commit. Người 1 thực hiện sau khi kiểm tra diff:

```powershell
git branch --show-current
git status --short
git diff
```

Nếu toàn bộ thay đổi hiện tại là kế hoạch chung, có hai cách an toàn:

1. Commit kế hoạch trên branch hiện tại, mở PR vào `develop`, rồi tiếp tục pipeline bằng một branch mới sau khi merge.
2. Giữ `feat/data-pipeline` cho cả kế hoạch khởi động và pipeline Phase 1, nhưng PR phải mô tả rõ hai nhóm file; cách này nhanh hơn nhưng PR lớn hơn.

Khuyến nghị cách 1 với commit như `docs(plan): add 30-day phase and git workflow`. Không chuyển branch hoặc cherry-pick khi còn thay đổi chưa commit mà chưa biết từng file thuộc ai.

Trình tự cụ thể cho workspace hiện tại, sau khi N1 đã đọc `git diff` và xác nhận các file đều thuộc PR kế hoạch:

```powershell
# Đang ở feat/data-pipeline: stage đúng bộ tài liệu kế hoạch
git add README.md docs/05-ke-hoach-phan-cong.md docs/06-git-workflow.md docs/data_contract.md docs/phases docs/archive
git diff --cached
git commit -m "docs(plan): add 30-day phases and git workflow"

# Tạo nhánh tích hợp từ main lần đầu
git switch main
git pull --ff-only origin main
git switch -c develop
git push -u origin develop

# Push branch chứa bộ kế hoạch và mở PR vào develop
git switch feat/data-pipeline
git push -u origin feat/data-pipeline
```

Sau khi PR tài liệu được merge, không tiếp tục code pipeline trên lịch sử cũ chưa đồng bộ. Cập nhật branch hoặc tạo branch Phase 1 sạch từ `develop`:

```powershell
git switch develop
git pull --ff-only origin develop
git switch -c feat/p1-data-pipeline
```

Nếu muốn giữ tên `feat/data-pipeline`, chỉ tái sử dụng sau khi branch cũ đã merge và đồng bộ với `develop`; cách đơn giản nhất cho người mới là dùng tên mới `feat/p1-data-pipeline`.
