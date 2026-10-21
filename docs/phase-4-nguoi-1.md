# Phase 4 — Người 1: runbook, release và tích hợp

Bạn là N1. Khoảng8giờ/4–5ngày, bắt đầu sau biên bảnPhase3 ngày21/10.
Nhánh `chore/p4-repro-runbook`; N2 `docs/p4-playbook-cases`, N3 `feat/p4-demo`.
Không cần đợi hai bạn mới chuẩn bị môi trường/gói/runbook.

## 1. Gửi đúng thứ cho hai bạn (1giờ)

Pushcode/tàiliệu hiệnhành lên develop, gửi link hướngdẫn
[N2](phase-4-nguoi-2.md) và [N3](phase-4-nguoi-3.md).
Gửi **phase3_handoff_20261021.zip cho cảhai**, kèm receipt
`docs/handoffs/phase-3-complete-20261021.json`. Gói mới hợp nhất r2/v2;
gói stepB/r1 trước không đủ. Phase1/2 chỉ gửi lại nếu thiếu/saihash.
Khônggửi `.env`, APIkey hoặc `.venv`. Commitcode không đưa dataignored lênGitHub.

## 2. Branch và manifest đường dẫn (1giờ)

```powershell
git status --short
git switch develop
git pull --ff-only origin develop
git switch -c chore/p4-repro-runbook
```

Lưu việc cũ trước; branch đã tồn tại thì switch rồi mergeorigin/develop.
Tạo `config/demo.yaml` với pathPhase1/2/3, receipt, dataset/model/context versions;
pathrelative, không cố định ổD hoặcusername. Chốt adapterpath cùngN3 trước khi code.
Dataset t08-v1.0-20261010, context-v2; policycontext-v1 không nhầm với contextversion.

## 3. Runbook tái chạy (2giờ)

Tạo **`docs/runbook.md`**: clone/pull,ownvenv,installrequirements,nhậnZIP/verify,
paths,snapshotversions,chạyCLI/notebookthật,lỗi thườnggặp, thời gianđo.
`scripts/package_phase3_release.py --verify <staging>` đãcó; CLI demo chưa có,
chỉ điền khi N3 triểnkhai và bạn đãchạy `--help`. Không dùng lệnh cũ giảđịnh.
Lấy logcommands ở `reports/p3_review_n1.md` cho nguồn táitạo, nhưng táitạo mới
không được ghi đè release/ZIP đã gửi. Mỗi lầnrebuild dùngrevision riêng.

Thứ tự kiểm: phase1verifier→phase2receipt/model nếu cần→phase3manifest→demo.
Không training/collect trong đườngdemo. Lọc requirements phùhợp, dependenciesmodel
chỉ cầnAI, Torch chỉ optionalDistilBERT. Không ép máyN2 cài GPU để xem bảng.

## 4. Kiểm máy sạch hoặc máy đồngđội (2giờ)

Nhờ N3 thực hiện runbook bằng gói đã gửi trên ownvenv; ghi thật vào
**`reports/p4_reproduction.md`**: máy/OS/Python/commit/hash,command,elapsed,
actual/expected, file nào khác, screenshot/log. Chưa nhậnlog thì pending,
không viết “đã chạy máy khác” vì bạn giải nén lại trên máyN1.
Chọn mộtID đi qua source→ranking→plot→case; mộtclient giữreview;
một prediction cómode/modelversion. Không cần toànbộtrain lặp lại.

## 5. Tích hợp và rehearsal (2giờ)

N2giao lời thoại/Q&A, N3giao CLI/notebook/tests. Kiểm diff rồi merge develop,
chạy testphạmvi thayđổi và mộtsmoke endtoend. Ghép **`reports/demo-script.md`**
từ đoạn N2 và thao tác N3; diễn tập6phút, ghi giờ thực tế.
**`reports/release-checklist.md`** gồm owner, blocker, expected/actual,
version/hash, pass/pending, cách xử lý. Cắt Streamlit/Docker trước nếu khôngđủgiờ,
giữ pipeline nghiêncứu và demoCLI/notebook đúng.

## 6. Prompt và Git

```text
Đọc docs/phase-4-nguoi-1.md và completionPhase3. Làm runbook/manifestpaths,
không giả định CLI N3 chưa triểnkhai. Verifygói, giữ inputreadonly. Khi N2/N3 giao,
kiểm/merge và chạy smoke; logthật, pending máykhác nếu chưa nhận. Không training,
downloadnguồn mới hoặc bậtcloud. Ghi blocker cụthể trước khi chốt Phase4.
```

```powershell
git add config/demo.yaml docs/runbook.md reports/release-checklist.md reports/p4_reproduction.md reports/demo-script.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(phase4): record reproducible demo runbook and release checks"
git push -u origin chore/p4-repro-runbook
```

Chỉadd file đã có, không thêm dữliệu lớn. Merge vềdevelop khi kiểmxong;
không merge main hoặc tagfinal cho tới khi quyếtđịnh nộp.
GatePhase4: inputverified, demooffline6phút thực chạy, AI/observedtách,
Web/mobilecase cónguồn, fallback mởđược, logmáynhận, blocker đãđóng/cắt.
Sau gate này mới chia việcPhase5: báo cáo, slide và bảo vệ.
