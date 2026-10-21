# Phase 3 — kiểm tra hoàn tất phạm vi người 3

Ngày rà: **2026-10-21 (Asia/Saigon)**. Dataset `t08-v1.0-20261010`; dùng đúng gói
N2 `n2_p3_context_20261019_r1.zip` theo hash người dùng xác nhận. Không trộn context
revision mới hơn hoặc thay cohort/model/policy. Đây là gate N3; tích hợp chung thuộc N1/N2.

| Yêu cầu trong docs/phase-3-nguoi-3.md | Kết quả / bằng chứng |
|---|---|
| §4 input/hash/môi trường | Phase 1 verifier đã pass 14 file; Phase 2 prediction khớp ZIP receipt; N2 r1 khớp SHA-256/45.788 byte và 21 file envelope; `.venv` Python 3.13.16; pip check pass |
| §5 scatter/top-50 | 396 ID/3 KEV; 2 trang đủ 50 mỗi policy; top50_long 150 dòng; ngày nguồn và ties trong caption |
| §6 overlap/recall/context | 7 PNG + 7 SVG đã xem; recall CVSS/EPSS; Base/Env cùng 3 patch pairs; queue giữ 6 cặp, 3 review gồm 2 client |
| §7 case mobile | [CVE-2023-41387/MOB-02](../docs/cases/p3-mobile-n3.md): nguồn, phiên bản giả định, attack path, C/I/A, rank, review và giới hạn |
| §7 Environmental độc lập | [Crosscheck](p3_environmental_crosscheck_n3.md): Decimal thay số theo FIRST, expected 9.8 = N2 9.8, delta 0; không gọi scorer N2 |
| §8 AI phụ | [Báo cáo](p3_prediction_rank_impact.md): validation69/test108, cùng ID cho observed/2 model, coverage100%, 354 dòng; không thêm train |
| §9 UI offline | [UI contract](../docs/phase-4-ui-contract.md): khóa join, phiên bản, trường thực tế, null/review, demo flow; chưa code app |
| §9 notebook | [03_priority_analysis.ipynb](../notebooks/03_priority_analysis.ipynb): chạy hết 6 code cells theo thứ tự; 7 PNG thật embedded, không error |
| §12 handoff | `scripts/finalize_phase3_n3.py` kiểm hashes, tạo metadata và ZIP mới; receipt Git/ZIP tại [p3-n3.md](../docs/handoffs/p3-n3.md) |

## Kiểm tra đã chạy

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_plots tests.test_prediction_rank_impact tests.test_p3_environmental_crosscheck tests.test_rankings -q
.\.venv\Scripts\python.exe scripts/check_phase3_environmental_n3.py
.\.venv\Scripts\python.exe scripts/execute_phase3_notebook.py
.\.venv\Scripts\python.exe -m pip check
```

Các suite gồm 31 test plots/ranking, 12 test AI và 3 test crosscheck.
Lần đầu crosscheck có lỗi assertion so chuỗi Decimal `0.929600` với `0.9296`;
đã sửa test so giá trị Decimal, không đổi phép tính hay score, chạy lại 3 test pass.
Notebook không cần cài Jupyter: runner stdlib lưu stdout và display_data PNG thật.
Artifact/source/phiên bản được kiểm trước khi hiển thị và đóng gói.

## Kiểm hình và đối chiếu

[Log hình](p3_figures_check.md) lưu lượt xem PNG/SVG, sửa legend context và mẫu 5
CVE mỗi policy. Lần rà cuối mở lại scatter, top-50 hai trang: ID/badge/nhãn đọc được.
Các cặp context và review được đối chiếu toàn bộ với CSV N2; notebook giữ nguyên
N/A và reason/action. Không có số minh họa giả trong bộ bàn giao.

Không sửa file N2 sở hữu, evaluator/notebook Phase 2 hoặc cấu hình model. Các thay đổi
có sẵn ngoài phạm vi N3 trong working tree được giữ nguyên và không đưa vào commit N3.
Không tự gửi tin nhắn thay người dùng tới N1/N2; receipt là nội dung sẵn sàng bàn giao.
Việc N1/N2 xác nhận tích hợp và gate toàn nhóm không được đánh dấu hoàn tất bởi N3.
