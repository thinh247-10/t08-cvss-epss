# Cau hoi nghien cuu va pham vi

## RQ1 — Uoc luong CVSS tu mo ta van ban

**Cau hoi:** Khi mot CVE vua duoc cong bo va chua ai cham diem, co the uoc luong
vector CVSS chi tu mo ta khong?

**Vi sao co y nghia:** Tu 4/2026, NVD khong con tu phan tich phan lon CVE. Khoang
trong nay tao ra nhu cau thuc te cho mot co che uoc luong doc lap.

**Phuong phap:** Baseline TF-IDF + Logistic Regression, sau do DistilBERT multi-head
(1 encoder dung chung, 8 head cho AV/AC/PR/UI/S/C/I/A).

**Danh gia:**
- F1 theo tung lop (khong chi accuracy tong — du lieu lech lop nang)
- MAE/RMSE cua Base Score tinh lai tu vector du doan
- So sanh voi baseline: neu TF-IDF gan bang DistilBERT, do la mot phat hien dang ban

**Luu y phuong phap:** chia train/test theo **ngay publish**, khong random —
mo phong dung bai toan thuc te.

---

## RQ2 — Bat dong giua cac thang do

**Cau hoi:** CVSS, EPSS, KEV va SSVC bat dong voi nhau o dau, va bat dong do co y
nghia gi voi doi van hanh?

**Bon o can phan tich:**

| | EPSS thap | EPSS cao |
|---|---|---|
| **CVSS cao** | Chiem da so — bang chung "CVSS cao ≠ va truoc" | Uu tien cao nhat |
| **CVSS thap** | Co the hoan | **Diem mu nguy hiem** — bo sot neu chi dung CVSS |

**KEV la override:** CVE nam trong KEV da dang bi khai thac thuc te — len dau danh
sach bat ke CVSS/EPSS noi gi.

**San pham:** scatter plot CVSS (x) vs EPSS (y), to mau rieng diem thuoc KEV.

---

## RQ3 — Boi canh he thong

Xem [03-environmental-context.md](03-environmental-context.md)

---

## RQ4 — Quy trinh uu tien va

Xem [04-patch-playbook.md](04-patch-playbook.md)

---

## Ngoai pham vi

- Khong khai thac CVE, khong viet/chay exploit, khong PoC.
- Khong tai tao mo hinh EPSS (du lieu telemetry khong cong khai).
- Khong danh gia he thong that cua bat ky to chuc nao.
