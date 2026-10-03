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

**Luu y phuong phap:** chia train/validation/test theo ngay publish thay vi random
de giam leakage theo thoi gian. Tuy nhien, snapshot NVD hien tai co the chua thong tin
duoc cap nhat sau ngay CVE cong bo, nen cach chia nay khong tu tai tao chinh xac
trang thai du lieu "as known then".

---

## RQ2 — Bat dong giua cac tin hieu uu tien

**Cau hoi:** CVSS, EPSS va trang thai CISA KEV bat dong voi nhau o dau,
va su bat dong do co y nghia gi doi voi viec uu tien va lo hong?

CVSS, EPSS va KEV khong do cung mot dai luong:

- CVSS bieu dien muc do nghiem trong cua lo hong.
- EPSS uoc luong xac suat bi khai thac trong 30 ngay toi.
- KEV cho biet CVE co nam trong catalog cac lo hong da duoc CISA ghi nhan
  la bi khai thac hay khong.

Khong gia dinh truoc nhom nao "chiem da so" hoac mot cach xep hang nao tot hon.
Ket luan phai dua tren dataset va snapshot thuc te cua nhom.

**Cac truong hop can phan tich sau khi co du lieu:**

| | EPSS thap | EPSS cao |
|---|---|---|
| **CVSS cao** | Kiem tra truong hop severity cao nhung likelihood thap | Severity va likelihood deu cao |
| **CVSS thap hon** | Thuong can them context de danh gia | Co the bi xep thap neu chi dung CVSS |

Cac diem thuoc KEV duoc danh dau de doi chieu voi hai cach xep hang.
Khong coi KEV la override truoc khi kiem tra CVE co thuc su anh huong san pham
va phien ban trong boi canh dang phan tich hay khong.

**San pham:** scatter plot CVSS (x) vs EPSS (y), danh dau cac diem thuoc KEV;
dong thoi so sanh cac danh sach CVSS-first, EPSS-first va chinh sach KEV-first.

SSVC chi duoc nhac nhu tai lieu tham khao neu con thoi gian, khong phai dau ra
bat buoc cua RQ2.

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
