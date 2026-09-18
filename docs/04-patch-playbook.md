# RQ4 — Patch Prioritization Playbook

> San pham cuoi cung cua do an: mot quy trinh ma ky su bao mat co the dung duoc,
> khong phai mot bieu do.
>
> **File nay la khung — nhom dien vao sau khi co ket qua tu RQ2 va RQ3.**

## 1. Luong xu ly khi nhan CVE moi

```
CVE moi
  |
  +-- Co trong KEV?  --> CO --> [ACT] Va trong 24-72h, bo qua cac buoc con lai
  |
  +-- KHONG
       |
       +-- Co anh huong tai san cua to chuc khong? --> KHONG --> [TRACK] Ghi nhan, khong hanh dong
       |
       +-- CO
            |
            +-- Tinh Environmental Score (theo CR/IR/AR cua tai san)
            +-- Tra EPSS
            |
            +-- Quyet dinh theo bang nguong ben duoi
```

## 2. Bang nguong (nhom tu dien sau khi phan tich du lieu)

| Environmental Score | EPSS | Muc do | SLA va |
|---------------------|------|--------|--------|
| >= _?_ | >= _?_ | Critical | _?_ |
| >= _?_ | < _?_ | High | _?_ |
| < _?_ | >= _?_ | Medium | _?_ |
| < _?_ | < _?_ | Low | _?_ |

**Cach chon nguong:** khong doan. Dua tren phan bo thuc te trong dataset — vi du
chon nguong EPSS sao cho bat duoc X% CVE trong KEV ma chi phai va Y% tong so CVE.
Ghi ro danh doi nay trong bao cao.

## 3. Cac truong hop ngoai le

- **Khong co ban va:** chuyen sang bien phap giam thieu (virtual patching qua WAF,
  cach ly mang, tat tinh nang). Ghi nhan lai ro ro chap nhan.
- **Ban va gay gian doan:** can cua so bao tri; trong thoi gian cho, ap dung giam thieu.
- **CVE chua co diem CVSS** (trang thai `Not Scheduled` cua NVD): dung mo hinh du doan
  o RQ1 de uoc luong tam thoi, danh dau ro la uoc luong.

## 4. Do luong hieu qua quy trinh

- Recall tren KEV: quy trinh nay co bat duoc cac CVE bi khai thac that khong?
- Khoi luong cong viec: so CVE phai va moi thang so voi cach chi dung CVSS
- Thoi gian trung binh tu khi CVE cong bo den khi va xong

## 5. Han che

(Nhom dien sau khi hoan thanh phan tich.)
