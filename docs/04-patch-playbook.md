# RQ4 — Patch Prioritization Playbook

> San pham cuoi cung cua do an: mot quy trinh ma ky su bao mat co the dung duoc,
> khong phai mot bieu do.
>
> **File nay la khung — nhom dien vao sau khi co ket qua tu RQ2 va RQ3.**

## 1. Luong xu ly khi nhan CVE moi

```text
CVE moi
  |
  +-- San pham/phien ban bi anh huong co ton tai trong he thong khong?
       |
       +-- KHONG --> [NOT APPLICABLE]
       |             Ghi ly do va bang chung, khong dua vao hang doi va.
       |
       +-- CHUA RO --> [REVIEW REQUIRED]
       |               Xac minh san pham, phien ban va advisory.
       |
       +-- CO
            |
            +-- CVE co trong KEV khong?
            |      |
            |      +-- CO --> ghi nhan known exploitation
            |      |
            |      +-- KHONG --> khong duoc suy ra la chua tung bi khai thac
            |
            +-- Xac dinh exposure cua tai san
            +-- Tinh Environmental Score neu du du lieu va can cu
            +-- Tra EPSS tai snapshot dang su dung
            |
            +-- Dua vao hang doi uu tien theo chinh sach cua to chuc gia dinh
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

Bang nguong va SLA, neu duoc dien, la **chinh sach minh hoa cua to chuc gia dinh**,
khong phai nguong chuan cua CVSS, EPSS, CISA hay quy tac ap dung pho quat. Moi SLA
can neu nguoi phu trach, ngoai le va cach xu ly khi chua co ban va.

## 3. Cac truong hop ngoai le

- **Khong co ban va:** chuyen sang bien phap giam thieu (virtual patching qua WAF,
  cach ly mang, tat tinh nang). Ghi nhan lai ro ro chap nhan.
- **Ban va gay gian doan:** can cua so bao tri; trong thoi gian cho, ap dung giam thieu.
- **Mobile/client:** `exposure=client` chua co muc uu tien so trong policy ban dau.
  Sau khi xac dinh cap CVE-tai san la affected, giu `queue_status=review_required`,
  `priority_rank=null`, ghi ly do va uu tien xac minh neu co KEV. Khong tu doi client
  thanh internet hoac gan 0. N2 xem duong tan cong va de xuat policy rieng theo
  [data contract, muc 9](data_contract.md#9-hàng-đợi-theo-bối-cảnh--dataprocessedpriority_queuecsv).
- **CVE thieu diem CVSS:** xac dinh bang viec kiem tra co metric/vector CVSS v3.1
  hop le hay khong, khong chi dua vao ten `vulnStatus` nhu `Not Scheduled`. Co the
  dung mo hinh RQ1 de uoc luong tam thoi, nhung phai danh dau `predicted`, luu
  model version va khong tron voi diem quan sat tu nguon.

## 4. Danh gia quy trinh

- Bao cao `KEV coverage@K` theo dinh nghia trong data contract. Day la do bao phu
  catalog trong snapshot, khong phai recall day du cua tat ca CVE bi khai thac.
- So sanh so luong CVE trong cac nhom uu tien voi CVSS-first tren cung cohort;
  khong quy doi thanh cong suc hoac chi phi tiet kiem neu chua co du lieu van hanh.
- Chi bao cao thoi gian tu cong bo den va xong neu nhom co log van hanh that.
  Neu khong, day la de xuat chi so cho trien khai sau nay.

## 5. Han che

- KEV la catalog khong day du; khong co trong KEV khong phai nhan am.
- EPSS thay doi theo ngay va khong biet boi canh rieng cua tai san.
- Environmental Score phu thuoc gia dinh inventory va danh gia CR/IR/AR cua nhom.
- Nguong, SLA va thu tu hang doi la chinh sach minh hoa, can sensitivity analysis
  va xac nhan cua nghiep vu truoc khi ap dung thuc te.
- Truong hop thieu applicability, exposure, score hoac EPSS phai o trang thai
  `review_required`; khong gan 0 de day xuong cuoi hang doi.
