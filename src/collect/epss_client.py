#!/usr/bin/env python3
"""
Lay diem EPSS cho danh sach CVE.

TODO:
  - Goi theo lo (API ho tro ?cve=A,B,C) de giam so request
  - Tham so &date=YYYY-MM-DD de lay snapshot lich su
  - CHOT RO moc thoi gian va ghi lai trong metadata:
      EPSS thay doi hang ngay. Neu dung EPSS hom nay de xep hang CVE cu,
      mo hinh "biet truoc tuong lai" -> so sanh khong cong bang.
      Goi y: lay EPSS tai thoi diem 30 ngay sau khi CVE publish.
  - Ghi ra data/raw/epss.parquet
"""
