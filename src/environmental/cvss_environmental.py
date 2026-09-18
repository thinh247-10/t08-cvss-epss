#!/usr/bin/env python3
"""
Tinh CVSS v3.1 Environmental Score.

Day la phan BAO MAT TRONG TAM cua do an — xem docs/03-environmental-context.md

TODO (nguoi phu trach Security Analysis):
  - Cai dat cong thuc Environmental theo dac ta CVSS v3.1 (FIRST)
  - Input: vector Base + CR/IR/AR cua tai san + cac Modified metric (MAV/MAC/MPR/MUI/MS/MC/MI/MA)
  - Output: Environmental Score

Nguyen tac: chi dieu chinh MAV/MAC/MPR dua tren bien phap kiem soat DA TRIEN KHAI
va kiem chung duoc. Neu khong, day tro thanh cach hop ly hoa viec tri hoan va.
"""
