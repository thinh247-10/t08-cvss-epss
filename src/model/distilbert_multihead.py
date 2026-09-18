#!/usr/bin/env python3
"""
DistilBERT multi-head du doan 8 thanh phan vector CVSS.

Kien truc:
    1 DistilBERT encoder dung chung
      |
      +-- head AV  (4 lop: N/A/L/P)
      +-- head AC  (2 lop: L/H)
      +-- head PR  (3 lop: N/L/H)
      +-- head UI  (2 lop: N/R)
      +-- head S   (2 lop: U/C)
      +-- head C   (3 lop: N/L/H)
      +-- head I   (3 lop: N/L/H)
      +-- head A   (3 lop: N/L/H)

KHONG train 8 mo hinh rieng — multi-task hoc chung tan dung ngu canh tot hon va nhe hon.

TODO:
  - Weighted loss de xu ly lech lop (du lieu NVD lech nang ve AV:N, AC:L, PR:N)
  - Danh gia: F1 tung lop + MAE cua Base Score tinh lai tu vector du doan
  - Train 1 lan ra ket qua chap nhan duoc roi DUNG. Khong grid search —
    trong tam do an la phan bao mat, khong phai toi uu mo hinh.
"""
