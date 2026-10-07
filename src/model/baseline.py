#!/usr/bin/env python3
"""Baseline: TF-IDF + Logistic Regression multi-output.

TODO (nguoi phu trach ML/NLP):
  - Chay CAI NAY TRUOC DistilBERT
  - Neu baseline gan bang DistilBERT, do la mot PHAT HIEN dang ban, khong phai that bai:
    co the cac tu khoa nhu "remote", "authentication", "privilege" da du de doan AV/PR
  - Bao cao F1 theo tung lop, khong chi accuracy tong
  - Chia train/test theo ngay publish, KHONG random
"""

from src.model.data_validation import ModelInputs, validate_model_input


def prepare_baseline_inputs(frame, *, dataset_version=None) -> ModelInputs:
    """Validate explicitly submitted rows and expose description-only features.

    This is the Phase 1 input boundary. Training, split approval, fitted
    preprocessing and evaluation remain Phase 2 work.
    """
    return validate_model_input(frame, dataset_version=dataset_version)
