"""Read frozen releases, never collect, train, score or rewrite their inputs.

Manifests must come from the team's trusted receipt. Use receive_demo_inputs.py
to anchor a newly received Phase 3 extraction to the receipt's ZIP hash.
ML dependencies are imported only by the explicit live_prediction action.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import time
import zipfile

import pandas as pd
import yaml

from scripts.package_phase3_release import verify as verify_phase3

ROOT = Path(__file__).resolve().parents[2]
DATASET = "t08-v1.0-20261010"
CONTEXT = "phase3-context-v2"
POLICY = "cvss-epss-kev-first-v1"
TFIDF = "tfidf-v1-n1-reproduction-20261017"
DISTILBERT = "distilbert-v1-n1-20261017"
METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
DEFAULT_P1 = ROOT / "data/processed/phase1_v1_20261010"
DEFAULT_P2 = ROOT / "data/processed/phase2_received"
DEFAULT_P3 = ROOT / "data/processed/p3_received_20261021"


class DemoError(ValueError):
    """A concise error safe to show in the demo."""


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def file_info(path):
    path = Path(path)
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": sha}


def safe_path(root, name):
    name = str(name).replace("\\", "/")
    parts = name.split("/")
    if (PureWindowsPath(name).drive or name.startswith("/") or ":" in name
            or any(p in {"", ".", ".."} or p.endswith((".", " ")) for p in parts)):
        raise DemoError(f"Đường dẫn manifest không an toàn: {name}")
    root = Path(root).resolve()
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        raise DemoError(f"Đường dẫn vượt thư mục release: {name}")
    return path


def verify_files(root, manifest, *, optional_missing=()):
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise DemoError("Manifest thiếu danh sách file.")
    verified = {}
    for name, record in files.items():
        path = safe_path(root, name)
        if path in verified:
            raise DemoError(f"Manifest trùng đường dẫn: {name}")
        expected = {k: record[k] for k in ("bytes", "sha256")}
        if not path.exists() and any(str(name).replace("\\", "/").startswith(prefix) for prefix in optional_missing):
            continue
        if not path.is_file() or file_info(path) != expected:
            raise DemoError(f"Sai hash/bytes hoặc thiếu file: {name}")
        verified[path] = expected
    return verified


def require_covered(root, names, verified):
    for name in names:
        if safe_path(root, name) not in verified:
            raise DemoError(f"File chưa có trong manifest: {name}")


def require_version(obj, **expected):
    for key, value in expected.items():
        actual = obj[key] if key in obj else None
        valid = actual.eq(value).fillna(False).all() if isinstance(actual, pd.Series) else actual == value
        if not valid:
            raise DemoError(f"Sai {key}: yêu cầu {value}")


def unique(frame, keys):
    if set(keys) - set(frame):
        raise DemoError(f"Thiếu khóa: {keys}")
    if frame[keys].isna().any().any() or frame.duplicated(keys).any():
        raise DemoError(f"Khóa null/trùng: {keys}")


def read_csv(path):
    # Reject duplicate headers before pandas silently renames them.
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        header = next(csv.reader(stream))
    if len(header) != len(set(header)):
        raise DemoError(f"Cột CSV trùng: {path}")
    frame = pd.read_csv(path, dtype="string", keep_default_na=False, na_values=[""])
    for col in frame:
        if col in {"is_kev", "vector_valid", "selection_is_discriminating"}:
            values = frame[col].str.lower()
            if not values.dropna().isin(["true", "false"]).all():
                raise DemoError(f"Boolean CSV không hợp lệ: {col}")
            frame[col] = values.map({"true": True, "false": False}).astype("boolean")
        elif col.endswith("_rank") or col in {"rank_delta", "n", "eligible", "k"}:
            number = pd.to_numeric(frame[col], errors="raise")
            if not number.dropna().mod(1).eq(0).all():
                raise DemoError(f"Rank/count phải là số nguyên: {col}")
            if col.endswith("_rank") and number.dropna().lt(1).any():
                raise DemoError(f"Rank phải >= 1 hoặc null: {col}")
            frame[col] = number.astype("Int64")
        elif col in {"epss", "cvss_base_score", "base_score", "environmental_score", "predicted_base_score", "common_coverage"}:
            frame[col] = pd.to_numeric(frame[col], errors="raise").astype("Float64")
            limit = 1 if col in {"epss", "common_coverage"} else 10
            if not frame[col].dropna().between(0, limit).all():
                raise DemoError(f"Giá trị ngoài miền: {col}")
    return frame


def checked_join(left, right, keys, *, exact_ids=False):
    """Left join with explicit equality of every shared non-key value."""
    unique(left, keys)
    unique(right, keys)
    l = left.set_index(keys)
    r = right.set_index(keys)
    if exact_ids and (set(l.index) != set(r.index)):
        raise DemoError(f"Tập khóa không khớp: {keys}")
    common = l.index.intersection(r.index)
    for col in l.columns.intersection(r.columns):
        a, b = l.loc[common, col], r.loc[common, col]
        equal = (a.isna() & b.isna()) | a.eq(b).fillna(False)
        if not equal.all():
            raise DemoError(f"Hai nguồn không khớp cột {col}")
    return left.merge(right.drop(columns=[c for c in right if c in left and c not in keys]),
                      how="left", on=keys, validate="one_to_one")


def records(frame):
    return json.loads(frame.to_json(orient="records", force_ascii=False, date_format="iso"))


def display_value(value, reason="nguồn không có giá trị"):
    if isinstance(value, (list, tuple, dict)):
        return str(value)
    return f"N/A — {reason}" if value is None or pd.isna(value) else str(value)


@dataclass
class Release:
    cves: pd.DataFrame
    pairs: pd.DataFrame
    metadata: dict
    ranking_metrics: dict
    figure_manifest: dict
    phase3: Path
    predictions: pd.DataFrame = field(default_factory=pd.DataFrame)
    prediction_metrics: dict = field(default_factory=dict)
    prediction_ranks: pd.DataFrame = field(default_factory=pd.DataFrame)
    ai_status: str = "Chưa có prediction đã xác minh"
    phase2: Path | None = None
    model_record: dict | None = None
    verified_files: dict = field(default_factory=dict)
    load_seconds: float = 0

    def summary(self):
        return {"dataset_version": DATASET, "context_version": CONTEXT,
                "cohort_id": self.metadata["cohort_id"], "policy_version": POLICY,
                "n": len(self.cves), "total_kev": int(self.cves.is_kev.sum()),
                "source_dates": self.metadata["source_dates"], "mapping": len(self.pairs),
                "scored": int(self.pairs.environmental_score.notna().sum()),
                "queue": self.pairs.queue_status.value_counts().to_dict(),
                "ai_status": self.ai_status, "load_seconds": self.load_seconds}

    def lookup_cve(self, cve_id):
        if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id.strip().upper()):
            raise DemoError("CVE ID rỗng hoặc sai định dạng (ví dụ CVE-2023-41387).")
        rows = self.cves[self.cves.cve_id.eq(cve_id.strip().upper())]
        if rows.empty:
            raise DemoError(f"Không có bản ghi trong ranking cohort: {cve_id}")
        return records(rows)[0]

    def lookup_asset_pairs(self, cve_id):
        cve = self.lookup_cve(cve_id)
        return self.pairs[self.pairs.cve_id.eq(cve["cve_id"])].copy()

    def lookup_context_comparison(self, cve_id):
        cve = self.lookup_cve(cve_id)
        path = self.phase3 / "data/processed/p3_n2/context_comparison.csv"
        if path not in self.verified_files or file_info(path) != self.verified_files[path]:
            raise DemoError("Context comparison thiếu manifest hoặc đã đổi hash.")
        frame = read_csv(path)
        require_version(frame, dataset_version=DATASET, context_version=CONTEXT)
        unique(frame, ["cve_id", "asset_id"])
        return frame[frame.cve_id.eq(cve["cve_id"])].copy()

    def lookup_prediction(self, cve_id, model_version=TFIDF, split=None):
        cve = self.lookup_cve(cve_id)
        if model_version not in {TFIDF, DISTILBERT}:
            raise DemoError("Model version không thuộc release đã khóa.")
        if split is not None and split not in {"validation", "test"}:
            raise DemoError("AI chỉ có split validation hoặc test.")
        if self.predictions.empty:
            return {"mode": "unavailable", "reason": self.ai_status}
        rows = self.predictions[self.predictions.cve_id.eq(cve["cve_id"])
                                & self.predictions.model_version.eq(model_version)]
        if split:
            rows = rows[rows.split.eq(split)]
        if rows.empty:
            return {"mode": "saved", "reason": "Không có prediction held-out cho CVE/model/split này (train không được ghép vào)."}
        return {"mode": "saved", "label": "Dự đoán — kết quả đã lưu", **records(rows)[0]}

    def compare_predictions(self, split):
        if split not in {"validation", "test"}:
            raise DemoError("Chọn riêng validation hoặc test.")
        if self.predictions.empty:
            return {"reason": self.ai_status}
        return next(s for s in self.prediction_metrics["splits"] if s["split"] == split)

    def figure_path(self, name):
        relative = f"reports/figures/phase3/{name}.png"
        allowed = {x["path"] for x in self.figure_manifest["outputs"]}
        if relative not in allowed:
            raise DemoError(f"Hình không có trong figures manifest: {name}")
        path = safe_path(self.phase3, relative)
        if path not in self.verified_files or file_info(path) != self.verified_files[path]:
            raise DemoError(f"Hình đã thay đổi: {name}")
        return path

    def live_prediction(self, cve_id):
        """Explicit validation-only CPU inference; no fitting and no downloads."""
        observed = self.lookup_cve(cve_id)
        if not observed.get("description") or not observed["description"].strip():
            return {"mode": "unavailable", "reason": "Mô tả rỗng; không chạy model."}
        if observed.get("split") != "validation":
            return {"mode": "unavailable", "reason": "Demo live chỉ dùng mô tả validation đã khóa."}
        saved = self.lookup_prediction(cve_id, TFIDF, "validation")
        if not self.model_record or not self.phase2:
            return {**saved, "fallback_reason": "Không có model live đã xác minh; dùng kết quả đã lưu nếu có."}
        path = self.phase2 / "baseline/models/baseline.joblib"
        try:
            current_model = file_info(path)
        except OSError as exc:
            return {**saved, "fallback_reason": f"Model live không còn đọc được: {exc}"}
        if current_model != self.model_record:
            raise DemoError("Sai hash model trước khi nạp joblib; dừng live inference.")
        try:
            from src.model.baseline import load_artifact
            from src.model.predict import predict_frame
            artifact = load_artifact(path)
            require_version(artifact, dataset_version=DATASET)
            if artifact["model_versions"]["tfidf"] != TFIDF:
                raise DemoError("Model live sai version.")
            result = records(predict_frame(artifact, pd.DataFrame([observed]),
                                           model_kind="tfidf", prediction_usage="demo"))[0]
        except DemoError:
            raise
        except (ImportError, OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
            return {**saved, "fallback_reason": f"Live không khả dụng: {type(exc).__name__}: {exc}"}
        return {"mode": "live", "label": "Dự đoán — TF-IDF CPU vừa chạy", **result}


def _load_predictions(release, phase1, phase2):
    manifest = read_json(phase2 / "manifest.json")
    require_version(manifest, dataset_version=DATASET, status="complete")
    if manifest.get("baseline_model_versions", {}).get("tfidf") != TFIDF or manifest.get("distilbert_model_version") != DISTILBERT:
        raise DemoError("Phase 2 model version không khớp receipt.")
    verified = verify_files(phase2, manifest, optional_missing=("distilbert/model/",))
    verified[phase2 / "manifest.json"] = file_info(phase2 / "manifest.json")
    require_covered(phase2, ["baseline.zip", "distilbert/predictions.csv"], verified)
    # The outer manifest covers baseline.zip, not its extracted directory.
    # Verify every extracted member against this verified nested ZIP before joblib.
    with zipfile.ZipFile(phase2 / "baseline.zip") as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            path = safe_path(phase2 / "baseline", member.filename)
            expected = {"bytes": member.file_size, "sha256": hashlib.sha256(archive.read(member)).hexdigest()}
            if member.filename == "models/baseline.joblib" and not path.exists():
                continue
            if not path.is_file() or file_info(path) != expected:
                raise DemoError(f"Baseline giải nén sai hash: {member.filename}")
            verified[path] = expected
    require_covered(phase2, ["baseline/data/processed/predictions.csv"], verified)
    ml = pd.read_parquet(phase1 / "ml_cohort.parquet", columns=["cve_id", "split", "dataset_version"])
    unique(ml, ["cve_id"])
    require_version(ml, dataset_version=DATASET)
    frames = []
    for name, version in [("baseline/data/processed/predictions.csv", TFIDF), ("distilbert/predictions.csv", DISTILBERT)]:
        frame = read_csv(phase2 / name)
        unique(frame, ["cve_id", "model_version"])
        require_version(frame, dataset_version=DATASET, prediction_usage="evaluation")
        allowed = {TFIDF, TFIDF + "-dummy"} if version == TFIDF else {DISTILBERT}
        if not frame.model_version.isin(allowed).all() or not frame.split.isin(["validation", "test"]).all():
            raise DemoError("Prediction trộn model/split không hợp lệ.")
        frame = frame[frame.model_version.eq(version)].copy()
        required = {*(f"pred_{m}" for m in METRICS), "predicted_vector", "predicted_base_score", "vector_valid", "prediction_error"}
        if required - set(frame):
            raise DemoError("Prediction thiếu vector/8 metrics/trạng thái.")
        expected = ml.set_index("cve_id").reindex(frame.cve_id)
        if not frame.split.reset_index(drop=True).eq(expected.split.reset_index(drop=True)).fillna(False).all():
            raise DemoError("Prediction split khác ML release hoặc CVE không thuộc ML.")
        frames.append(frame[frame.cve_id.isin(release.cves.cve_id)])
    predictions = pd.concat(frames, ignore_index=True)
    ranks = release.prediction_ranks
    unique(ranks, ["cve_id", "model_version"])
    require_version(ranks, dataset_version=DATASET)
    checked_join(ranks, predictions, ["cve_id", "model_version"], exact_ids=True)
    for split in release.prediction_metrics["splits"]:
        subset = ranks[ranks.split.eq(split["split"])]
        for version in (TFIDF, DISTILBERT):
            if set(subset[subset.model_version.eq(version)].cve_id) != set(split["common_ids"]):
                raise DemoError("AI common_ids không khớp bảng rank.")
    release.predictions = predictions
    release.verified_files.update(verified)
    release.phase2 = phase2
    release.model_record = verified.get(phase2 / "baseline/models/baseline.joblib")
    release.ai_status = "Dự đoán — kết quả đã lưu; live TF-IDF chỉ khi yêu cầu"


def load_release(phase1=DEFAULT_P1, phase2=DEFAULT_P2, phase3=DEFAULT_P3,
                 *, phase1_manifest=ROOT / "docs/handoffs/phase-1-v1.json"):
    started = time.perf_counter()
    p1, p3 = Path(phase1).resolve(), Path(phase3).resolve()
    try:
        manifest1 = read_json(phase1_manifest)
        require_version(manifest1, dataset_version=DATASET)
        verified = verify_files(p1, manifest1)
        verified[Path(phase1_manifest).resolve()] = file_info(phase1_manifest)
        require_covered(p1, ["metadata.json", "ranking_cohort.parquet", "ml_cohort.parquet"], verified)
        meta1 = read_json(p1 / "metadata.json")
        require_version(meta1, dataset_version=DATASET, status="complete")
        for name, record in meta1.get("files", {}).items():
            if manifest1["files"].get(name) != record:
                raise DemoError("Manifest Phase 1 và metadata không khớp.")
        # Reuse the existing Phase 3 verifier, including its complete/context gate.
        verify_phase3(p3)
        manifest3 = read_json(p3 / "phase3_manifest.json")
        require_version(manifest3, dataset_version=DATASET, context_version=CONTEXT,
                        release_version="phase3-n1-integrated-20261021")
        verified.update(verify_files(p3, manifest3))
        verified[p3 / "phase3_manifest.json"] = file_info(p3 / "phase3_manifest.json")
        n2, n3 = p3 / "data/processed/p3_n2", p3 / "data/processed/p3_n3"
        required = ["config/assets.yaml", "reports/p3_figures.md"]
        required += [f"data/processed/p3_n2/{n}" for n in ["metadata.json", "ranking_metrics.json", "context_metadata.json", "rankings.csv", "cve_asset_mapping.csv", "environmental_scores.csv", "priority_queue.csv"]]
        required += [f"data/processed/p3_n3/{n}" for n in ["figures_manifest.json", "prediction_rank_metrics.json", "predicted_rank_comparison.csv"]]
        require_covered(p3, required, verified)
        meta = read_json(n2 / "metadata.json")
        metrics = read_json(n2 / "ranking_metrics.json")
        context = read_json(n2 / "context_metadata.json")
        figures = read_json(n3 / "figures_manifest.json")
        for obj in (meta, metrics, figures):
            require_version(obj, dataset_version=DATASET, cohort_id=DATASET + ":ranking", policy_version=POLICY)
        for obj in (meta, metrics, context, figures["context"]):
            require_version(obj, context_version=CONTEXT)
        require_version(metrics, schema_version="p3-ranking-metrics-v1")
        require_version(context, dataset_version=DATASET, schema_version="p3-context-artifacts-v1", inventory_version="phase1-v1")
        for entry in figures["outputs"]:
            path = safe_path(p3, entry["path"])
            if verified.get(path) != {k: entry[k] for k in ("bytes", "sha256")}:
                raise DemoError(f"Figures manifest không khớp release: {entry['path']}")
        for obj in (metrics, context):
            if obj["source_dates"] != meta["source_dates"]:
                raise DemoError("Ngày nguồn Phase 3 không khớp.")
        for key, value in meta["source_dates"].items():
            if meta1.get(key) != value:
                raise DemoError(f"Ngày nguồn Phase 1/3 không khớp: {key}")
        ranks = read_csv(n2 / "rankings.csv")
        require_version(ranks, dataset_version=DATASET, cohort_id=DATASET + ":ranking", policy_version=POLICY)
        observed = pd.read_parquet(p1 / "ranking_cohort.parquet")
        require_version(observed, dataset_version=DATASET)
        cves = checked_join(ranks, observed, ["cve_id"], exact_ids=True)
        if len(cves) != meta["n"] or int(cves.is_kev.sum()) != meta["total_kev"]:
            raise DemoError("Số CVE/KEV không khớp metadata.")
        if metrics["n"] != meta["n"] or metrics["total_kev"] != meta["total_kev"]:
            raise DemoError("Mẫu số ranking metrics không khớp metadata.")
        for col in ("cvss_rank", "epss_rank", "kev_first_rank"):
            if set(cves[col].dropna()) != set(range(1, len(cves) + 1)):
                raise DemoError(f"Rank không đầy đủ/unique: {col}")
        mapping, scores, queue = [read_csv(n2 / n) for n in ("cve_asset_mapping.csv", "environmental_scores.csv", "priority_queue.csv")]
        for table in (mapping, scores, queue):
            require_version(table, dataset_version=DATASET, context_version=CONTEXT)
            unique(table, ["cve_id", "asset_id"])
        require_version(queue, policy_version="context-v1")
        if not mapping.cve_id.isin(cves.cve_id).all():
            raise DemoError("Mapping có CVE ngoài ranking cohort.")
        keys = ["cve_id", "asset_id"]
        if not set(map(tuple, scores[keys].values)).issubset(set(map(tuple, mapping[keys].values))):
            raise DemoError("Environmental có cặp ngoài mapping.")
        pairs = checked_join(checked_join(mapping, scores, keys), queue, keys, exact_ids=True)
        inventory = yaml.safe_load((p3 / "config/assets.yaml").read_text(encoding="utf-8"))
        require_version(inventory, inventory_version="phase1-v1")
        assets = pd.DataFrame(inventory["assets"])
        unique(assets, ["asset_id"])
        if not pairs.asset_id.isin(assets.asset_id).all():
            raise DemoError("Asset không có trong inventory.")
        # Preserve mapping product separately from the inventory's product.
        assets = assets.rename(columns={c: "asset_" + c for c in assets if c != "asset_id"})
        pairs = pairs.merge(assets, on="asset_id", how="left", validate="many_to_one")
        if not pairs.exposure.eq(pairs.asset_exposure).all():
            raise DemoError("Exposure khác inventory.")
        review = pairs.queue_status.eq("review_required")
        patch = pairs.queue_status.eq("patch")
        if not (review | patch).all() or pairs.loc[review, "priority_rank"].notna().any() or pairs.loc[patch, "priority_rank"].isna().any():
            raise DemoError("Queue status/rank không hợp lệ.")
        if not pairs.loc[pairs.exposure.eq("client"), "queue_status"].eq("review_required").all():
            raise DemoError("Client phải giữ review_required.")
        pairs["environmental_missing_reason"] = pairs.mapping_reason.where(pairs.environmental_score.isna(), pd.NA)
        pairs["priority_rank_missing_reason"] = pairs.priority_reason.where(pairs.priority_rank.isna(), pd.NA)
        release = Release(cves, pairs, meta, metrics, figures, p3, verified_files=verified)
        release.prediction_metrics = read_json(n3 / "prediction_rank_metrics.json")
        require_version(release.prediction_metrics, dataset_version=DATASET)
        release.prediction_ranks = read_csv(n3 / "predicted_rank_comparison.csv")
        if phase2 is not None:
            try:
                _load_predictions(release, p1, Path(phase2).resolve())
            except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
                release.ai_status = f"Chưa có prediction đã xác minh — {exc}"
        release.load_seconds = time.perf_counter() - started
        return release
    except (ValueError, OSError, KeyError, StopIteration) as exc:
        raise DemoError(f"Không mở được release: {exc}") from exc
