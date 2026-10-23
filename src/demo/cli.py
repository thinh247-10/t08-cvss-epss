"""Demo local offline: summary, cve, predict. Không thu thập hoặc train."""
import argparse
import json
from pathlib import Path
import sys

from .data_loader import (DEFAULT_P1, DEFAULT_P2, DEFAULT_P3, DISTILBERT, TFIDF,
                          DemoError, display_value, load_release, records)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase1", type=Path, default=DEFAULT_P1)
    p.add_argument("--phase2", type=Path, default=DEFAULT_P2)
    p.add_argument("--phase3", type=Path, default=DEFAULT_P3)
    p.add_argument("--no-ai", action="store_true", help="Chỉ mở dữ liệu quan sát/bối cảnh")
    p.add_argument("--json", action="store_true", help="JSON giữ null và boolean đúng kiểu")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("summary", help="Snapshot, số CVE/cặp tài sản và trạng thái AI")
    cve = sub.add_parser("cve", help="CVSS quan sát, ba rank và các cặp tài sản")
    cve.add_argument("cve_id")
    predict = sub.add_parser("predict", help="Dự đoán đã lưu; --live mới chạy TF-IDF CPU")
    predict.add_argument("cve_id")
    predict.add_argument("--model-version", choices=[TFIDF, DISTILBERT], default=TFIDF)
    predict.add_argument("--split", choices=["validation", "test"])
    predict.add_argument("--live", action="store_true")
    return p


def render(value, prefix=""):
    if isinstance(value, dict):
        reason = value.get("reason") or value.get("priority_reason") or value.get("mapping_reason") or "nguồn không có giá trị"
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                render(item, prefix + "  ")
            else:
                print(f"{prefix}{key}: {display_value(item, reason)}")
    elif isinstance(value, list):
        if not value:
            print(prefix + "N/A — không có bản ghi")
        for item in value:
            render(item, prefix)
            print()
    else:
        print(prefix + display_value(value))


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    p = parser()
    args = p.parse_args(argv)
    try:
        release = load_release(args.phase1, None if args.no_ai else args.phase2, args.phase3)
        if args.command == "summary":
            output = release.summary()
        elif args.command == "cve":
            output = {"CVSS quan sát": release.lookup_cve(args.cve_id),
                      "Bối cảnh và hành động": records(release.lookup_asset_pairs(args.cve_id))}
        else:
            if args.live and (args.model_version != TFIDF or args.split == "test"):
                raise DemoError("Live chỉ hỗ trợ TF-IDF trên validation đã khóa.")
            observed = release.lookup_cve(args.cve_id)
            prediction = (release.live_prediction(args.cve_id) if args.live else
                          release.lookup_prediction(args.cve_id, args.model_version, args.split))
            output = {"CVSS quan sát": {k: observed[k] for k in ("cve_id", "cvss_vector", "cvss_base_score", "cvss_source", "cvss_type")},
                      "Dự đoán": prediction}
        if args.json:
            print(json.dumps(output, ensure_ascii=False, indent=2, allow_nan=False))
        else:
            render(output)
        return 0
    except DemoError as exc:
        print(f"Demo: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
