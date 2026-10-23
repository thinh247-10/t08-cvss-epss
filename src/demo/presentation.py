"""Small display helpers shared by the notebook and its stdlib runner."""
import json

import pandas as pd

from .data_loader import DemoError, METRICS, display_value

TABLE_SINK = None  # stdlib runner supplies a notebook display_data sink


def table(frame, columns=None):
    if frame.empty:
        print("N/A — không có bản ghi")
        return
    view = frame if columns is None else frame.loc[:, columns]
    view = view.astype(object).copy()
    for index, row in view.iterrows():
        original = frame.loc[index]
        for col in view:
            reason = original.get(col + "_missing_reason")
            if col == "kev_recall":
                reason = original.get("kev_recall_reason")
            if reason is None or pd.isna(reason):
                reason = original.get("priority_reason", "nguồn không có giá trị")
            view.at[index, col] = display_value(row[col], reason)
    plain = view.to_string(index=False)
    markup = '<div style="overflow-x:auto;max-width:100%">' + view.to_html(index=False, escape=True) + '</div>'
    markup = markup.replace('<td>', '<td style="min-width:80px;max-width:360px;white-space:normal;vertical-align:top;padding:6px">')
    if TABLE_SINK is not None:
        TABLE_SINK(markup, plain)
    else:
        try:
            from IPython import get_ipython
            from IPython.display import HTML, display
        except ImportError:
            print(plain)
        else:
            if get_ipython() is None:
                print(plain)
            else:
                display(HTML(markup))


def show_cve(release, cve_id):
    try:
        row = release.lookup_cve(cve_id)
    except DemoError as exc:
        print(exc)
        return
    print(f"CVSS quan sát — {row['cve_id']}")
    for key in ("description", "cvss_vector", "cvss_base_score", "cvss_source", "cvss_type",
                "epss", "epss_date", "is_kev", "kev_date_added", "cvss_rank", "epss_rank", "kev_first_rank"):
        print(f"{key}: {display_value(row.get(key))}")


def show_prediction(release, cve_id, *, live=False):
    try:
        observed = release.lookup_cve(cve_id)
        predicted = release.live_prediction(cve_id) if live else release.lookup_prediction(cve_id)
    except DemoError as exc:
        result = {"mode": "unavailable", "reason": str(exc)}
        print(result["reason"])
        return result
    print(f"Mode: {predicted['mode']}; {predicted.get('label', predicted.get('reason', ''))}")
    if "fallback_reason" in predicted:
        print(predicted["fallback_reason"])
    if "predicted_vector" not in predicted:
        print(predicted.get("reason", "N/A"))
        return predicted
    observed_metrics = dict(x.split(":") for x in observed["cvss_vector"].split("/")[1:])
    table(pd.DataFrame({"Metric": METRICS,
                        "CVSS quan sát": [observed_metrics[m] for m in METRICS],
                        "Dự đoán": [predicted[f"pred_{m}"] for m in METRICS]}))
    print(f"Quan sát: {observed['cvss_vector']} / Base={observed['cvss_base_score']}")
    print(f"Dự đoán: {predicted['predicted_vector']} / Base={predicted['predicted_base_score']}")
    print(f"Model: {predicted['model_version']}; split={predicted['split']}; usage={predicted['prediction_usage']}")
    print(f"Vector valid: {predicted['vector_valid']}; error: {predicted.get('prediction_error') or 'không có'}")
    return predicted


def show_comparison(release, split):
    result = release.compare_predictions(split)
    if "reason" in result:
        print(result["reason"])
        return
    print(f"{split}: N={result['common_n']}/{result['eligible']}; cùng common_ids cho cả hai model")
    print(json.dumps(result["coverage"], ensure_ascii=False, indent=2))
    for model in result["models"]:
        print(model["model_version"], "tau-b:", display_value(model["kendall_tau_b"], model.get("undefined_reason")))
        print("Jaccard:", model["jaccard"])
    ranks = release.prediction_ranks
    table(ranks[ranks.split.eq(split)].head(4), ["cve_id", "model", "cvss_base_score", "predicted_base_score", "observed_rank", "predicted_rank", "rank_delta"])
    print("rank_delta = observed_rank − predicted_rank; dương: dự đoán xếp sớm hơn. Đây là severity, không đo hiệu quả vá.")
