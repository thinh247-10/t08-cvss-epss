"""Shared DistilBERT encoder and eight CVSS heads; optional Torch dependencies."""
import json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from torch import nn
from transformers import DistilBertConfig, DistilBertModel, AutoTokenizer
from safetensors.torch import load_file, save_file
from src.model.baseline import preprocess_descriptions
from src.model.data_validation import LABEL_ORDER, TARGET_METRICS
from src.model.predict import PREDICTION_COLUMNS, labels_to_vector
from src.environmental.cvss_base import calculate_base_score


class MultiHeadDistilBert(nn.Module):
    def __init__(self, encoder):
        super().__init__()
        self.encoder = encoder
        self.dropout = nn.Dropout(0.2)
        self.heads = nn.ModuleDict({m: nn.Linear(encoder.config.dim, len(labels))
                                    for m, labels in LABEL_ORDER.items()})

    def forward(self, input_ids, attention_mask):
        hidden = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state[:, 0]
        return {m: head(self.dropout(hidden)) for m, head in self.heads.items()}


def encode_targets(frame):
    return torch.tensor(np.column_stack([
        frame[m].map({label: i for i, label in enumerate(labels)}).to_numpy(dtype=np.int64)
        for m, labels in LABEL_ORDER.items()]), dtype=torch.long)


def train_class_weights(targets):
    """Balanced inverse frequencies from TRAIN; absent classes receive zero."""
    if targets.ndim != 2 or targets.shape[1] != 8 or targets.shape[0] == 0:
        raise ValueError('Nonempty targets with eight metrics required')
    result = {}
    for j, (metric, labels) in enumerate(LABEL_ORDER.items()):
        counts = torch.bincount(targets[:, j], minlength=len(labels)).float()
        present = counts.gt(0)
        weights = torch.zeros_like(counts)
        weights[present] = len(targets) / (present.sum() * counts[present])
        result[metric] = weights
    return result


def multihead_loss(logits, targets, weights):
    return torch.stack([nn.functional.cross_entropy(logits[m], targets[:, j], weight=weights[m])
                        for j, m in enumerate(TARGET_METRICS)]).mean()


def tokenize_descriptions(tokenizer, descriptions, max_length):
    texts, audit = preprocess_descriptions(descriptions)
    raw = tokenizer(texts.tolist(), truncation=False, padding=False, verbose=False)
    lengths = [len(ids) for ids in raw['input_ids']]
    audit = {**audit, 'token_rows': len(lengths),
             'truncated_rows': sum(n > max_length for n in lengths), 'max_length': max_length}
    tokens = tokenizer(texts.tolist(), max_length=max_length, truncation=True,
                       padding='max_length', return_tensors='pt')
    return {k: tokens[k] for k in ('input_ids', 'attention_mask')}, audit


def save_model(model, tokenizer, folder, metadata):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    model.encoder.config.save_pretrained(folder)
    tokenizer.save_pretrained(folder)
    save_file({k: v.detach().cpu().contiguous() for k, v in model.state_dict().items()},
              str(folder / 'model.safetensors'))
    (folder / 'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf-8')


def load_model(folder, device='cpu'):
    folder = Path(folder)
    meta = json.loads((folder / 'metadata.json').read_text(encoding='utf-8'))
    if meta['label_order'] != {k: list(v) for k, v in LABEL_ORDER.items()}:
        raise ValueError('Checkpoint label map mismatch')
    model = MultiHeadDistilBert(DistilBertModel(DistilBertConfig.from_pretrained(folder, local_files_only=True)))
    model.load_state_dict(load_file(str(folder / 'model.safetensors')), strict=True)
    model.to(device).eval()
    tokenizer = AutoTokenizer.from_pretrained(folder, local_files_only=True)
    return model, tokenizer, meta


def infer_tokens(model, tokens, batch_size, device):
    model.eval()
    arrays = []
    with torch.inference_mode():
        for start in range(0, len(tokens['input_ids']), batch_size):
            logits = model(**{k: v[start:start+batch_size].to(device) for k, v in tokens.items()})
            arrays.append(torch.stack([logits[m].argmax(dim=1) for m in TARGET_METRICS], dim=1).cpu())
    return torch.cat(arrays) if arrays else torch.empty((0, 8), dtype=torch.long)


def contract_predictions(frame, class_ids, metadata, usage='evaluation'):
    if usage not in ('evaluation', 'demo'):
        raise ValueError('Unknown prediction usage')
    if frame.cve_id.duplicated().any() or frame.cve_id.isna().any() or len(frame) != len(class_ids):
        raise ValueError('Unique IDs and one prediction per input required')
    if class_ids.ndim != 2 or class_ids.shape[1] != 8:
        raise ValueError('Eight class IDs required')
    for j, labels in enumerate(LABEL_ORDER.values()):
        if (class_ids[:, j] < 0).any() or (class_ids[:, j] >= len(labels)).any():
            raise ValueError('Class ID out of range')
    if usage == 'evaluation':
        if not frame['split'].isin(['validation', 'test']).all():
            raise ValueError('Evaluation requires held-out rows')
        if not frame.dataset_version.eq(metadata['dataset_version']).all():
            raise ValueError('Dataset version mismatch')
    rows = []
    for row, classes in zip(frame.to_dict('records'), class_ids.tolist()):
        labels = {m: LABEL_ORDER[m][classes[j]] for j, m in enumerate(TARGET_METRICS)}
        vector = labels_to_vector(labels)
        rows.append({'cve_id': row['cve_id'], 'split': row.get('split'),
                     'dataset_version': metadata['dataset_version'], 'model_version': metadata['model_version'],
                     'prediction_usage': usage, **{f'pred_{m}': v for m, v in labels.items()},
                     'predicted_vector': vector, 'predicted_base_score': calculate_base_score(vector),
                     'vector_valid': True, 'prediction_error': ''})
    return pd.DataFrame(rows, columns=PREDICTION_COLUMNS)
