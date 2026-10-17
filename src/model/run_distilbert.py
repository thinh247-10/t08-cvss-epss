"""Timeboxed optional DistilBERT experiment on the immutable Phase 1 release.

Stages: prepare (network/cache), smoke (train-only), train (fixed epoch then
validation and locked test). Refuses overwrites and never selects on test.
"""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import math
from pathlib import Path
import random
import time

import numpy as np
import pandas as pd
import torch
import yaml
from transformers import AutoTokenizer, DistilBertModel
from huggingface_hub import HfApi, snapshot_download

from src.collect.verify_phase1 import verify
from src.model.run_phase2 import sha256, write_json
from src.model.data_validation import LABEL_ORDER, validate_model_input
from src.model.evaluate import evaluate_predictions
from src.model.distilbert_multihead import (
    MultiHeadDistilBert, encode_targets, train_class_weights, multihead_loss,
    tokenize_descriptions, save_model, load_model, infer_tokens, contract_predictions,
)


RELEASE = Path('data/processed/phase1_v1_20261010')
CONFIG = Path('config/distilbert.yaml')
PREPARED = Path('models/distilbert_pretrained/prepared.json')


def now():
    return datetime.now(timezone.utc).isoformat()


def seed_all(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.benchmark = False
    torch.set_num_threads(4)


def device_info():
    if not torch.cuda.is_available():
        raise RuntimeError('CUDA unavailable: stop optional extension, do not silently use CPU')
    probe = torch.ones((32, 32), device='cuda')
    (probe @ probe).sum().item()
    return {'name': torch.cuda.get_device_name(0), 'torch': torch.__version__,
            'cuda_runtime': torch.version.cuda, 'total_vram': torch.cuda.get_device_properties(0).total_memory}


def prepare(config):
    if PREPARED.exists():
        raise FileExistsError('Prepared checkpoint already exists; reuse it offline')
    hardware = device_info()
    revision = HfApi().model_info(config['checkpoint']).sha
    folder = snapshot_download(config['checkpoint'], revision=revision,
        cache_dir='models/hf_cache', allow_patterns=['config.json', 'model.safetensors',
        'tokenizer.json', 'tokenizer_config.json', 'vocab.txt', 'special_tokens_map.json'])
    folder = Path(folder).resolve()
    if not (folder / 'model.safetensors').is_file():
        raise FileNotFoundError('Expected safetensors checkpoint')
    write_json(PREPARED, {'checkpoint': config['checkpoint'], 'revision': revision,
        'folder': str(folder), 'hardware': hardware, 'prepared_at': now(),
        'files': {p.name: sha256(p) for p in folder.iterdir() if p.is_file()}})
    print(json.dumps(json.loads(PREPARED.read_text()), indent=2), flush=True)


def initialize(config):
    info = json.loads(PREPARED.read_text())
    if info['checkpoint'] != config['checkpoint']:
        raise ValueError('Prepared checkpoint mismatch')
    folder = Path(info['folder'])
    for name, digest in info['files'].items():
        if sha256(folder / name) != digest:
            raise ValueError('Pretrained checkpoint checksum mismatch')
    tokenizer = AutoTokenizer.from_pretrained(folder, local_files_only=True)
    encoder = DistilBertModel.from_pretrained(folder, local_files_only=True, use_safetensors=True,
                                             attn_implementation='sdpa')
    return MultiHeadDistilBert(encoder).to('cuda'), tokenizer, info


def train_epoch(model, tokens, targets, config, weights, *, smoke=False, budget=21600, log_path=None):
    model.train()
    dataset = torch.utils.data.TensorDataset(tokens['input_ids'], tokens['attention_mask'], targets)
    loader = torch.utils.data.DataLoader(dataset, batch_size=config['batch_size'], shuffle=True,
                  generator=torch.Generator().manual_seed(config['seed']), num_workers=0)
    optimizer = torch.optim.AdamW(model.parameters(), lr=config['learning_rate'],
                                 weight_decay=config['weight_decay'])
    accumulation = config['gradient_accumulation']
    total_batches = min(len(loader), config['smoke_steps']) if smoke else len(loader)
    updates = math.ceil(total_batches / accumulation)
    warmup = max(1, int(updates * config['warmup_fraction']))
    def schedule(step):
        return min((step+1)/warmup, max(0.0, (updates-step)/max(1, updates-warmup)))
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, schedule)
    scaler = torch.amp.GradScaler('cuda')
    optimizer.zero_grad(set_to_none=True)
    weights = {m: w.to('cuda') for m, w in weights.items()}
    started = time.monotonic()
    losses = []
    skipped_updates = 0
    torch.cuda.reset_peak_memory_stats()
    for step, (ids, mask, labels) in enumerate(loader):
        if step >= total_batches:
            break
        if time.monotonic()-started > budget:
            raise TimeoutError('Training budget exhausted; no test evaluation permitted')
        # Last accumulation group can be shorter than the others.
        group_size = min(accumulation, total_batches-(step//accumulation)*accumulation)
        with torch.autocast('cuda', dtype=torch.float16):
            logits = model(ids.to('cuda'), mask.to('cuda'))
            loss = multihead_loss(logits, labels.to('cuda'), weights)
        if not torch.isfinite(loss):
            raise ValueError('Nonfinite loss')
        scaler.scale(loss/group_size).backward()
        if (step+1) % accumulation == 0 or step+1 == total_batches:
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            old_scale = scaler.get_scale()
            scaler.step(optimizer)
            scaler.update()
            if scaler.get_scale() >= old_scale:
                scheduler.step()
            else:
                skipped_updates += 1
            optimizer.zero_grad(set_to_none=True)
        losses.append(loss.item())
        if (step+1) % 100 == 0 or step+1 == total_batches:
            event = {'step': step+1, 'steps': total_batches, 'seconds': time.monotonic()-started,
                     'mean_loss': float(np.mean(losses[-100:]))}
            print(json.dumps(event), flush=True)
            if log_path:
                with Path(log_path).open('a', encoding='utf-8') as handle:
                    handle.write(json.dumps(event)+'\n')
    torch.cuda.synchronize()
    return {'seconds': time.monotonic()-started, 'steps': total_batches,
            'mean_loss': float(np.mean(losses)), 'peak_vram_bytes': torch.cuda.max_memory_allocated(),
            'amp_scale': scaler.get_scale(), 'skipped_amp_updates': skipped_updates}


def smoke(config, output):
    output.mkdir(parents=True, exist_ok=False)
    hardware = device_info()
    seed_all(config['seed'])
    verify(RELEASE, Path('docs/handoffs/phase-1-v1.json'))
    frame = pd.read_parquet(RELEASE/'ml_cohort.parquet')
    train = frame.loc[frame.split.eq('train')].copy()
    sample = train.sample(n=config['smoke_steps']*config['batch_size'], random_state=config['seed'])
    model, tokenizer, info = initialize(config)
    tokens, audit = tokenize_descriptions(tokenizer, sample.description, config['max_length'])
    targets = encode_targets(sample)
    stats = train_epoch(model, tokens, targets, config, train_class_weights(encode_targets(train)), smoke=True)
    small = {k: v[:5] for k, v in tokens.items()}
    predicted = infer_tokens(model, small, 5, 'cuda')
    meta = {'label_order': {m: list(v) for m, v in LABEL_ORDER.items()},
            'dataset_version': config['dataset_version'], 'model_version': 'smoke-only-not-for-results',
            'config': config, 'pretrained_revision': info['revision']}
    save_model(model, tokenizer, output/'smoke_model', meta)
    loaded, _, _ = load_model(output/'smoke_model', 'cuda')
    if not torch.equal(predicted, infer_tokens(loaded, small, 5, 'cuda')):
        raise ValueError('Smoke save/load predictions differ')
    estimate = stats['seconds']/stats['steps'] * math.ceil(len(train)/config['batch_size'])
    # Conservative allowance for validation, test, saving, and thermal slowdown.
    total_estimate = estimate*2.5
    result = {'status': 'passed', 'config_sha256': sha256(CONFIG), 'hardware': hardware,
              'training': stats, 'token_audit': audit, 'save_load_equal': True,
              'estimated_train_seconds': estimate, 'estimated_total_seconds': total_estimate,
              'within_budget': total_estimate+stats['seconds'] < config['machine_budget_seconds'],
              'sample_ids': sample.cve_id.tolist(), 'usage': 'train_only_smoke_not_evaluation'}
    write_json(output/'smoke.json', result)
    print(json.dumps({k:v for k,v in result.items() if k!='sample_ids'}, indent=2), flush=True)


def train(config, output, smoke_path):
    smoke_result = json.loads(smoke_path.read_text())
    if smoke_result['status'] != 'passed' or not smoke_result['within_budget']:
        raise ValueError('Smoke/time gate did not pass')
    if smoke_result['config_sha256'] != sha256(CONFIG):
        raise ValueError('Configuration changed after smoke')
    if config['epochs'] != 1 or config['selection'] != 'single_predeclared_epoch_no_search':
        raise ValueError('This runner implements one fixed epoch only')
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    verify(RELEASE, Path('docs/handoffs/phase-1-v1.json'))
    frame = pd.read_parquet(RELEASE/'ml_cohort.parquet')
    validate_model_input(frame, dataset_version=config['dataset_version'])
    train_frame = frame.loc[frame.split.eq('train')].copy()
    validation = frame.loc[frame.split.eq('validation')].copy()
    seed_all(config['seed'])
    hardware = device_info()
    model, tokenizer, info = initialize(config)
    tokens, train_audit = tokenize_descriptions(tokenizer, train_frame.description, config['max_length'])
    targets = encode_targets(train_frame)
    weights = train_class_weights(targets)
    declaration = {'started_at': now(), 'config': config, 'config_sha256': sha256(CONFIG),
         'pretrained_revision': info['revision'], 'dataset_sha256': sha256(RELEASE/'ml_cohort.parquet'),
         'hardware': hardware, 'class_weights_train_only': {m:w.tolist() for m,w in weights.items()},
         'library_versions': {p: importlib.metadata.version(p) for p in ('torch','transformers','safetensors','numpy','pandas')}}
    declaration['source_sha256'] = {name:sha256(name) for name in (
        'src/model/run_distilbert.py','src/model/distilbert_multihead.py','src/model/evaluate.py')}
    write_json(output/'declaration.json', declaration)
    remaining = config['machine_budget_seconds']-smoke_result['training']['seconds']-(time.monotonic()-started)
    print('TRAIN START: fixed one epoch, no test access', flush=True)
    stats = train_epoch(model, tokens, targets, config, weights, budget=remaining,
                        log_path=output/'training.jsonl')
    del tokens, targets
    meta = {'label_order': {m:list(v) for m,v in LABEL_ORDER.items()},
            'dataset_version': config['dataset_version'], 'model_version': config['model_version'],
            'config': config, 'pretrained_revision': info['revision'], 'training': stats,
            'library_versions': declaration['library_versions']}
    save_model(model, tokenizer, output/'model', meta)
    vt, val_audit = tokenize_descriptions(tokenizer, validation.description, config['max_length'])
    vp = contract_predictions(validation, infer_tokens(model, vt, config['eval_batch_size'], 'cuda'), meta)
    vm = evaluate_predictions(validation, vp, model_version=meta['model_version'], dataset_version=meta['dataset_version'])
    vp.to_csv(output/'validation_predictions.csv', index=False)
    write_json(output/'validation_metrics.json', vm)
    loaded, _, _ = load_model(output/'model', 'cuda')
    if not torch.equal(infer_tokens(model, {k:v[:5] for k,v in vt.items()}, 5, 'cuda'),
                       infer_tokens(loaded, {k:v[:5] for k,v in vt.items()}, 5, 'cuda')):
        raise ValueError('Saved model smoke mismatch')
    del loaded, vt
    torch.cuda.empty_cache()
    lock = {'locked_at': now(), 'test_status': 'not_run', 'model_sha256': sha256(output/'model/model.safetensors'),
            'config_sha256': sha256(CONFIG), 'dataset_sha256': declaration['dataset_sha256'],
            'validation_mean_macro_f1': vm['scopes']['all_ml']['validation']['mean_macro_f1']}
    write_json(output/'lock.json', lock)
    if time.monotonic()-started+smoke_result['training']['seconds'] > config['machine_budget_seconds']:
        raise TimeoutError('Time budget reached before test; keep validation-only result')
    # One final test pass AFTER checkpoint/config lock; never fit or select afterwards.
    lock['test_status'] = 'running'
    lock['test_started_at'] = now()
    write_json(output/'lock.json', lock)
    test = frame.loc[frame.split.eq('test')].copy()
    tt, test_audit = tokenize_descriptions(tokenizer, test.description, config['max_length'])
    tp = contract_predictions(test, infer_tokens(model, tt, config['eval_batch_size'], 'cuda'), meta)
    predictions = pd.concat([vp, tp], ignore_index=True)
    predictions.to_csv(output/'predictions.csv', index=False)
    metrics = evaluate_predictions(frame.loc[frame.split.ne('train')], predictions,
                model_version=meta['model_version'], dataset_version=meta['dataset_version'])
    write_json(output/'metrics.json', {'status':'complete', 'models':{'distilbert':metrics},
              'dataset_version':meta['dataset_version'], 'training':stats,
              'token_audit':{'train':train_audit,'validation':val_audit,'test':test_audit},
              'total_seconds':time.monotonic()-started})
    lock['test_status'] = 'complete'
    lock['test_completed_at'] = now()
    write_json(output/'lock.json', lock)
    files = {p.relative_to(output).as_posix(): {'bytes':p.stat().st_size,'sha256':sha256(p)}
             for p in output.rglob('*') if p.is_file()}
    write_json(output/'manifest.json', {'status':'complete','dataset_version':meta['dataset_version'],
              'model_version':meta['model_version'],'files':files})
    print(json.dumps({'status':'complete','training':stats,
           'validation':metrics['scopes']['all_ml']['validation']['mean_macro_f1'],
           'test':metrics['scopes']['all_ml']['test']['mean_macro_f1'],'output':str(output)},indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare','smoke','train'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--smoke-report', type=Path)
    args = parser.parse_args()
    config = yaml.safe_load(CONFIG.read_text())
    if args.stage == 'prepare':
        prepare(config)
    elif args.stage == 'smoke':
        smoke(config, args.output)
    else:
        train(config, args.output, args.smoke_report)


if __name__ == '__main__':
    main()
