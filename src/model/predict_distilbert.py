"""Verify the completed DistilBERT bundle, then run one offline demo description."""
import argparse
import json
from pathlib import Path
import pandas as pd
from src.model.run_phase2 import sha256


def verify_bundle(folder):
    folder = Path(folder).resolve()
    manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    if manifest['status'] != 'complete':
        raise ValueError('Bundle is not complete')
    for name, entry in manifest['files'].items():
        path = (folder/name).resolve()
        if not path.is_relative_to(folder) or not path.is_file():
            raise ValueError('Unsafe or absent bundle file')
        if path.stat().st_size != entry['bytes'] or sha256(path) != entry['sha256']:
            raise ValueError(f'Bundle checksum mismatch: {name}')
    if 'model/model.safetensors' not in manifest['files'] or 'model/metadata.json' not in manifest['files']:
        raise ValueError('Model files are not covered by manifest')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--description', required=True)
    parser.add_argument('--device', choices=['cpu','cuda'], default='cpu')
    args = parser.parse_args()
    if not args.description.strip():
        parser.error('Description must be nonblank')
    manifest = verify_bundle(args.bundle)
    from src.model.distilbert_multihead import load_model, tokenize_descriptions, infer_tokens, contract_predictions
    model, tokenizer, metadata = load_model(args.bundle/'model', args.device)
    if metadata['model_version'] != manifest['model_version'] or metadata['dataset_version'] != manifest['dataset_version']:
        raise ValueError('Manifest and model versions disagree')
    frame = pd.DataFrame({'cve_id':['demo-description'],'description':[args.description]})
    tokens, _ = tokenize_descriptions(tokenizer, frame.description, metadata['config']['max_length'])
    predictions = contract_predictions(frame, infer_tokens(model,tokens,1,args.device), metadata, usage='demo')
    print(predictions.to_json(orient='records', indent=2))


if __name__ == '__main__':
    main()
