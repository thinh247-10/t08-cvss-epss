"""Offline tiny encoder tests; no pretrained downloads or real-data training."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

AVAILABLE = all(importlib.util.find_spec(name) is not None for name in ('torch','transformers','safetensors'))


@unittest.skipUnless(AVAILABLE, 'Optional DistilBERT dependencies not installed')
class DistilBertTests(unittest.TestCase):
    def setUp(self):
        import torch
        from transformers import DistilBertConfig, DistilBertModel
        from src.model.distilbert_multihead import MultiHeadDistilBert
        torch.manual_seed(42)
        self.model = MultiHeadDistilBert(DistilBertModel(DistilBertConfig(
            vocab_size=40, dim=16, hidden_dim=32, n_layers=1, n_heads=2, dropout=0.0, attention_dropout=0.0)))
        self.ids = torch.tensor([[2,5,6,3],[2,7,8,3]])
        self.mask = torch.ones_like(self.ids)

    def test_eight_heads_and_shared_encoder_receive_gradients(self):
        import torch
        from src.model.distilbert_multihead import multihead_loss, train_class_weights, LABEL_ORDER
        targets = torch.tensor([[0]*8,[1]*8])
        logits = self.model(self.ids, self.mask)
        self.assertEqual({k:v.shape[1] for k,v in logits.items()}, {k:len(v) for k,v in LABEL_ORDER.items()})
        loss = multihead_loss(logits, targets, train_class_weights(targets))
        self.assertTrue(torch.isfinite(loss))
        loss.backward()
        self.assertGreater(self.model.encoder.embeddings.word_embeddings.weight.grad.abs().sum().item(), 0)
        for head in self.model.heads.values():
            self.assertGreater(head.weight.grad.abs().sum().item(), 0)

    def test_train_weights_absent_classes_and_contract_guards(self):
        import torch
        import pandas as pd
        from src.model.distilbert_multihead import train_class_weights, contract_predictions
        weights = train_class_weights(torch.zeros((4,8),dtype=torch.long))
        self.assertEqual(weights['AV'].tolist(), [1.0,0.0,0.0,0.0])
        with self.assertRaises(ValueError):
            train_class_weights(torch.empty((0,8),dtype=torch.long))
        frame = pd.DataFrame({'cve_id':['CVE-2024-1234'],'split':['validation'],'dataset_version':['v1']})
        meta = {'dataset_version':'v1','model_version':'test'}
        result = contract_predictions(frame, torch.zeros((1,8),dtype=torch.long), meta)
        self.assertTrue(result.vector_valid.all())
        self.assertEqual(result.predicted_base_score.iloc[0], 0.0)
        with self.assertRaises(ValueError):
            contract_predictions(frame.assign(split='train'), torch.zeros((1,8),dtype=torch.long), meta)
        with self.assertRaises(ValueError):
            contract_predictions(frame, torch.full((1,8),-1,dtype=torch.long), meta)

    def test_safetensors_reload_preserves_all_logits(self):
        import torch
        from transformers import BertTokenizer
        from src.model.distilbert_multihead import save_model, load_model, LABEL_ORDER
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vocab = root/'vocab.txt'
            vocab.write_text('[PAD]\n[UNK]\n[CLS]\n[SEP]\n[MASK]\na\nb\nc\nd\n',encoding='utf-8')
            tokenizer = BertTokenizer(vocab_file=str(vocab))
            self.model.eval()
            before = self.model(self.ids, self.mask)
            save_model(self.model, tokenizer, root/'model', {'label_order':{k:list(v) for k,v in LABEL_ORDER.items()}})
            loaded, _, _ = load_model(root/'model')
            after = loaded(self.ids, self.mask)
            for key in before:
                torch.testing.assert_close(before[key], after[key], rtol=0, atol=0)


if __name__ == '__main__':
    unittest.main()
