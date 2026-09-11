# Qwen V2.2 portable cloud worker

This directory is copied into every exported cloud batch. It contains only the
immutable inference input, public classifier contract, and portable worker. It
never connects to the local database and contains no `.env`, database file, or
credential.

---

## KAGGLE QUICK START

1. Create or open a Kaggle notebook.
2. Enable GPU accelerator in Kaggle Settings.
3. Enable Internet access in Kaggle Settings.
4. Add the exported `cloud_batch_kaggle-<batch-id>.zip` as a dataset input.
5. Open `qwen_kaggle.ipynb` and click **Run All**.
6. Download the generated `<batch-id>-results.jsonl` from the output panel.
7. Place it in `data\cloud_results\` on your local machine.
8. Run `.\cloud-import.ps1`.

---

## COLAB QUICK START

1. Open `qwen_colab.ipynb` in Google Colab.
2. Select a GPU runtime: *Runtime → Change runtime type → GPU*.
3. Upload `cloud_batch_colab-<batch-id>.zip` to `/content` (Colab Files panel → Upload).
4. Click **Run All**.
5. Download the generated `<batch-id>-results.jsonl` from the Files panel.
6. Place it in `data\cloud_results\` on your local machine.
7. Run `.\cloud-import.ps1`.

---

## Resuming an interrupted run

The worker appends and `fsync`s each successful result. Re-running the notebook
with an existing `results.jsonl` skips immutable `(rule_id, context_sha256)`
successes. Failed attempts are recorded separately in `errors.jsonl` and remain
retryable.

## Manual Colab or Linux GPU run

Install Ollama and the Python requirements, start `ollama serve`, pull the model
named in `manifest.json`, then run:

```bash
python worker.py --manifest manifest.json --input input.jsonl \
  --output results.jsonl --errors errors.jsonl --environment colab
```

Ollama engine version, model digest, platform, and environment are recorded in
every result. The local importer reruns Qwen V2.2 canonicalization, MITRE
hardening, shared finalization, and deterministic validation before committing.
