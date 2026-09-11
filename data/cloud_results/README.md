# cloud_results

Place downloaded cloud batch result files here.

Expected filename pattern:

    kaggle-YYYYMMDD-NNN-results.jsonl
    colab-YYYYMMDD-NNN-results.jsonl

Then run from the project root:

    .\cloud-import.ps1

The importer is idempotent — running it twice creates no duplicates.
