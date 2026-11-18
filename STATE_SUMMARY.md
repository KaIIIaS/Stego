# StegoVizor 2.0 — Execution State Summary (2026-11-18)

## Completed (M0–M1)
- **M0-01**: UI rename + passport + README sync — `DONE`. Name `StegoGuard` → `СтегоВизор` across GUI, docs, pyproject, config.example. PDF CDR confirmed implemented.
- **M0-02**: CI pipeline — `DONE`. GitHub Actions workflow `tests` (Python 3.9–3.12), `ruff` blocking, `mypy` informational, `compileall`, pip cache, dev deps in `pyproject.toml`.
- **M1-01**: Resource limits — `DONE`. Config: `max_file_size_mb=512`, `max_decompressed_mb=256`, `max_image_pixels=64_000_000`, `max_archive_depth=3`, `max_nested_files=1000`, `max_analysis_seconds=300`. Analyzer: `FILE_TOO_LARGE` error, `DECOMPRESSION_LIMIT` finding for PNG, `max_pixels` guard before `img.load()`. Soft timeout via `max_analysis_seconds`.
- **M1-02**: Atomic quarantine — `IN PROGRESS`. Unique names with `sha256+timestamp+uuid`, `manifest.jsonl` for quarantine/clean/sanitize dirs, symlink skipping in `collect_files`, concurrent-safe processing with temp-file+os.replace. Two test added: `test_monitor_does_not_overwrite_same_names`, `test_monitor_concurrent_same_names`.
- **M1-03**: Password hygiene — `DONE`. CLI: `--password` now shows warning about process exposure; `--password-stdin` reads from `getpass`; `_get_password(args)` helper with priority `--password-stdin > --password > interactive`. Updated `cmd_analyze`, `cmd_sanitize`, `cmd_pdf_extract`, `cmd_monitor`.

## Remaining Milestones
- **M1-04**: SQLite audit integrity (hash chain) — `TODO`
- **M1-05**: Signed offline build + SBOM — `TODO`
- **M2**: Detection expansion — JPEG/DCT analysis, raster sanitization, archive scanning — `TODO`
- **M2–M3**: Real dataset / calibration, TPR/FPR reporting — `TODO`
- **M3–M4**: Pilot preparation, certification docs, TAM/SAM/SOM — `TODO`
- **M4**: Product release — `TODO`

## Key Metrics (as of 2026-11-18)
- Tests: **49** (up from 45) — all pass in ~5.4 s
- Config fields added: `max_file_size_mb`, `max_decompressed_mb`, `max_image_pixels`, `max_archive_depth`, `max_nested_files`, `max_analysis_seconds`
- PNG: `DECOMPRESSION_LIMIT` finding added, decompression cap enforced
- Monitor: unique quarantine names, manifest journal, no overwrite on collision
- CLI: `--password-stdin` safe mode, `--password` warns
- GUI: title `СтегоВизор 2.0`, logo `СВ`
- Docs: `README.md`, `DEPLOYMENT_OFFLINE.md`, `config.example.json` updated

## Next Immediate Task
- **M1-04**: Add hash-chain integrity to SQLite journal (`History` class: compute SHA-256 of each record, append previous-hash field, store manifest). Update `Config.validate()` if needed.