# AGENTS.md: StegoVizor 2.0

This file gives future OpenCode sessions the highest-signal context for working in this repo.
Every line below answers: "Would an agent likely miss this without help?" If not, it is omitted.

## 1. Investigation order (highest-value sources first)

- `README.md` — project purpose, supported formats, command summary, architecture diagram
- `pyproject.toml` — package name, version, dependencies, tool config (ruff, mypy), script entrypoint
- `stegoguard/config.py` — Config dataclass, all limit fields (`max_file_size_mb`, `max_decompressed_mb`, `max_image_pixels`, `max_archive_depth`, `max_nested_files`, `max_analysis_seconds`), validation rules, `load()`/`save()` flow
- `stegoguard/analyzer.py` — `analyze_file()` entrypoint; file-size check at line 41; PDF dispatch at line 62-66; PNG parsing at line 85-86 with `max_decompressed_bytes`; `load_image()` with `max_pixels` at line 116-117; timeout logic at lines 69-78, 88-98, 129-140
- `stegoguard/monitor.py` — `FolderMonitor`; `_unique_path()` for collision‑free quarantine/sanitize names; `_move_to()` with `os.replace` pattern; `manifest.jsonl` append; `_stable_new_files()` for debouncing; password flows via `_get_password()` in cli.py
- `stegoguard/cli.py` — `_get_password()` priority: `--password-stdin > --password > interactive`; `--password-stdin` added to `analyze`, `sanitize`, `pdf-extract`, `monitor`; warning on `--password` process exposure; subcommand parsers
- CI workflow: `.github/workflows/tests` — Python 3.9–3.12, blocking `ruff` (E9,F63,F7,F82), informational `mypy`, `compileall`, pip cache
- `tests/` — 49 tests total; `run_tests.py` uses unittest discovery; new tests: `test_decompression_limit`, `test_file_size_limit`, `test_monitor_does_not_overwrite_same_names`, `test_monitor_concurrent_same_names`

## 2. Executable commands (agent shortcuts)

| Goal | Command |
|---|---|
| Run all tests | `python run_tests.py` (49 tests, ~5.4 s) |
| Lint (syntax + undefined names, blocking) | `ruff check .` |
| Typecheck (informational) | `mypy .` |
| Lint + typecheck together | `ruff check . && mypy .` |
| Initialize default config | `python main.py init-config config.json` |
| Generate sample dataset | `python main.py samples output_dir --count 5 --seed 7` |
| Benchmark on dataset | `python main.py benchmark dataset_dir` |
| Analyze files/dirs | `python main.py analyze PATH [-r] [--attacks] [--robustness] -o reports` |
| Sanitize PDF+PNG | `python main.py sanitize input [-o out] [--lsb-mode predictive] [--alpha] [--password-stdin]` |
| Extract PDF attachments | `python main.py pdf-extract doc.pdf -o extracted [--password-stdin]` |
| Monitor a directory | `python main.py monitor /path/to/dir [--interval 5] [--quarantine Q] [--clean-dir OK] [--sanitize-dir S]` |
| GUI launch | `python main.py gui` |

**Command ordering that matters**: `lint -> typecheck -> test`. Ruff blocks on syntax/undefined names; mypy is informational only.

## 3. Key architectural facts (not obvious from filenames)

- Package entrypoint: `stegoguard.cli:main` (registered as `stegoguard` script in pyproject.toml)
- Two GUI backends: `gui_modern.py` (CustomTkinter, preferred) and `gui_legacy.py` (fallback Tkinter). UI rename `StegoGuard` → `СтегоВизор` already applied in both.
- Analyzer flow: file size check → PDF dispatch (line 62) → PNG structural parse with `max_decompressed_bytes` cap → statistical analysis with `load_image(raw, max_pixels=cfg.max_image_pixels)` → verdict via `compute_verdict()`.
- `parse_png(src, thresholds, max_decompressed_bytes)` in `png_parser.py` calls `_check_idat` which caps zlib decompression output; exceeding it raises `DECOMPRESSION_LIMIT` finding and skips pixel analysis.
- `FolderMonitor._move_to()` uses temp file + `os.replace` for atomic quarantine/sanitize moves; unique names generated via `sha256+timestamp+uuid` pattern; `manifest.jsonl` appended for every action.
- `--password-stdin` is the safe path; `--password` prints a stderr warning about process exposure.
- Config validation: `validate()` enforces `0 <= payload_suspicious <= payload_stego <= 1`, `0 <= risk_suspicious <= risk_stego <= 100`, all limit fields >= 1, `max_archive_depth >= 0` and `max_nested_files >= 1`.
- PDF analysis is fully static, local, no sandbox/execution. It does NOT decode encrypted PDFs without `--password`.
- JPEG, BMP, TIFF, WEBP, GIF: only statistical pixel analysis via Pillow; no structural checks or sanitization implemented.

## 4. Testing quirks

- New tests added: `test_decompression_limit` (png_parser), `test_file_size_limit`, `test_monitor_does_not_overwrite_same_names`, `test_monitor_concurrent_same_names` (robustness_reports).
- Tests expect exact filenames in some cases (`test_monitor_quarantine` checks `q/bad.png` and `ok/clean.png`); if quarantine naming changes, update test expectations.
- `run_tests.py` uses `unittest.defaultTestLoader.discover("tests", top_level_dir=".")` — no custom runner config.
- Fuzz testing not started (goal: 24 h). Real dataset goal: ≥300 labeled files.
- Coverage not measured (goal: ≥70%). Run with `python -m pytest tests/ -coveragetype=html` if needed.

## 5. Environment / setup gotchas

- Python ≥3.9 required. Dependencies: numpy, scipy, Pillow, matplotlib, pypdf, customtkinter.
- `.gitignore` already tracks `__pycache__/`, `.venv/`, `build/`, `dist/`, `*.egg-info/`, IDE files, OS files, logs, temp files, and backup/backup docx files.
- CI runs on Python 3.9–3.12. Local development: `pip install -r requirements.txt` then `pip install -e .` for `stegoguard` command.
- Offline install: `pip install --no-index --find-links ./wheelhouse -r requirements.txt` (no network at runtime).
- `--password` appears in `ps`/process list — always prefer `--password-stdin` for sensitive PDFs.
- `DEPLOYMENT_OFFLINE.md` references the offline install procedure; keep it in sync with `requirements.txt` and `wheelhouse/` if one exists.

## 6. What to extract / verify before starting work

- Read `README.md` architecture diagram and `ROADMAP.md` for current milestone (M0–M12).
- Verify the Config limit fields match the code: `max_file_size_mb=512`, `max_decompressed_mb=256`, `max_image_pixels=64_000_000`, `max_archive_depth=3`, `max_nested_files=1000`, `max_analysis_seconds=300`.
- Check that `png_parser.py:_check_idat` accepts `max_decompressed_bytes` and raises `DECOMPRESSION_LIMIT` — this was recently added but not yet fully wired in all paths.
- Confirm `monitor.py:_unique_path` uses the `sha256+timestamp+uuid` pattern to avoid name collisions in quarantine/clean/sanitize dirs.
- Ensure `cli.py:_get_password` priority (`--password-stdin > --password > interactive`) is used in all subcommand callers (analyze, sanitize, pdf-extract, monitor).
- If adding a new file-type analyzer, follow the pattern: `analyze_file` → file‑size check → format dispatch → per‑format parse → statistical analysis → verdict.