StegoVizor 2.0 — Session State (2026-11-18)

Completed: M0-01 (name+passport+docs), M0-02 (CI), M1-01 (limits+timeout), M1-02 (atomic quarantine), M1-03 (password stdin)
Remaining: M1-04 (SQLite hash chain), M1-05 (signed build+SBOM), M2 (JPEG/DCT+archives), M3 (real dataset/calibration), M3-4 (pilot/certification), M4 (product release)

Key metrics: 49/49 tests passing, config fields (max_file_size_mb=512, max_decompressed_mb=256, max_image_pixels=64M, max_analysis_seconds=300), DECOMPRESSION_LIMIT finding, atomic quarantine with manifest, CLI password hygiene (--password-stdin), UI renamed to СтегоВизор.

Next task: M1-04 — add hash-chain integrity to History/SQLite journal.