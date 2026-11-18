"""Оркестратор анализа: структура PNG + статистический стегоанализ + заключение."""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional

from . import __version__
from .analysis import image_complexity, run_statistical
from .attacks import assess_attacks
from .config import Config
from .image_io import UnsupportedImageError, load_image
from .png_parser import parse_png
from .robustness import assess_robustness
from .scoring import compute_verdict
from .utils import sha256_file, to_jsonable

log = logging.getLogger("stegoguard")


class Analyzer:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    def analyze_file(self, path: str, robustness: bool = False, attacks: bool = False,
                     progress: Optional[Callable[[float], None]] = None,
                     password: Optional[str] = None) -> Dict:
        cfg = self.config
        t0 = time.perf_counter()
        timeout = cfg.max_analysis_seconds
        timeout_exceeded = False
        result: Dict = {
            "tool": "СтегоВизор", "version": __version__,
            "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "file": os.path.abspath(path), "file_name": os.path.basename(path),
        }
        try:
            file_size = os.path.getsize(path)
            if file_size > cfg.max_file_size_bytes:
                result.update({
                    "file_size": file_size,
                    "error_code": "FILE_TOO_LARGE",
                    "verdict": "ERROR",
                    "verdict_label": "Ошибка анализа",
                    "risk_score": None,
                    "reasons": [
                        f"Размер файла {file_size} байт превышает лимит "
                        f"{cfg.max_file_size_bytes} байт ({cfg.max_file_size_mb} МБ)."
                    ],
                    "recommendations": [
                        "Уменьшить файл или увеличить max_file_size_mb в конфигурации с учётом доступной памяти."
                    ],
                })
                result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
                log.warning("%s: превышен лимит размера файла (%s байт)", path, file_size)
                return to_jsonable(result)
            with open(path, "rb") as fh:
                head = fh.read(1024)
            ext = os.path.splitext(path)[1].lower()
            if ext == ".pdf" or b"%PDF-" in head:
                from .pdf_analyzer import analyze_pdf
                result = analyze_pdf(path, cfg, password=password)
                log.info("%s -> %s (PDF, риск %s)", path, result["verdict"], result.get("risk_score"))
                return result
            with open(path, "rb") as fh:
                raw = fh.read()
            if time.perf_counter() - t0 > timeout:
                timeout_exceeded = True
                result.update({
                    "verdict": "ERROR",
                    "verdict_label": "Таймаут анализа",
                    "risk_score": None,
                    "reasons": [f"Анализ превысил лимит {timeout} сек"],
                    "recommendations": ["Уменьшить размер входного файла или увеличить max_analysis_seconds в конфигурации."],
                })
                result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
                log.warning("%s: анализ превысил таймаут %s сек", path, timeout)
                return to_jsonable(result)
            result["file_size"] = len(raw)
            result["sha256"] = sha256_file(path)
            is_png = raw.startswith(b"\x89PNG\r\n\x1a\n")
            if is_png:
                structure = parse_png(raw, cfg.thresholds,
                                      max_decompressed_bytes=cfg.max_decompressed_bytes)
                result["structure"] = structure.to_dict()
            if time.perf_counter() - t0 > timeout:
                timeout_exceeded = True
                result.update({
                    "verdict": "ERROR",
                    "verdict_label": "Таймаут анализа",
                    "risk_score": None,
                    "reasons": [f"Анализ превысил лимит {timeout} сек"],
                    "recommendations": ["Уменьшить размер входного файла или увеличить max_analysis_seconds в конфигурации."],
                })
                result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
                log.warning("%s: анализ превысил таймаут %s сек", path, timeout)
                return to_jsonable(result)
            else:
                result["format"] = (os.path.splitext(path)[1].lstrip(".").upper() or "IMAGE")
                result["structure"] = {"findings": [], "chunk_summary": {}, "trailing_bytes": 0}
                result["format_note"] = "Для данного растрового формата выполнен статистический анализ пикселей; структурные проверки PNG неприменимы."
            stats = None
            decompression_limited = is_png and any(
                f.get("code") == "DECOMPRESSION_LIMIT" for f in result["structure"].get("findings", [])
            )
            if decompression_limited:
                result["image_error"] = (
                    f"Распаковка IDAT остановлена: превышен лимит {cfg.max_decompressed_mb} МБ. "
                    "Пиксельный анализ пропущен для защиты памяти."
                )
                log.warning("%s: %s", path, result["image_error"])
            else:
                try:
                    img = load_image(raw, include_alpha=cfg.include_alpha,
                                     max_pixels=cfg.max_image_pixels)
                    result["image"] = {"width": img.width, "height": img.height, "mode": img.mode,
                                       "bit_depth": 16 if img.max_value > 255 else 8,
                                       "channels": list(img.channels), "samples": img.n_samples,
                                       "has_alpha": img.alpha is not None}
                    work = img.crop_center(cfg.analysis_max_pixels)
                    if work is not img:
                        result["image"]["analyzed_fragment"] = f"{work.width}x{work.height}"
                    stats = run_statistical(work.channels, work.max_value, cfg.thresholds, full=True,
                                            palette=img.is_palette)
                    result["statistics"] = stats
                    result["complexity"] = image_complexity(work.channels, work.max_value)
                    if time.perf_counter() - t0 > timeout:
                        timeout_exceeded = True
                        result.update({
                            "verdict": "ERROR",
                            "verdict_label": "Таймаут анализа",
                            "risk_score": None,
                            "reasons": [f"Анализ превысил лимит {timeout} сек"],
                            "recommendations": ["Уменьшить размер входного файла или увеличить max_analysis_seconds в конфигурации."],
                        })
                        result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
                        log.warning("%s: анализ превысил таймаут %s сек", path, timeout)
                        return to_jsonable(result)
                    if robustness:
                        result["robustness"] = assess_robustness(img, cfg, progress)
                    if attacks:
                        result["attacks"] = assess_attacks(img, cfg)
                except UnsupportedImageError as exc:
                    result["image_error"] = str(exc)
                    log.warning("%s: %s", path, exc)
            if is_png:
                result.update(compute_verdict(stats, structure, cfg.thresholds))
            else:
                from types import SimpleNamespace
                result.update(compute_verdict(stats, SimpleNamespace(structural_risk=0.0, findings=[]), cfg.thresholds))
            if result.get("image_error") and not stats:
                result.update({"verdict": "ERROR", "verdict_label": "Ошибка анализа", "risk_score": None,
                               "reasons": [("PNG: " if ext in {".png", ".apng"} else "") + result["image_error"]], "recommendations": ["Проверить целостность файла и соответствие расширения фактическому формату."]})
        except Exception as exc:  # noqa: BLE001
            log.exception("Ошибка анализа %s", path)
            result.update({"verdict": "ERROR", "verdict_label": "Ошибка анализа", "error": str(exc),
                           "risk_score": None, "reasons": [str(exc)], "recommendations": []})
        result["elapsed_sec"] = round(time.perf_counter() - t0, 3)
        log.info("%s -> %s (риск %s)", path, result["verdict"], result.get("risk_score"))
        return to_jsonable(result)

    def analyze_many(self, paths: Iterable[str], robustness: bool = False, attacks: bool = False,
                     callback: Optional[Callable[[int, int, Dict], None]] = None,
                     password: Optional[str] = None) -> List[Dict]:
        paths = list(paths)
        results = []
        for i, p in enumerate(paths, 1):
            r = self.analyze_file(p, robustness=robustness, attacks=attacks, password=password)
            results.append(r)
            if callback:
                callback(i, len(paths), r)
        return results
