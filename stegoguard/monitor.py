"""Режим непрерывного контроля каталога (шлюз приёма изображений в промышленный сегмент)."""
from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
import uuid
from typing import Dict, Optional, Tuple

from .analyzer import Analyzer
from .database import History
from .report import save_html, save_json
from .sanitizer import sanitize
from .scoring import VERDICT_ORDER
from .utils import collect_files

log = logging.getLogger("stegoguard.monitor")


class FolderMonitor:
    def __init__(self, analyzer: Analyzer, folder: str, interval: float = 5.0, recursive: bool = False,
                 quarantine_dir: Optional[str] = None, clean_dir: Optional[str] = None,
                 sanitize_dir: Optional[str] = None, report_dir: Optional[str] = None,
                 history: Optional[History] = None, quarantine_level: str = "SUSPICIOUS",
                 password: Optional[str] = None):
        self.analyzer = analyzer
        self.folder = folder
        self.interval = interval
        self.recursive = recursive
        self.quarantine_dir = quarantine_dir
        self.clean_dir = clean_dir
        self.sanitize_dir = sanitize_dir
        self.report_dir = report_dir
        self.history = history
        self.quarantine_level = quarantine_level
        self.password = password
        self._seen: Dict[str, Tuple[float, int]] = {}
        self._pending: Dict[str, Tuple[float, int]] = {}
        self._manifest_lock = threading.Lock()
        self.processed = 0

    @staticmethod
    def _unique_path(directory: str, filename: str, result: Optional[Dict] = None) -> str:
        """Возвращает свободное имя, не перезаписывая уже помещённые файлы."""
        os.makedirs(directory, exist_ok=True)
        stem, ext = os.path.splitext(filename)
        digest = str((result or {}).get("sha256") or "")[:12]
        tag = digest or uuid.uuid4().hex[:12]
        base = f"{stem}_{time.strftime('%Y%m%dT%H%M%S')}_{tag}_{uuid.uuid4().hex[:8]}"
        dst = os.path.join(directory, base + ext)
        counter = 1
        while os.path.exists(dst):
            dst = os.path.join(directory, f"{base}_{counter}{ext}")
            counter += 1
        return dst

    def _append_manifest(self, directory: str, result: Dict, source: str,
                         destination: str, action: str) -> None:
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source": os.path.abspath(source),
            "destination": os.path.abspath(destination),
            "action": action,
            "verdict": result.get("verdict"),
            "risk_score": result.get("risk_score"),
            "sha256": result.get("sha256"),
            "file_name": os.path.basename(source),
        }
        with self._manifest_lock:
            with open(os.path.join(directory, "manifest.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _move_to(self, source: str, directory: str, result: Dict) -> str:
        """Перемещает файл под уникальным именем; временный файл исключает недописанные копии."""
        destination = self._unique_path(directory, os.path.basename(source), result)
        temporary = f"{destination}.part-{uuid.uuid4().hex[:8]}"
        try:
            shutil.move(source, temporary)
            os.replace(temporary, destination)
        except Exception:
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except OSError:
                pass
            raise
        return destination

    def _stable_new_files(self):
        ready = []
        for path in collect_files([self.folder], recursive=self.recursive):
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            sig = (st.st_mtime, st.st_size)
            if self._seen.get(path) == sig:
                continue
            if self._pending.get(path) == sig:     # размер не меняется между опросами -> запись завершена
                ready.append(path)
                self._pending.pop(path, None)
            else:
                self._pending[path] = sig
        return ready

    def process(self, path: str) -> Dict:
        source_path = path
        result = self.analyzer.analyze_file(path, password=self.password)
        stem = os.path.splitext(os.path.basename(path))[0]
        if self.report_dir:
            ts = time.strftime("%Y%m%d_%H%M%S")
            json_path = self._unique_path(self.report_dir, f"{stem}_{ts}.json")
            save_json(result, json_path)
            if result["verdict"] != "CLEAN":
                html_path = self._unique_path(self.report_dir, f"{stem}_{ts}.html")
                save_html(result, html_path, path)
        if self.history:
            self.history.add(result)
        dangerous = VERDICT_ORDER.get(result["verdict"], 3) >= VERDICT_ORDER[self.quarantine_level]
        action = "оставлен"
        if dangerous and self.quarantine_dir:
            dst = self._move_to(path, self.quarantine_dir, result)
            action = f"помещён в карантин: {dst}"
            self._append_manifest(self.quarantine_dir, result, source_path, dst, action)
            path = dst
        if self.sanitize_dir and result["verdict"] != "ERROR" and (not dangerous or not self.quarantine_dir):
            ext = os.path.splitext(path)[1].lower()
            dst = self._unique_path(self.sanitize_dir, os.path.basename(path), result)
            temporary = f"{dst}.part-{uuid.uuid4().hex[:8]}"
            try:
                if result.get("format") == "PDF" or ext == ".pdf":
                    from .pdf_sanitizer import sanitize_pdf
                    cfg = getattr(self.analyzer, "config", None)
                    rep = sanitize_pdf(
                        path, temporary, password=self.password,
                        reencode_images=getattr(getattr(cfg, "pdf", None), "sanitize_reencode_images", True),
                        remove_hidden_text=getattr(getattr(cfg, "pdf", None), "sanitize_remove_hidden_text", True),
                    )
                    os.replace(temporary, dst)
                    action += (f"; санитизированная копия PDF: {dst} "
                               f"(изображений перекодировано {rep['images_reencoded']}, "
                               f"скрытых символов {rep['removed_hidden_chars']})")
                    self._append_manifest(self.sanitize_dir, result, path, dst, action)
                elif ext in {".png", ".apng"}:
                    sanitize(path, temporary)
                    os.replace(temporary, dst)
                    action += f"; санитизированная копия: {dst}"
                    self._append_manifest(self.sanitize_dir, result, path, dst, action)
                else:
                    action += "; автоматическая санитизация этого формата не поддерживается"
            except Exception as exc:  # noqa: BLE001
                try:
                    if os.path.exists(temporary):
                        os.remove(temporary)
                except OSError:
                    pass
                action += f"; ошибка санитизации: {exc}"
                log.exception("Ошибка санитизации %s", path)
        elif self.clean_dir and not dangerous and os.path.exists(path):
            dst = self._move_to(path, self.clean_dir, result)
            action = f"передан: {dst}"
            self._append_manifest(self.clean_dir, result, source_path, dst, action)
        level = logging.WARNING if dangerous else logging.INFO
        log.log(level, "[%s] %s риск=%s -> %s", result["verdict"], os.path.basename(path), result.get("risk_score"), action)
        result["monitor_action"] = action
        self.processed += 1
        return result

    def run(self, stop_event: Optional[threading.Event] = None, max_cycles: Optional[int] = None) -> None:
        log.info("Контроль каталога %s (интервал %.1f с)", self.folder, self.interval)
        cycles = 0
        while not (stop_event and stop_event.is_set()):
            for path in self._stable_new_files():
                try:
                    st = os.stat(path)
                    self.process(path)
                    self._seen[path] = (st.st_mtime, st.st_size)
                except Exception:  # noqa: BLE001
                    log.exception("Ошибка обработки %s", path)
                    self._seen[path] = (0, -1)
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            if stop_event:
                stop_event.wait(self.interval)
            else:
                time.sleep(self.interval)
