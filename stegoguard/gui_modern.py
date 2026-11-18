"""Современный графический интерфейс СтегоВизор на CustomTkinter.

Оформление повторяет привычную веб-панель: тёмная шапка, светлый фон,
карточки со сводкой, таблица очереди и карточка результата. Все операции
выполняются локально; интерфейс не открывает браузер и не использует сеть.
"""
from __future__ import annotations

import os
import queue
import sys
import threading
from collections import Counter
from typing import Dict, List, Optional, Tuple

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __app_name__, __version__
from .analyzer import Analyzer
from .config import Config
from .utils import collect_files, human_bytes

if sys.platform.startswith("win"):
    UI_FONT = "Segoe UI"
elif sys.platform == "darwin":
    UI_FONT = "SF Pro Text"
else:
    UI_FONT = "DejaVu Sans"

BG = "#F3F6FA"
CARD = "#FFFFFF"
BORDER = "#E2E8F0"
TEXT = "#162033"
MUTED = "#64748B"
SUBTLE = "#F8FAFC"
PRIMARY = "#2563EB"
PRIMARY_HOVER = "#1D4ED8"
NAVY = "#0F172A"
GREEN = "#15803D"
GREEN_BG = "#ECFDF5"
AMBER = "#B45309"
AMBER_BG = "#FFFBEB"
RED = "#B91C1C"
RED_BG = "#FEF2F2"
GRAY = "#475569"
GRAY_BG = "#F1F5F9"

VERDICT_STYLES = {
    "CLEAN": (GREEN, GREEN_BG, "Чисто"),
    "SUSPICIOUS": (AMBER, AMBER_BG, "Подозрительно"),
    "STEGO_DETECTED": (RED, RED_BG, "Обнаружено"),
    "ERROR": (GRAY, GRAY_BG, "Ошибка"),
}

FILTERS = {
    "Все": None,
    "Чистые": "CLEAN",
    "Подозрительные": "SUSPICIOUS",
    "Обнаружено": "STEGO_DETECTED",
}


def _clear(widget: tk.Misc) -> None:
    for child in widget.winfo_children():
        child.destroy()


def _plural(count: int, one: str, few: str, many: str) -> str:
    if count % 10 == 1 and count % 100 != 11:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def _show_value(value, suffix: str = "") -> str:
    if value is None or value == "":
        return "—"
    return f"{value}{suffix}"


def _show_bool(value) -> str:
    return "да" if value else "нет"


def _payload(result: Dict) -> Optional[float]:
    statistics = result.get("statistics") or {}
    if statistics.get("effective_payload") is not None:
        return float(statistics["effective_payload"])
    pdf = result.get("pdf") or {}
    value = pdf.get("max_image_payload")
    return float(value) if value is not None else None


def _format_of(result: Optional[Dict], path: str) -> str:
    if result and result.get("format"):
        return str(result["format"]).upper()
    ext = os.path.splitext(path)[1].lstrip(".").upper()
    return ext or "—"


def _shorten_path(path: str, limit: int = 52) -> str:
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


def _verdict_style(verdict: str) -> Tuple[str, str, str]:
    return VERDICT_STYLES.get(verdict, VERDICT_STYLES["ERROR"])


def run_gui(cfg: Optional[Config] = None) -> None:
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")

    cfg = cfg or Config()
    analyzer = Analyzer(cfg)
    root = ctk.CTk()
    root.title(f"{__app_name__} {__version__}")
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = min(1320, max(1040, screen_width - 80))
    window_height = min(820, max(650, screen_height - 145))
    pos_x = max(20, (screen_width - window_width) // 2)
    pos_y = max(20, (screen_height - window_height) // 2)
    root.geometry(f"{window_width}x{window_height}+{pos_x}+{pos_y}")
    root.minsize(1040, 650)
    root.configure(fg_color=BG)
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(4, weight=1)

    results: Dict[str, Dict] = {}
    files: List[str] = []
    running: set = set()
    messages: queue.Queue = queue.Queue()
    busy = tk.BooleanVar(value=False)
    robustness_var = tk.BooleanVar(value=False)
    attacks_var = tk.BooleanVar(value=False)
    password_var = tk.StringVar(value="")
    filter_var = tk.StringVar(value="Все")
    status_var = tk.StringVar(value="Добавьте PDF или изображения для локального анализа")
    action_buttons: List[ctk.CTkButton] = []
    cards: Dict[str, Tuple[ctk.CTkLabel, ctk.CTkLabel]] = {}

    # ------------------------------------------------------------------ модель
    def selected_path() -> Optional[str]:
        selection = tree.selection()
        return selection[0] if selection else None

    def row_values(path: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        result = results.get(path)
        base = os.path.basename(path)
        if result is None:
            if path in running:
                return ((base, _format_of(None, path), "● Проверяется…", "—", "—", "—"),
                        ("RUNNING",))
            return ((base, _format_of(None, path), "● В очереди", "—", "—", "—"),
                    ("QUEUED",))
        verdict = str(result.get("verdict") or "ERROR")
        _, _, short_label = _verdict_style(verdict)
        risk = result.get("risk_score")
        risk_text = f"{risk:.1f}" if risk is not None else "—"
        payload = _payload(result)
        payload_text = f"{payload:.1%}" if payload is not None else "—"
        findings = (result.get("structure") or {}).get("findings") or []
        count = len([item for item in findings if item.get("severity") != "info"])
        return ((base, _format_of(result, path), f"● {short_label}", risk_text,
                 payload_text, str(count) if count else "—"), (verdict,))

    def matches_filter(path: str) -> bool:
        result = results.get(path)
        query = search_entry.get().strip().lower()
        if query and query not in os.path.basename(path).lower() and query not in path.lower():
            return False
        wanted = FILTERS.get(filter_var.get())
        if wanted is None:
            return True
        return bool(result and result.get("verdict") == wanted)

    def refresh_summary() -> None:
        counts = Counter(str(item.get("verdict") or "ERROR") for item in results.values())
        total = len(files)
        analyzed = len(results)
        errors = counts.get("ERROR", 0)
        cards["total"][0].configure(text=str(total))
        host = f"{analyzed} проверено"
        if errors:
            host += f" · ошибок {errors}"
        cards["total"][1].configure(text=host if analyzed else "файлы ещё не добавлены")
        for key, verdict in (("clean", "CLEAN"), ("suspicious", "SUSPICIOUS"),
                             ("detected", "STEGO_DETECTED")):
            value = counts.get(verdict, 0)
            cards[key][0].configure(text=str(value))
            cards[key][1].configure(
                text=f"{value / analyzed:.0%} от проверенных" if analyzed else "нет проверенных файлов")

    def refresh_tree() -> None:
        chosen = selected_path()
        children = tree.get_children()
        if children:
            tree.delete(*children)
        for path in files:
            if not matches_filter(path):
                continue
            values, tags = row_values(path)
            tree.insert("", "end", iid=path, values=values, tags=tags)
        queue_label.configure(text=f"{len(files)} {_plural(len(files), 'файл', 'файла', 'файлов')}")
        rows = tree.get_children()
        if rows:
            empty_label.place_forget()
        else:
            empty_label.configure(text=("Очередь пуста. Добавьте PDF или изображения."
                                        if not files else "По выбранному фильтру ничего не найдено."))
            empty_label.place(relx=0.5, rely=0.5, anchor="center")
        if chosen and tree.exists(chosen):
            tree.selection_set(chosen)

    def set_busy(value: bool) -> None:
        busy.set(value)
        state = "disabled" if value else "normal"
        for button in action_buttons:
            button.configure(state=state)
        analyze_button.configure(text="Анализ…" if value else "▶  Запустить анализ")

    # ------------------------------------------------------------------ детали
    def show_placeholder(message: str = "Выберите файл в очереди, чтобы увидеть детали.") -> None:
        _clear(detail_scroll)
        box = ctk.CTkFrame(detail_scroll, fg_color="transparent")
        box.pack(fill="both", expand=True, pady=54)
        ctk.CTkLabel(box, text="⌕", font=(UI_FONT, 42), text_color="#CBD5E1").pack()
        ctk.CTkLabel(box, text="Выберите файл", font=(UI_FONT, 14, "bold"),
                     text_color=TEXT).pack(pady=(10, 4))
        ctk.CTkLabel(box, text=message, font=(UI_FONT, 10), text_color=MUTED,
                     justify="center", wraplength=300).pack(padx=18)

    def show_details(path: str) -> None:
        if path not in results:
            show_placeholder("Файл проверяется…" if path in running
                             else "Файл ещё не проверен. Запустите анализ, чтобы увидеть результат.")
            return
        result = results[path]
        verdict = str(result.get("verdict") or "ERROR")
        color, color_bg, short_label = _verdict_style(verdict)
        risk = result.get("risk_score")
        risk_text = f"{risk:.1f}" if risk is not None else "—"
        _clear(detail_scroll)
        parent = detail_scroll

        def section(title: str) -> None:
            ctk.CTkLabel(parent, text=title.upper(), font=(UI_FONT, 9, "bold"),
                         text_color=MUTED, anchor="w").pack(fill="x", padx=10, pady=(16, 4))

        ctk.CTkLabel(parent, text=os.path.basename(path), font=(UI_FONT, 16, "bold"),
                     text_color=TEXT, anchor="w", justify="left",
                     wraplength=320).pack(fill="x", padx=10, pady=(6, 0))
        ctk.CTkLabel(parent, text=_shorten_path(path), font=(UI_FONT, 8), text_color=MUTED,
                     anchor="w", justify="left", wraplength=320).pack(fill="x", padx=10, pady=(2, 0))

        badge = ctk.CTkFrame(parent, fg_color=color_bg, corner_radius=9)
        badge.pack(fill="x", padx=10, pady=(12, 0))
        ctk.CTkLabel(badge, text=short_label, font=(UI_FONT, 10, "bold"),
                     text_color=color).pack(side="left", padx=10, pady=6)
        ctk.CTkLabel(badge, text=f"риск {risk_text}", font=(UI_FONT, 10, "bold"),
                     text_color=color).pack(side="right", padx=10)

        ctk.CTkLabel(parent, text=str(result.get("verdict_label") or ""),
                     font=(UI_FONT, 9), text_color=MUTED, anchor="w", justify="left",
                     wraplength=320).pack(fill="x", padx=10, pady=(4, 0))

        risk_row = ctk.CTkFrame(parent, fg_color="transparent")
        risk_row.pack(fill="x", padx=10, pady=(12, 0))
        ctk.CTkLabel(risk_row, text=risk_text, font=(UI_FONT, 32, "bold"),
                     text_color=color).pack(side="left")
        ctk.CTkLabel(risk_row, text="/ 100\nинтегральный риск", font=(UI_FONT, 8),
                     text_color=MUTED, justify="left").pack(side="left", padx=(6, 0), pady=(9, 0))

        section("Действия")
        actions = ctk.CTkFrame(parent, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(0, 2))
        is_pdf = _format_of(result, path) == "PDF" or os.path.splitext(path)[1].lower() == ".pdf"
        ctk.CTkButton(actions, text="Очистить копию (CDR)", height=34, corner_radius=8,
                      fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                      font=(UI_FONT, 10, "bold"), command=lambda: do_sanitize(path)).pack(
            fill="x", pady=(0, 6))
        if is_pdf:
            ctk.CTkButton(actions, text="Извлечь вложения PDF", height=34, corner_radius=8,
                          fg_color="#EFF6FF", hover_color="#DBEAFE", text_color=PRIMARY,
                          font=(UI_FONT, 10, "bold"), command=lambda: do_extract_pdf(path)).pack(
                fill="x", pady=(0, 6))

        pairs: List[Tuple[str, str]] = [
            ("Формат", _format_of(result, path)),
            ("Размер", human_bytes(result.get("file_size") or 0)),
            ("Доля вложения", f"{_payload(result):.1%}" if _payload(result) is not None else "—"),
            ("Находки", str(len([f for f in (result.get("structure") or {}).get("findings") or []
                                 if f.get("severity") != "info"]))),
        ]
        pdf = result.get("pdf") or {}
        image = result.get("image") or {}
        if pdf:
            hidden = pdf.get("hidden_text") or {}
            pairs += [
                ("Страниц", _show_value(pdf.get("pages"))),
                ("Объектов", _show_value(pdf.get("objects"))),
                ("Потоков", _show_value(pdf.get("streams"))),
                ("JavaScript", _show_value(pdf.get("javascript_count"))),
                ("Действий", _show_value(pdf.get("action_count"))),
                ("Вложений", _show_value(pdf.get("attachments"))),
                ("Изображений", f"{_show_value(pdf.get('images'))} / {_show_value(pdf.get('analyzed_images'))}"),
                ("Скрытый текст", _show_value(hidden.get("hidden_chars"))),
                ("Подписей", _show_value(pdf.get("signature_count"))),
                ("После EOF", f"{_show_value(pdf.get('trailing_bytes'))} Б"),
                ("Шифрование", _show_bool(pdf.get("encrypted"))),
            ]
        elif image:
            pairs += [
                ("Пиксели", f"{_show_value(image.get('width'))}×{_show_value(image.get('height'))}"),
                ("Режим", _show_value(image.get("mode"))),
                ("Битность", _show_value(image.get("bit_depth"))),
            ]
        robustness = result.get("robustness") or {}
        if robustness.get("supported"):
            pairs += [
                ("ИСС", f"{robustness.get('stability_index', 0):.1f} "
                        f"({robustness.get('stability_class') or '—'})"),
                ("Безопасная ёмкость",
                 human_bytes(robustness.get("max_secure_capacity_bytes") or 0)),
            ]
        digest = result.get("sha256")
        if digest:
            pairs.append(("SHA-256", f"{digest[:18]}…"))

        info = ctk.CTkFrame(parent, fg_color=SUBTLE, corner_radius=12)
        info.pack(fill="x", padx=10, pady=(12, 0))
        for column in range(2):
            info.grid_columnconfigure(column, weight=1, uniform="detail")
        for index, (key, value) in enumerate(pairs):
            cell = ctk.CTkFrame(info, fg_color="transparent")
            cell.grid(row=index // 2, column=index % 2, sticky="nsew", padx=10, pady=5)
            ctk.CTkLabel(cell, text=key.upper(), font=(UI_FONT, 8, "bold"),
                         text_color=MUTED, anchor="w").pack(fill="x")
            ctk.CTkLabel(cell, text=value, font=(UI_FONT, 10, "bold"), text_color=TEXT,
                         anchor="w", justify="left", wraplength=140).pack(fill="x")

        def bullet(text: str, mark: str, mark_color: str) -> None:
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(row, text=mark, width=16, font=(UI_FONT, 10, "bold"),
                         text_color=mark_color, anchor="n").pack(side="left", anchor="n")
            ctk.CTkLabel(row, text=text, font=(UI_FONT, 10), text_color="#334155",
                         anchor="w", justify="left", wraplength=292).pack(
                side="left", fill="x", expand=True)

        if result.get("parse_error"):
            section("Предупреждение разбора")
            bullet(str(result["parse_error"]), "!", AMBER)
        if result.get("format_note"):
            section("Примечание")
            bullet(str(result["format_note"]), "i", PRIMARY)

        section("Основания")
        reasons = result.get("reasons") or []
        if reasons:
            for reason in reasons:
                bullet(str(reason), "•", color)
        else:
            bullet("Существенных оснований не выявлено.", "✓", GREEN)

        recommendations = result.get("recommendations") or []
        if recommendations:
            section("Рекомендации")
            for recommendation in recommendations:
                bullet(str(recommendation), "→", PRIMARY)

        attacks = result.get("attacks") or {}
        if attacks.get("supported") and attacks.get("neutralizing"):
            section("Нейтрализуют LSB-канал")
            bullet(", ".join(str(item) for item in attacks["neutralizing"]), "✓", GREEN)

    # ------------------------------------------------------------------ действия
    def add_paths(paths: List[str]) -> None:
        added = 0
        for path in paths:
            if path and os.path.isfile(path) and path not in files:
                files.append(path)
                added += 1
        refresh_summary()
        refresh_tree()
        if added:
            status_var.set(f"Добавлено файлов: {added}. В очереди: {len(files)}")
        else:
            status_var.set(f"Новых файлов нет. В очереди: {len(files)}")

    def add_files() -> None:
        if busy.get():
            return
        selected = filedialog.askopenfilenames(
            filetypes=[("Поддерживаемые файлы",
                        "*.png *.apng *.jpg *.jpeg *.bmp *.tif *.tiff *.webp *.gif *.pdf"),
                       ("Все файлы", "*.*")])
        add_paths(list(selected))

    def add_folder() -> None:
        if busy.get():
            return
        directory = filedialog.askdirectory()
        if directory:
            add_paths(collect_files([directory], recursive=True))

    def start_analysis() -> None:
        if busy.get():
            return
        pending = [path for path in files if path not in results]
        if not pending:
            messagebox.showinfo(__app_name__,
                                "Добавьте файлы для анализа или очистите очередь для повторной проверки.")
            return
        set_busy(True)
        running.clear()
        progress.set(0)
        status_var.set(f"Анализ {len(pending)} {_plural(len(pending), 'файла', 'файлов', 'файлов')}…")

        def worker(paths: List[str], robustness: bool, attacks: bool, password: str) -> None:
            for index, path in enumerate(paths, 1):
                messages.put(("progress", path, index, len(paths)))
                try:
                    result = analyzer.analyze_file(path, robustness=robustness, attacks=attacks,
                                                   password=password or None)
                except Exception as exc:  # noqa: BLE001
                    result = {
                        "file": path,
                        "file_name": os.path.basename(path),
                        "format": _format_of(None, path),
                        "verdict": "ERROR",
                        "verdict_label": "Ошибка анализа",
                        "risk_score": None,
                        "reasons": [str(exc)],
                        "recommendations": [],
                    }
                messages.put(("result", path, result))
            messages.put(("done",))

        threading.Thread(target=worker,
                         args=(pending, robustness_var.get(), attacks_var.get(), password_var.get()),
                         daemon=True).start()

    def clear_queue() -> None:
        if busy.get():
            return
        files.clear()
        results.clear()
        running.clear()
        search_entry.delete(0, "end")
        filter_var.set("Все")
        refresh_summary()
        refresh_tree()
        show_placeholder()
        status_var.set("Очередь очищена")
        progress.set(0)

    def save_report(path: Optional[str] = None) -> None:
        source = path or selected_path()
        if not source or source not in results:
            messagebox.showinfo(__app_name__, "Выберите проверенный файл")
            return
        target = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("JSON", "*.json")])
        if not target:
            return
        from .report import save_html, save_json
        if target.lower().endswith(".json"):
            save_json(results[source], target)
        else:
            save_html(results[source], target, source)
        status_var.set(f"Отчёт сохранён: {target}")

    def save_all_reports() -> None:
        if not results:
            messagebox.showinfo(__app_name__, "Нет результатов для экспорта")
            return
        directory = filedialog.askdirectory()
        if not directory:
            return
        from .report import write_reports
        written = write_reports(list(results.values()), directory)
        count = sum(len(items) for items in written.values())
        status_var.set(f"Экспортировано файлов отчётов: {count}")
        messagebox.showinfo(__app_name__, f"Отчёты сохранены:\n{directory}")

    def do_sanitize(path: Optional[str] = None) -> None:
        if busy.get():
            return
        source = path or selected_path()
        if not source:
            messagebox.showinfo(__app_name__, "Выберите файл для санитизации")
            return
        result = results.get(source) or {}
        is_pdf = _format_of(result, source) == "PDF" or os.path.splitext(source)[1].lower() == ".pdf"
        ext = os.path.splitext(source)[1].lower()
        if is_pdf:
            target = filedialog.asksaveasfilename(
                defaultextension=".pdf", initialfile="clean_" + os.path.basename(source),
                filetypes=[("PDF", "*.pdf")])
            if not target:
                return
            from .pdf_sanitizer import sanitize_pdf
            pdf_cfg = getattr(cfg, "pdf", None)
            status_var.set(f"Санитизация PDF: {os.path.basename(source)}…")
            root.update_idletasks()
            try:
                report = sanitize_pdf(
                    source, target, password=password_var.get() or None,
                    reencode_images=getattr(pdf_cfg, "sanitize_reencode_images", True),
                    remove_hidden_text=getattr(pdf_cfg, "sanitize_remove_hidden_text", True))
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror(__app_name__, f"Санитизация PDF не выполнена:\n{exc}")
                status_var.set("Санитизация PDF не выполнена")
                return
            verification = report.get("verification") or {}
            messagebox.showinfo(
                __app_name__,
                f"Очищенная копия PDF сохранена:\n{target}\n\n"
                f"Изображений перекодировано: {report.get('images_reencoded', 0)}\n"
                f"Скрытых символов удалено: {report.get('removed_hidden_chars', 0)}\n"
                f"Проверка результата: {verification.get('verdict', '—')}, "
                f"остаточных находок: {len(verification.get('residual_findings') or [])}")
            status_var.set(f"PDF санитизирован: {os.path.basename(target)}")
            return
        if ext not in {".png", ".apng"}:
            messagebox.showwarning(
                __app_name__,
                "Санитизация доступна для PNG/APNG и PDF. Для других растровых форматов "
                "доступен анализ без изменения исходного файла.")
            return
        target = filedialog.asksaveasfilename(
            defaultextension=".png", initialfile="clean_" + os.path.basename(source))
        if not target:
            return
        from .sanitizer import sanitize
        try:
            report = sanitize(source, target)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(__app_name__, f"Санитизация PNG не выполнена:\n{exc}")
            return
        messagebox.showinfo(__app_name__,
                            f"Очищенная копия сохранена:\n{target}\nPSNR: {report['psnr']:.2f} дБ")
        status_var.set(f"PNG санитизирован: {os.path.basename(target)}")

    def do_extract_pdf(path: Optional[str] = None) -> None:
        if busy.get():
            return
        source = path or selected_path()
        if not source:
            messagebox.showinfo(__app_name__, "Выберите PDF-файл")
            return
        result = results.get(source) or {}
        is_pdf = _format_of(result, source) == "PDF" or os.path.splitext(source)[1].lower() == ".pdf"
        if not is_pdf:
            messagebox.showwarning(__app_name__, "Извлечение вложений доступно только для PDF.")
            return
        directory = filedialog.askdirectory()
        if not directory:
            return
        from .pdf_analyzer import extract_pdf_attachments
        try:
            written = extract_pdf_attachments(source, directory, password=password_var.get() or None)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(__app_name__, f"Не удалось извлечь вложения:\n{exc}")
            return
        if not written:
            messagebox.showinfo(__app_name__, "Вложенные файлы не найдены")
            status_var.set("Вложенные файлы не найдены")
            return
        status_var.set(f"Извлечено вложений: {len(written)}")
        if messagebox.askyesno(__app_name__,
                               f"Извлечено файлов: {len(written)}\n{directory}\n\n"
                               "Добавить извлечённые файлы в очередь анализа?"):
            add_paths([item["path"] for item in written])

    # ------------------------------------------------------------------ сборка UI
    header = ctk.CTkFrame(root, fg_color=NAVY, corner_radius=0, height=82)
    header.grid(row=0, column=0, sticky="ew")
    header.pack_propagate(False)
    brand = ctk.CTkFrame(header, fg_color="transparent")
    brand.pack(side="left", padx=26, pady=14)
    logo = ctk.CTkFrame(brand, width=46, height=46, fg_color=PRIMARY, corner_radius=13)
    logo.pack(side="left")
    logo.pack_propagate(False)
    ctk.CTkLabel(logo, text="СВ", font=(UI_FONT, 15, "bold"),
                 text_color="#FFFFFF").place(relx=0.5, rely=0.5, anchor="center")
    brand_text = ctk.CTkFrame(brand, fg_color="transparent")
    brand_text.pack(side="left", padx=(12, 0))
    title_row = ctk.CTkFrame(brand_text, fg_color="transparent")
    title_row.pack(anchor="w")
    ctk.CTkLabel(title_row, text="Стего", font=(UI_FONT, 21, "bold"),
                 text_color="#FFFFFF").pack(side="left")
    ctk.CTkLabel(title_row, text="Визор", font=(UI_FONT, 21, "bold"),
                 text_color="#60A5FA").pack(side="left")
    ctk.CTkLabel(brand_text, text="Локальный анализ файлов и стеганографических рисков",
                 font=(UI_FONT, 10), text_color="#94A3B8").pack(anchor="w", pady=(1, 0))
    header_right = ctk.CTkFrame(header, fg_color="transparent")
    header_right.pack(side="right", padx=26)
    pill = ctk.CTkFrame(header_right, fg_color="#13243B", corner_radius=18,
                        border_width=1, border_color="#25405F")
    pill.pack(side="right")
    ctk.CTkLabel(pill, text="●  Автономный режим", font=(UI_FONT, 10, "bold"),
                 text_color="#4ADE80").pack(padx=12, pady=5)
    ctk.CTkLabel(header_right, text=f"v{__version__} · без сети", font=(UI_FONT, 9),
                 text_color="#64748B").pack(side="right", padx=(0, 12))

    ctk.CTkFrame(root, fg_color=PRIMARY, height=3, corner_radius=0).grid(
        row=1, column=0, sticky="ew")

    toolbar = ctk.CTkFrame(root, fg_color=CARD, corner_radius=16,
                           border_width=1, border_color=BORDER)
    toolbar.grid(row=2, column=0, sticky="ew", padx=24, pady=(18, 0))
    toolbar_inner = ctk.CTkFrame(toolbar, fg_color="transparent")
    toolbar_inner.pack(fill="x", padx=16, pady=12)
    toolbar_left = ctk.CTkFrame(toolbar_inner, fg_color="transparent")
    toolbar_left.pack(side="left")
    analyze_button = ctk.CTkButton(
        toolbar_left, text="▶  Запустить анализ", width=172, height=38, corner_radius=9,
        fg_color=PRIMARY, hover_color=PRIMARY_HOVER, font=(UI_FONT, 11, "bold"),
        command=start_analysis)
    analyze_button.pack(side="left", padx=(0, 8))
    add_files_button = ctk.CTkButton(
        toolbar_left, text="＋  Файлы", width=104, height=38, corner_radius=9,
        fg_color="#F1F5F9", hover_color="#E2E8F0", text_color=TEXT,
        border_width=1, border_color=BORDER, font=(UI_FONT, 10), command=add_files)
    add_files_button.pack(side="left", padx=(0, 8))
    add_folder_button = ctk.CTkButton(
        toolbar_left, text="▣  Папка", width=104, height=38, corner_radius=9,
        fg_color="#F1F5F9", hover_color="#E2E8F0", text_color=TEXT,
        border_width=1, border_color=BORDER, font=(UI_FONT, 10), command=add_folder)
    add_folder_button.pack(side="left", padx=(0, 8))
    clear_button = ctk.CTkButton(
        toolbar_left, text="Очистить", width=92, height=38, corner_radius=9,
        fg_color="transparent", hover_color="#F1F5F9", text_color=MUTED,
        font=(UI_FONT, 10), command=clear_queue)
    clear_button.pack(side="left")
    action_buttons.extend([analyze_button, add_files_button, add_folder_button, clear_button])

    toolbar_right = ctk.CTkFrame(toolbar_inner, fg_color="transparent")
    toolbar_right.pack(side="right")
    ctk.CTkLabel(toolbar_right, text="Пароль PDF", font=(UI_FONT, 9),
                 text_color=MUTED).pack(side="left", padx=(0, 6))
    ctk.CTkEntry(toolbar_right, textvariable=password_var, show="*", width=136, height=34,
                 corner_radius=8, border_color=BORDER, fg_color=SUBTLE,
                 font=(UI_FONT, 9)).pack(side="left", padx=(0, 16))
    ctk.CTkCheckBox(toolbar_right, text="Оценка стойкости", variable=robustness_var,
                    width=18, height=18, checkbox_width=18, checkbox_height=18,
                    corner_radius=5, fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                    border_color="#CBD5E1", text_color=TEXT,
                    font=(UI_FONT, 9)).pack(side="left", padx=(0, 12))
    ctk.CTkCheckBox(toolbar_right, text="Живучесть", variable=attacks_var,
                    width=18, height=18, checkbox_width=18, checkbox_height=18,
                    corner_radius=5, fg_color=PRIMARY, hover_color=PRIMARY_HOVER,
                    border_color="#CBD5E1", text_color=TEXT,
                    font=(UI_FONT, 9)).pack(side="left")

    stats = ctk.CTkFrame(root, fg_color="transparent")
    stats.grid(row=3, column=0, sticky="ew", padx=24, pady=(16, 0))
    for column in range(4):
        stats.grid_columnconfigure(column, weight=1, uniform="stats")

    def make_stat_card(column: int, key: str, title: str, color: str) -> None:
        card = ctk.CTkFrame(stats, fg_color=CARD, corner_radius=16,
                            border_width=1, border_color=BORDER)
        card.grid(row=0, column=column, sticky="nsew", padx=(0, 12) if column < 3 else 0)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=18, pady=13)
        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")
        ctk.CTkLabel(top, text=title.upper(), font=(UI_FONT, 8, "bold"),
                     text_color=MUTED, anchor="w").pack(side="left")
        ctk.CTkFrame(top, width=9, height=9, fg_color=color,
                     corner_radius=5).pack(side="right")
        value = ctk.CTkLabel(inner, text="0", font=(UI_FONT, 27, "bold"),
                             text_color=color, anchor="w")
        value.pack(anchor="w", pady=(2, 0))
        caption = ctk.CTkLabel(inner, text="нет данных", font=(UI_FONT, 8),
                               text_color=MUTED, anchor="w")
        caption.pack(anchor="w")
        cards[key] = (value, caption)

    make_stat_card(0, "total", "Всего файлов", PRIMARY)
    make_stat_card(1, "clean", "Чистые", GREEN)
    make_stat_card(2, "suspicious", "Подозрительные", AMBER)
    make_stat_card(3, "detected", "Обнаружено", RED)

    content = ctk.CTkFrame(root, fg_color="transparent")
    content.grid(row=4, column=0, sticky="nsew", padx=24, pady=(16, 0))
    content.grid_columnconfigure(0, weight=1)
    content.grid_columnconfigure(1, weight=0, minsize=360)
    content.grid_rowconfigure(0, weight=1)

    table_card = ctk.CTkFrame(content, fg_color=CARD, corner_radius=16,
                              border_width=1, border_color=BORDER)
    table_card.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
    table_head = ctk.CTkFrame(table_card, fg_color="transparent")
    table_head.pack(fill="x", padx=18, pady=(14, 0))
    title_box = ctk.CTkFrame(table_head, fg_color="transparent")
    title_box.pack(side="left")
    ctk.CTkLabel(title_box, text="Очередь файлов", font=(UI_FONT, 15, "bold"),
                 text_color=TEXT, anchor="w").pack(side="left")
    queue_label = ctk.CTkLabel(title_box, text="0 файлов", font=(UI_FONT, 9),
                               text_color=MUTED)
    queue_label.pack(side="left", padx=(10, 0))
    export_button = ctk.CTkButton(
        table_head, text="⤓  Экспорт всех", width=126, height=30, corner_radius=8,
        fg_color="#F1F5F9", hover_color="#E2E8F0", text_color=TEXT,
        border_width=1, border_color=BORDER, font=(UI_FONT, 9),
        command=save_all_reports)
    export_button.pack(side="right")

    table_filters = ctk.CTkFrame(table_card, fg_color="transparent")
    table_filters.pack(fill="x", padx=18, pady=(10, 10))
    search_entry = ctk.CTkEntry(
        table_filters, placeholder_text="Поиск по имени файла…",
        placeholder_text_color="#94A3B8", height=32, corner_radius=8,
        border_color=BORDER, fg_color=SUBTLE, font=(UI_FONT, 9))
    search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
    search_entry.bind("<KeyRelease>", lambda _event: refresh_tree())
    filter_button = ctk.CTkSegmentedButton(
        table_filters, values=list(FILTERS), variable=filter_var,
        command=lambda _value: refresh_tree(), height=30, corner_radius=8,
        selected_color=PRIMARY, selected_hover_color=PRIMARY_HOVER,
        unselected_color="#EFF3F8", unselected_hover_color="#E2E8F0",
        text_color=TEXT, font=(UI_FONT, 9))
    filter_button.pack(side="right")

    tree_wrap = ctk.CTkFrame(table_card, fg_color="transparent")
    tree_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("SG.Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                    borderwidth=0, relief="flat", rowheight=38, font=(UI_FONT, 10))
    style.configure("SG.Treeview.Heading", background="#F8FAFC", foreground=MUTED,
                    borderwidth=0, relief="flat", font=(UI_FONT, 9, "bold"),
                    padding=(8, 9))
    style.map("SG.Treeview.Heading", background=[("active", "#EEF2F7")])
    style.map("SG.Treeview", background=[("selected", "#DBEAFE")],
              foreground=[("selected", "#1E3A8A")])
    columns = ("file", "format", "verdict", "risk", "payload", "findings")
    tree = ttk.Treeview(tree_wrap, columns=columns, show="headings", style="SG.Treeview",
                        selectmode="browse")
    headings = (("file", "Файл", 220, "w"), ("format", "Формат", 60, "w"),
                ("verdict", "Статус", 120, "w"), ("risk", "Риск", 55, "center"),
                ("payload", "Доля", 62, "center"), ("findings", "Находки", 65, "center"))
    for name, title, width, anchor in headings:
        tree.heading(name, text=title, anchor=anchor)
        tree.column(name, width=width, minwidth=50, anchor=anchor,
                    stretch=name == "file")
    tree.tag_configure("CLEAN", background=GREEN_BG, foreground="#166534")
    tree.tag_configure("SUSPICIOUS", background=AMBER_BG, foreground="#92400E")
    tree.tag_configure("STEGO_DETECTED", background=RED_BG, foreground="#991B1B")
    tree.tag_configure("ERROR", background=GRAY_BG, foreground="#334155")
    tree.tag_configure("QUEUED", background=CARD, foreground=MUTED)
    tree.tag_configure("RUNNING", background="#EFF6FF", foreground=PRIMARY)
    scrollbar = ctk.CTkScrollbar(tree_wrap, orientation="vertical", command=tree.yview,
                                 width=12, corner_radius=6, fg_color="transparent",
                                 button_color="#CBD5E1", button_hover_color="#94A3B8")
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y", padx=(4, 0))
    empty_label = ctk.CTkLabel(tree_wrap, text="Очередь пуста. Добавьте PDF или изображения.",
                               font=(UI_FONT, 10), text_color=MUTED)
    tree.bind("<<TreeviewSelect>>", lambda _event: show_details(selected_path())
              if selected_path() else None)

    detail_card = ctk.CTkFrame(content, fg_color=CARD, corner_radius=16,
                               border_width=1, border_color=BORDER)
    detail_card.grid(row=0, column=1, sticky="nsew")
    detail_head = ctk.CTkFrame(detail_card, fg_color="transparent")
    detail_head.pack(fill="x", padx=18, pady=(14, 6))
    ctk.CTkLabel(detail_head, text="Карточка результата", font=(UI_FONT, 15, "bold"),
                 text_color=TEXT, anchor="w").pack(side="left")
    detail_scroll = ctk.CTkScrollableFrame(
        detail_card, fg_color="transparent", corner_radius=0,
        scrollbar_button_color="#CBD5E1", scrollbar_button_hover_color="#94A3B8")
    detail_scroll.pack(fill="both", expand=True, padx=6, pady=(0, 8))

    footer = ctk.CTkFrame(root, fg_color=CARD, corner_radius=0, height=46)
    footer.grid(row=5, column=0, sticky="ew")
    footer.pack_propagate(False)
    ctk.CTkLabel(footer, textvariable=status_var, font=(UI_FONT, 10),
                 text_color=MUTED, anchor="w").pack(side="left", padx=24)
    progress = ctk.CTkProgressBar(footer, width=250, height=6, corner_radius=3,
                                  fg_color="#E2E8F0", progress_color=PRIMARY)
    progress.pack(side="right", padx=24)
    progress.set(0)

    def poll() -> None:
        try:
            while True:
                message = messages.get_nowait()
                if message[0] == "progress":
                    _, path, index, total = message
                    running.add(path)
                    refresh_tree()
                    if tree.exists(path) and (not tree.selection() or selected_path() == path):
                        tree.selection_set(path)
                        show_details(path)
                    progress.set(max(0.0, (index - 1) / max(total, 1)))
                    status_var.set(f"Анализ {index}/{total}: {os.path.basename(path)}")
                elif message[0] == "result":
                    _, path, result = message
                    results[path] = result
                    running.discard(path)
                    refresh_summary()
                    refresh_tree()
                    if not tree.selection() and tree.exists(path):
                        tree.selection_set(path)
                        show_details(path)
                    elif selected_path() == path:
                        show_details(path)
                elif message[0] == "done":
                    running.clear()
                    set_busy(False)
                    progress.set(1.0)
                    refresh_summary()
                    refresh_tree()
                    counts = Counter(str(item.get("verdict") or "ERROR")
                                     for item in results.values())
                    parts = []
                    for verdict, label in (("CLEAN", "чисто"), ("SUSPICIOUS", "подозрительно"),
                                           ("STEGO_DETECTED", "обнаружено"),
                                           ("ERROR", "ошибок")):
                        if counts.get(verdict):
                            parts.append(f"{label}: {counts[verdict]}")
                    status_var.set("Готово · " + (" · ".join(parts) if parts else "нет результатов"))
        except queue.Empty:
            pass
        root.after(120, poll)

    refresh_summary()
    refresh_tree()
    show_placeholder()
    root.after(120, poll)
    root.mainloop()
