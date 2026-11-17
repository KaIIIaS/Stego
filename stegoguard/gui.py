"""Выбор графического интерфейса СтегоВизор.

Основной вариант оформлен на CustomTkinter и выглядит как современное
веб-приложение. Если пакет customtkinter недоступен, используется классический
Tkinter-интерфейс, поэтому программа остаётся работоспособной и в минимальной
офлайн-поставке.
"""
from __future__ import annotations

import importlib.util
from typing import Optional

from .config import Config


def run_gui(cfg: Optional[Config] = None) -> None:
    """Запустить современный интерфейс или резервный Tkinter-вариант."""
    if importlib.util.find_spec("customtkinter") is not None:
        try:
            from .gui_modern import run_gui as run_modern
        except ImportError:
            pass
        else:
            run_modern(cfg)
            return
    from .gui_legacy import run_gui as run_legacy
    run_legacy(cfg)
