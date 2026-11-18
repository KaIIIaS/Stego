"""Конфигурация комплекса: пороги принятия решений и параметры оценки стойкости."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Thresholds:
    # Оценка доли заполнения контейнера (бит на отсчёт), выше которой изображение подозрительно
    payload_suspicious: float = 0.05
    # ... и выше которой фиксируется обнаружение вложения
    payload_stego: float = 0.10
    # p-значение атаки хи-квадрат, выше которого фиксируется последовательное LSB-вложение
    chi_square_p: float = 0.95
    # Интегральный риск (0..100)
    risk_suspicious: float = 30.0
    risk_stego: float = 60.0
    # Структурные эвристики
    text_chunk_max_len: int = 2048
    ancillary_max_bytes: int = 65536
    high_entropy: float = 7.2


@dataclass
class RobustnessSettings:
    rates: List[float] = field(default_factory=lambda: [0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0])
    methods: List[str] = field(default_factory=lambda: ["lsb_replacement", "lsb_matching"])
    trials: int = 2
    max_side: int = 512
    detection_threshold: float = 0.5


@dataclass
class PdfSettings:
    # Пределы статического разбора PDF (защита от документов-бомб)
    max_objects: int = 200_000
    max_stream_bytes: int = 64 * 1024 * 1024
    max_attachments: int = 1000
    # 0 - анализировать все страницы
    max_pages: int = 0
    analyze_images: bool = True
    max_images: int = 200
    full_image_analysis: bool = False
    analyze_text: bool = True
    max_text_chars: int = 2_000_000
    # Параметры санитизации PDF
    sanitize_reencode_images: bool = True
    sanitize_remove_hidden_text: bool = True


@dataclass
class Config:
    thresholds: Thresholds = field(default_factory=Thresholds)
    robustness: RobustnessSettings = field(default_factory=RobustnessSettings)
    pdf: PdfSettings = field(default_factory=PdfSettings)
    analysis_max_pixels: int = 4_000_000
    # Защита от файлов-бомб и исчерпания памяти
    max_file_size_mb: int = 512
    max_decompressed_mb: int = 256
    max_image_pixels: int = 64_000_000
    max_archive_depth: int = 3
    max_nested_files: int = 1000
    seed: int = 20240901
    max_analysis_seconds: int = 300
    include_alpha: bool = False
    db_path: str = "stegoguard_history.db"
    log_level: str = "INFO"
    log_file: Optional[str] = None

    @property
    def max_file_size_bytes(self) -> int:
        return int(self.max_file_size_mb) * 1024 * 1024

    @property
    def max_decompressed_bytes(self) -> int:
        return int(self.max_decompressed_mb) * 1024 * 1024

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        cfg = cls()
        for key, value in (data or {}).items():
            if key == "thresholds":
                cfg.thresholds = Thresholds(**{**asdict(cfg.thresholds), **value})
            elif key == "robustness":
                cfg.robustness = RobustnessSettings(**{**asdict(cfg.robustness), **value})
            elif key == "pdf":
                cfg.pdf = PdfSettings(**{**asdict(cfg.pdf), **value})
            elif hasattr(cfg, key):
                setattr(cfg, key, value)
            else:
                raise ValueError(f"Неизвестный параметр конфигурации: {key}")
        cfg.validate()
        return cfg

    def validate(self) -> None:
        t = self.thresholds
        if not 0 <= t.payload_suspicious <= t.payload_stego <= 1:
            raise ValueError("Требуется 0 <= payload_suspicious <= payload_stego <= 1")
        if not 0 <= t.risk_suspicious <= t.risk_stego <= 100:
            raise ValueError("Требуется 0 <= risk_suspicious <= risk_stego <= 100")
        r = self.robustness
        if not r.rates or any(not 0 < x <= 1 for x in r.rates):
            raise ValueError("Доли заполнения robustness.rates должны лежать в (0, 1]")
        unknown = set(r.methods) - {"lsb_replacement", "lsb_matching"}
        if unknown:
            raise ValueError(f"Неизвестные методы встраивания: {sorted(unknown)}")
        if r.trials < 1 or r.max_side < 32:
            raise ValueError("robustness.trials >= 1 и robustness.max_side >= 32")
        p = self.pdf
        if p.max_objects < 1 or p.max_stream_bytes < 1024 or p.max_attachments < 1:
            raise ValueError("pdf.max_objects >= 1, pdf.max_stream_bytes >= 1024, pdf.max_attachments >= 1")
        if p.max_pages < 0 or p.max_images < 0 or p.max_text_chars < 0:
            raise ValueError("Параметры pdf.max_pages/max_images/max_text_chars не могут быть отрицательными")
        if self.max_file_size_mb < 1 or self.max_decompressed_mb < 1:
            raise ValueError("max_file_size_mb >= 1 и max_decompressed_mb >= 1")
        if self.analysis_max_pixels < 1 or self.max_image_pixels < 1:
            raise ValueError("analysis_max_pixels >= 1 и max_image_pixels >= 1")
        if self.max_archive_depth < 0 or self.max_nested_files < 1:
            raise ValueError("max_archive_depth >= 0 и max_nested_files >= 1")
        if self.max_analysis_seconds < 1:
            raise ValueError("max_analysis_seconds >= 1")

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        if not path:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, ensure_ascii=False, indent=2)
