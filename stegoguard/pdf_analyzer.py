"""Полный локальный статический анализ PDF без запуска содержимого документа.

Анализ включает:
* низкоуровневую проверку файла (сигнатура, xref/startxref, %%EOF, хвостовые данные,
  инкрементальные обновления, данные после endstream);
* обход всех достижимых объектов и потоков, включая объектные потоки;
* активные конструкции: JavaScript (включая обфускацию), Launch, OpenAction, /AA,
  SubmitForm, ImportData, GoToR/GoToE, RichMedia, 3D, Movie/Sound/Rendition, XFA;
* вложенные файлы и associated files с проверкой сигнатур и типов;
* изображения (включая изображения внутри Form XObject и inline) и их стегоанализ;
* скрытый текстовый слой: невидимый текст (Tr 3), микроскопический, вне страницы,
  белый текст, пробельные/нулевые символы;
* метаданные Info и XMP, цифровые подписи и их покрытие;
* неиспользуемые объекты, объектные потоки и подозрительные потоки.

Документ никогда не открывается внешним приложением и не исполняется.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:  # pypdf остаётся обязательной зависимостью, но анализ должен деградировать мягко
    from pypdf import PdfReader
except Exception:  # pragma: no cover - зависит от окружения
    PdfReader = None

try:
    from pypdf.generic import IndirectObject
except Exception:  # pragma: no cover
    IndirectObject = None

from . import __app_name__, __version__
from .config import Config, PdfSettings
from .png_parser import SEVERITY_LABELS, SEVERITY_WEIGHTS, classify_blob, scan_signatures, shannon_entropy
from .utils import to_jsonable

PDF_HEADER_RE = re.compile(rb"%PDF-(\d\.\d)")
RAW_OBJ_RE = re.compile(rb"(?<![A-Za-z0-9])(\d+)\s+(\d+)\s+obj\b")
STARTXREF_RE = re.compile(rb"startxref\s+(\d+)")
LENGTH_RE = re.compile(rb"/Length\s+(\d+)")
STREAM_RE = re.compile(rb"(?<![A-Za-z])stream(\r\n|\r|\n)")
JPEG2000_RE = re.compile(rb"/Filter\s*\[?[^\]]*/(?:JPXDecode|JBIG2Decode|CCITTFaxDecode|Crypt)", re.S)

ACTION_SEVERITY = {
    "/JavaScript": "high",
    "/Launch": "critical",
    "/SubmitForm": "high",
    "/ImportData": "high",
    "/GoToR": "high",
    "/GoToE": "high",
    "/RichMedia": "high",
    "/Rendition": "high",
    "/3D": "high",
    "/URI": "low",
    "/GoTo": "info",
    "/GoToDp": "info",
    "/Named": "info",
    "/Thread": "info",
    "/Movie": "medium",
    "/Sound": "medium",
    "/Screen": "medium",
    "/Hide": "low",
    "/SetOCGState": "low",
    "/ResetForm": "medium",
    "/Trans": "info",
    "/OCG": "info",
    "/GoTo3DView": "high",
}

JS_DANGEROUS_PATTERNS = [
    (re.compile(r"\b(?:eval|unescape|decodeURIComponent|String\s*\.\s*fromCharCode|atob)\s*\(", re.I),
     "динамическое исполнение/обфускация"),
    (re.compile(r"\b(?:launchURL|exportDataObject|submitForm|importDataObject|getURL|mailDoc|"
                r"Net\s*\.\s*HTTP|SOAP\s*\.\s*connect|XMLData)\b", re.I),
     "сетевые или файловые операции"),
    (re.compile(r"\b(?:ActiveXObject|WScript|Shell\s*\.\s*Application|powershell|pwsh|cmd\s*\.\s*exe|"
                r"mshta|rundll32|regsvr32|wscript|cscript|GetObject)\b", re.I),
     "запуск системных команд"),
    (re.compile(r"(?:%u[0-9a-f]{4}|\\x[0-9a-f]{2}){6,}", re.I), "шелл-код/длинная escape-последовательность"),
    (re.compile(r"\b(?:util\s*\.\s*printf|getAnnots|getPageNthWord|getPageNumWords|"
                r"getIcon|media\s*\.\s*newPlayer)\b", re.I), "нестандартный доступ к объектам/медиа"),
]
JS_INFO_PATTERNS = [
    (re.compile(r"\bapp\s*\.\s*alert\b", re.I), "app.alert"),
    (re.compile(r"\bthis\s*\.\s*print\b", re.I), "this.print"),
    (re.compile(r"\bapp\s*\.\s*launchURL\b", re.I), "app.launchURL"),
]
SUSPICIOUS_URI_RE = re.compile(r"^\s*(?:javascript|data|vbscript|file)\s*:", re.I)
EXECUTABLE_EXT = {".exe", ".dll", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                  ".wsf", ".wsh", ".hta", ".msi", ".cpl", ".jar", ".py", ".sh", ".elf"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".cab", ".iso"}
OFFICE_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp"}
SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".py", ".sh", ".bat", ".cmd", ".hta"}
STANDARD_INFO_KEYS = {"Title", "Author", "Subject", "Keywords", "Creator", "Producer",
                      "CreationDate", "ModDate", "Trapped"}


# --------------------------------------------------------------------------- утилиты

def _resolve(obj: Any) -> Any:
    """Разыменовать IndirectObject, не падая на повреждённых ссылках."""
    if obj is None:
        return None
    getter = getattr(obj, "get_object", None)
    if callable(getter):
        try:
            resolved = getter()
            if resolved is not obj:
                return resolved
        except Exception:
            return obj
    return obj


def _idnum(obj: Any) -> Optional[int]:
    if IndirectObject is not None and isinstance(obj, IndirectObject):
        try:
            return int(obj.idnum)
        except Exception:
            return None
    return None


def _name(value: Any) -> str:
    value = _resolve(value)
    if value is None:
        return ""
    return str(value)


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(_resolve(value))
    except (TypeError, ValueError):
        return default


def _text_value(value: Any, limit: int = 65536) -> str:
    """Текст из строки/массива/потока pypdf с жёстким ограничением размера."""
    value = _resolve(value)
    if value is None:
        return ""
    getter = getattr(value, "get_data", None)
    if callable(getter):
        try:
            data = getter()
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)[:limit].decode("utf-8", "replace")
            if isinstance(data, str):
                return data[:limit]
        except Exception:
            return ""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)[:limit].decode("utf-8", "replace")
    if isinstance(value, (list, tuple)):
        out: List[str] = []
        size = 0
        for item in value:
            chunk = _text_value(item, limit - size)
            if not chunk:
                continue
            out.append(chunk)
            size += len(chunk)
            if size >= limit:
                break
        return "".join(out)[:limit]
    if isinstance(value, dict):
        for key in ("/JS", "/UF", "/F", "/URI", "/D", "/File"):
            if key in value:
                return _text_value(value[key], limit)
        return ""
    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _stream_bytes(value: Any, limit: int = 64 * 1024 * 1024) -> Tuple[Optional[bytes], bool]:
    """Вернуть (данные, усечено). Для не-потока вернуть None."""
    value = _resolve(value)
    getter = getattr(value, "get_data", None)
    if not callable(getter):
        return None, False
    try:
        data = getter()
    except Exception:
        return None, False
    if not isinstance(data, (bytes, bytearray)):
        return None, False
    raw = bytes(data)
    if len(raw) > limit:
        return raw[:limit], True
    return raw, False


def _is_textish(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    ctrl = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return ctrl / max(len(sample), 1) < 0.08


def _safe_preview(value: str, limit: int = 240) -> str:
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", value or "")
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit] + ("…" if len(value) > limit else "")


def _guess_format(name: str, data: bytes) -> str:
    ext = os.path.splitext(name or "")[1].lower()
    head = data[:4096]
    if head.startswith(b"%PDF-"):
        return "PDF"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP/Office"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"MZ"):
        return "Windows PE"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "MS Office OLE"
    if head.startswith(b"Rar!\x1a\x07"):
        return "RAR"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head.startswith(b"#!/"):
        return "сценарий оболочки"
    return ext.lstrip(".").upper() or "неизвестный"


def _attachment_flags(name: str, data: bytes) -> Dict[str, Any]:
    ext = os.path.splitext(name or "")[1].lower()
    head = data[:4096]
    signatures = scan_signatures(head, limit=4)
    labels = [label for _, label in signatures]
    exec_like = (ext in EXECUTABLE_EXT or ext in SCRIPT_EXT or ext in {".msi", ".cpl", ".jar"}
                 or head.startswith((b"MZ", b"\x7fELF")) or head.startswith(b"#!/")
                 or any("PowerShell" in x or "PHP" in x or "JavaScript" in x for x in labels))
    pdf_nested = head.startswith(b"%PDF-") or "PDF-документ" in labels
    archive = ext in ARCHIVE_EXT or head.startswith((b"PK\x03\x04", b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c",
                                                      b"\x1f\x8b", b"BZh91AY&SY"))
    office = ext in OFFICE_EXT or head.startswith(b"PK\x03\x04") or head.startswith(b"\xd0\xcf\x11\xe0")
    return {
        "extension": ext,
        "format": _guess_format(name, data),
        "signatures": [f"{label} (+{offset})" for offset, label in signatures],
        "executable": bool(exec_like),
        "nested_pdf": bool(pdf_nested),
        "archive": bool(archive),
        "office": bool(office),
    }


def _js_flags(code: str) -> Tuple[List[str], bool]:
    flags: List[str] = []
    dangerous = False
    for pattern, label in JS_DANGEROUS_PATTERNS:
        try:
            if pattern.search(code):
                flags.append(label)
                dangerous = True
        except Exception:
            continue
    for pattern, label in JS_INFO_PATTERNS:
        try:
            if pattern.search(code) and label not in flags:
                flags.append(label)
        except Exception:
            continue
    return flags, dangerous


def _long_encoded_blob(text: str) -> List[str]:
    """Эвристики закодированных данных в тексте (без декодирования)."""
    notes: List[str] = []
    compact = re.sub(r"\s+", "", text or "")
    if len(compact) >= 128:
        if re.fullmatch(r"[0-9A-Fa-f]+", compact):
            notes.append("длинная hex-строка")
        elif re.fullmatch(r"[A-Za-z0-9+/=]+", compact) and len(compact) % 4 == 0:
            notes.append("похоже на Base64")
        if shannon_entropy(compact.encode("utf-8", "ignore")) > 5.8:
            notes.append("высокая энтропия")
    return notes


def _bytes_preview(data: bytes, limit: int = 64) -> str:
    if not data:
        return ""
    return data[:limit].hex(" ")


# --------------------------------------------------------------------------- аудит объектов

class _PdfAudit:
    """Обход объектного графа PDF и накопление находок без исполнения документа."""

    def __init__(self, raw: bytes, cfg: PdfSettings):
        self.raw = raw
        self.cfg = cfg
        self.findings: List[Dict[str, Any]] = []
        self._finding_index: Dict[Tuple[str, str, str], int] = {}
        self.actions: List[Dict[str, Any]] = []
        self._action_index: set = set()
        self.javascripts: List[Dict[str, Any]] = []
        self._js_digests: set = set()
        self.attachments: List[Dict[str, Any]] = []
        self._attachment_digests: set = set()
        self.af_specs: List[Tuple[Any, str]] = []
        self.stream_checks: List[Dict[str, Any]] = []
        self.signatures: List[Dict[str, Any]] = []
        self.referenced: set = set()
        self.seen: set = set()
        self.visited = 0
        self.image_objects = 0
        self.object_streams = 0
        self.notes: List[str] = []

    # ---------------------------------------------------------------- находки
    def add(self, code: str, severity: str, title: str, details: str = "",
            location: Optional[str] = None, offset: Optional[int] = None,
            count: int = 1) -> Dict[str, Any]:
        key = (code, location or "", title)
        if key in self._finding_index:
            finding = self.findings[self._finding_index[key]]
            finding["count"] = int(finding.get("count", 1)) + max(1, int(count))
            return finding
        finding = {
            "code": code,
            "severity": severity,
            "severity_label": SEVERITY_LABELS.get(severity, severity),
            "title": title,
            "details": details,
            "location": location,
            "offset": offset,
            "count": max(1, int(count)),
        }
        self._finding_index[key] = len(self.findings)
        self.findings.append(finding)
        return finding

    def has_code(self, code: str) -> bool:
        return any(f["code"] == code for f in self.findings)

    def add_action(self, kind: str, target: str, location: str) -> None:
        kind = kind if kind.startswith("/") else "/" + kind
        target = (target or "").strip()
        key = (kind.lower(), target.lower(), location)
        if key in self._action_index:
            return
        self._action_index.add(key)
        self.actions.append({"type": kind, "target": target[:500], "location": location})
        severity = ACTION_SEVERITY.get(kind, "medium")
        if target and SUSPICIOUS_URI_RE.match(target):
            severity = "critical" if severity in ("low", "info", "medium") else severity
        if target and any(target.lower().endswith(ext) for ext in (".exe", ".dll", ".bat", ".cmd",
                                                                   ".ps1", ".vbs", ".js", ".hta", ".scr")):
            severity = "critical"
        if kind == "/JavaScript" and self._has_js_near(location):
            # Подробная находка уже создана анализатором кода JS.
            severity = "info"
        code = "PDF_ACTION_" + kind.strip("/").upper().replace("-", "_")
        if severity != "info":
            self.add(code, severity, f"Действие PDF {kind}",
                     f"Цель: {target[:300]}" if target else "Действие без явной цели", location)
        elif target:
            self.add(code, "info", f"Действие PDF {kind}", f"Цель: {target[:300]}", location)

    def _has_js_near(self, location: str) -> bool:
        return any(js.get("location") == location for js in self.javascripts)

    def add_javascript(self, code: str, location: str) -> None:
        code = (code or "").strip("\x00 \t\r\n")
        if not code:
            self.add("PDF_JAVASCRIPT", "medium", "Пустой объект JavaScript",
                     "Найден /JS без исполняемого кода", location)
            return
        digest = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()
        if digest in self._js_digests:
            return
        self._js_digests.add(digest)
        flags, dangerous = _js_flags(code)
        encoded = _long_encoded_blob(code)
        severity = "critical" if dangerous else "high"
        if encoded and not dangerous:
            severity = "high"
        record = {
            "location": location,
            "length": len(code),
            "sha256": digest,
            "snippet": _safe_preview(code, 400),
            "flags": flags + encoded,
            "dangerous": dangerous,
        }
        self.javascripts.append(record)
        title = "Обнаружен JavaScript" + (" с опасными конструкциями" if dangerous else "")
        details = f"Длина {len(code)} байт"
        if record["flags"]:
            details += "; признаки: " + ", ".join(record["flags"])
        details += f"; фрагмент: {record['snippet']}"
        self.add("PDF_JAVASCRIPT" + ("_DANGEROUS" if dangerous else ""), severity, title, details, location)
        if encoded and not dangerous:
            self.add("PDF_JAVASCRIPT_OBFUSCATED", "high", "Обфусцированный JavaScript",
                     "; ".join(encoded), location)

    # ---------------------------------------------------------------- обход
    def walk(self, obj: Any, path: str = "/Root", depth: int = 0) -> None:
        if obj is None or depth > 40:
            return
        idn = _idnum(obj)
        if idn is not None:
            self.referenced.add(idn)
        resolved = _resolve(obj)
        if resolved is None:
            return
        if self.visited >= self.cfg.max_objects:
            if not self.has_code("PDF_OBJECT_LIMIT"):
                self.add("PDF_OBJECT_LIMIT", "medium", "Превышен лимит обхода объектов PDF",
                         f"Обработано не более {self.cfg.max_objects} объектов; часть структуры не проверена")
            return
        if not (isinstance(resolved, (dict, list, tuple, bytes, bytearray, str)) or
                callable(getattr(resolved, "get_data", None))):
            return
        marker = id(resolved)
        if marker in self.seen:
            return
        self.seen.add(marker)
        self.visited += 1

        if isinstance(resolved, dict):
            self.inspect_dict(resolved, path)
            for key, value in list(resolved.items()):
                self.walk(value, f"{path}/{key}", depth + 1)
        elif isinstance(resolved, (list, tuple)):
            for idx, value in enumerate(resolved):
                self.walk(value, f"{path}[{idx}]", depth + 1)

        if callable(getattr(resolved, "get_data", None)):
            self.inspect_stream(resolved, path)

    def inspect_dict(self, obj: Dict[Any, Any], path: str) -> None:
        keys = {str(k): v for k, v in obj.items()}
        # Сначала разбираем JavaScript, чтобы действие /JavaScript не дублировало находку.
        if "/JS" in keys:
            self.add_javascript(_text_value(keys["/JS"], limit=512 * 1024), path)
        if "/JavaScript" in keys and "/JS" not in keys:
            value = _resolve(keys["/JavaScript"])
            if isinstance(value, dict) and "/S" not in value:
                self.add("PDF_JAVASCRIPT_NAMES", "medium", "Дерево имён JavaScript",
                         "В каталоге присутствует именованное действие JavaScript", path)
            elif isinstance(value, (list, tuple)):
                self.add("PDF_JAVASCRIPT_NAMES", "medium", "Дерево имён JavaScript",
                         "В каталоге присутствует именованное действие JavaScript", path)

        kind = _name(keys.get("/S"))
        if kind:
            self.add_action(kind, self._action_target(keys), path)

        if "/OpenAction" in keys:
            target = self._action_target(keys)
            self.add("PDF_OPEN_ACTION", "medium", "У документа задано действие OpenAction",
                     f"Цель: {target[:300]}" if target else "OpenAction без явной цели", path)
        if "/AA" in keys:
            self.add("PDF_ADDITIONAL_ACTIONS", "medium", "Дополнительные действия (Additional Actions)",
                     "Действия могут выполняться при открытии, закрытии, печати или изменении полей", path)
        if "/Launch" in keys:
            self.add("PDF_LAUNCH", "critical", "Обнаружено действие Launch",
                     "Действие может запускать внешнюю программу или файл", path)
        if "/SubmitForm" in keys:
            self.add("PDF_SUBMIT_FORM", "high", "Обнаружено действие SubmitForm",
                     "Отправка данных формы во внешний адрес", path)
        if "/ImportData" in keys:
            self.add("PDF_IMPORT_DATA", "high", "Обнаружено действие ImportData",
                     "Импорт данных из внешнего источника", path)
        if "/GoToR" in keys or "/GoToE" in keys:
            self.add("PDF_REMOTE_GOTO", "high", "Переход к внешнему/вложенному документу",
                     "Действие GoToR/GoToE может открыть другой файл", path)
        if "/RichMedia" in keys:
            self.add("PDF_RICH_MEDIA", "high", "Обнаружено интерактивное RichMedia-содержимое",
                     "Может содержать Flash/видео и активные сценарии", path)
        if "/XFA" in keys:
            self.add("PDF_XFA", "high", "Обнаружена динамическая форма XFA",
                     "XFA может содержать сценарии, внешние ссылки и скрытые данные", path)
        if "/AcroForm" in keys:
            self.add("PDF_ACROFORM", "low", "Присутствует AcroForm",
                     "Проверяются поля формы и связанные действия", path)
        if "/EmbeddedFiles" in keys:
            self.add("PDF_EMBEDDED_FILES", "high", "Каталог вложенных файлов",
                     "Документ содержит /EmbeddedFiles", path)
        if "/AF" in keys:
            self.add("PDF_ASSOCIATED_FILES", "high", "Связанные вложенные файлы (/AF)",
                     "К документу прикреплены associated files", path)
            self.af_specs.append((keys["/AF"], path))
        if "/Filespec" in keys or "/EF" in keys:
            self.add("PDF_FILESPEC", "info", "Описание вложенного файла", "Найден объект Filespec", path)
        if "/Collection" in keys:
            self.add("PDF_PORTFOLIO", "medium", "PDF-портфолио",
                     "Коллекция вложенных файлов может маскировать полезную нагрузку", path)
        if "/Movie" in keys or "/Sound" in keys:
            self.add("PDF_MULTIMEDIA", "medium", "Мультимедийный объект PDF", "Movie/Sound", path)
        if "/3D" in keys:
            self.add("PDF_3D", "high", "3D-анимация PDF", "Может содержать активные сценарии", path)
        if "/Rendition" in keys:
            self.add("PDF_RENDITION", "high", "Rendition-действие", "Мультимедийное действие PDF", path)

        if "/URI" in keys:
            uri = _text_value(keys["/URI"], limit=2048)
            if uri:
                severity = "critical" if SUSPICIOUS_URI_RE.match(uri) else ("high" if uri.lower().startswith(("file:", "smb:")) else "low")
                self.add("PDF_URI", severity, "URI-ссылка в PDF",
                         f"Схема/адрес: {uri[:300]}", path)

        if "/Encrypt" in keys:
            self.add("PDF_ENCRYPT", "medium", "Словарь шифрования PDF",
                     "Документ зашифрован; часть объектов может быть недоступна", path)
        if "/Sig" in keys and "/ByteRange" in keys:
            self._add_signature(keys, path)
        elif "/ByteRange" in keys:
            self._add_signature(keys, path)

        subtype = _name(keys.get("/Subtype"))
        stype = _name(keys.get("/Type"))
        if subtype == "/Image" or (stype == "/XObject" and subtype == "/Image"):
            self.image_objects += 1
        if stype == "/ObjStm":
            self.object_streams += 1
            self.add("PDF_OBJECT_STREAM", "info", "Объектный поток (ObjStm)",
                     "Объекты сжаты внутри /ObjStm; выполняется их логический обход", path)
        if stype == "/EmbeddedFile":
            self.add("PDF_EMBEDDED_STREAM", "high", "Поток вложенного файла",
                     "Найден объект /Type /EmbeddedFile", path)

    def _action_target(self, d: Dict[str, Any]) -> str:
        for key in ("/URI", "/F", "/D", "/File", "/Name"):
            if key in d:
                value = _text_value(d[key], limit=2048)
                if value:
                    return value
        win = _resolve(d.get("/Win"))
        if isinstance(win, dict):
            for key in ("/F", "/D"):
                if key in win:
                    value = _text_value(win[key], limit=2048)
                    if value:
                        return value
        return ""

    def _add_signature(self, d: Dict[str, Any], path: str) -> None:
        byte_range = _resolve(d.get("/ByteRange"))
        ranges: List[int] = []
        if isinstance(byte_range, (list, tuple)):
            for item in byte_range:
                try:
                    ranges.append(int(_resolve(item)))
                except Exception:
                    pass
        contents = _resolve(d.get("/Contents"))
        contents_len = 0
        if isinstance(contents, (bytes, bytearray, str)):
            contents_len = len(contents)
        elif callable(getattr(contents, "get_data", None)):
            data, _ = _stream_bytes(contents, limit=1 << 20)
            contents_len = len(data or b"")
        record = {
            "location": path,
            "name": _safe_preview(_text_value(d.get("/Name"), 200), 200),
            "reason": _safe_preview(_text_value(d.get("/Reason"), 300), 300),
            "subfilter": _name(d.get("/SubFilter")),
            "byte_range": ranges,
            "contents_length": contents_len,
            "signing_time": _safe_preview(_text_value(d.get("/M"), 80), 80),
        }
        if record not in self.signatures:
            self.signatures.append(record)
        if not self.has_code("PDF_SIGNATURE"):
            self.add("PDF_SIGNATURE", "info", "Цифровая подпись PDF",
                     "Документ содержит цифровую подпись; модификация делает её недействительной", path)

    def inspect_stream(self, obj: Any, path: str) -> None:
        d = obj
        stype = _name(d.get("/Type")) if hasattr(d, "get") else ""
        subtype = _name(d.get("/Subtype")) if hasattr(d, "get") else ""
        filters = self._filters(d)
        if subtype == "/Image":
            return
        data, truncated = _stream_bytes(obj, limit=self.cfg.max_stream_bytes)
        if data is None:
            return
        length = len(data)
        check: Dict[str, Any] = {
            "location": path, "type": stype, "subtype": subtype,
            "filters": filters, "length": length, "truncated": truncated,
        }
        if truncated:
            self.notes.append(f"Поток {path} усечён до {self.cfg.max_stream_bytes} байт при анализе")
            self.add("PDF_STREAM_TRUNCATED", "low", "Очень большой поток PDF",
                     f"{path}: анализ ограничен {self.cfg.max_stream_bytes} байт", path)
        if stype == "/ObjStm" or "/ObjStm" in path:
            self.object_streams = max(self.object_streams, 1)
        if stype == "/EmbeddedFile":
            check["kind"] = "embedded"
            self.add("PDF_EMBEDDED_STREAM", "high", "Поток вложенного файла",
                     f"{path}: {length} байт", path)
        if stype == "/Metadata" or subtype == "/XML":
            check["kind"] = "metadata"
        if stype in ("/ObjStm", "/XFA") or subtype in ("/XML", "/Form") or "Contents" in path or stype == "":
            check["kind"] = check.get("kind", "data")
            self._scan_stream_code(data, path, stype, subtype, check)
        # Сигнатуры файлов в начале потока (не ищем по всему бинарному содержимому).
        head = data[:4096]
        head_sigs = scan_signatures(head, limit=4)
        if head_sigs and min(offset for offset, _ in head_sigs) < 32:
            labels = ", ".join(f"{label} (+{offset})" for offset, label in head_sigs)
            check["signatures"] = labels
            severity = "critical" if any("PE" in label or "ELF" in label or "PowerShell" in label or
                                         "PHP" in label or "ZIP" in label for _, label in head_sigs) else "high"
            self.add("PDF_STREAM_EMBEDDED_FILE", severity, "Сигнатура файла внутри потока PDF",
                     f"{path}: {labels}", path)
        if JPEG2000_RE.search(self.raw) and stype == "/XObject" and subtype != "/Image":
            self.add("PDF_COMPLEX_FILTER", "low", "Сложные фильтры потоков",
                     "Используются JPX/JBIG2/CCITT/Crypt фильтры", path)
        # Энтропийная эвристика только для служебных потоков, не для контента страниц.
        if length >= 1024 and check.get("kind") in ("embedded", "metadata", "data") and _is_textish(data):
            entropy = shannon_entropy(data)
            check["entropy"] = round(entropy, 3)
            if entropy > 7.4:
                self.add("PDF_STREAM_ENCODED", "medium", "Поток с высокой энтропией",
                         f"{path}: {length} байт, энтропия {entropy:.2f} бит/байт", path)
        if check.get("kind") or check.get("signatures"):
            if len(self.stream_checks) < 200:
                self.stream_checks.append(check)

    @staticmethod
    def _filters(obj: Any) -> List[str]:
        if not hasattr(obj, "get"):
            return []
        value = _resolve(obj.get("/Filter"))
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [_name(x).lstrip("/") for x in value if _name(x)]
        name = _name(value)
        return [name.lstrip("/")] if name else []

    def _scan_stream_code(self, data: bytes, path: str, stype: str, subtype: str,
                          check: Dict[str, Any]) -> None:
        if not data or not _is_textish(data):
            return
        text = data.decode("latin-1", "replace")
        flags, dangerous = _js_flags(text)
        # Не считаем обычное слово "eval" в тексте страницы кодом: требуем JS-признаки.
        if flags and (dangerous or any(marker in text for marker in
                                       ("function", "var ", "this.", "app.", "eval(", "unescape(",
                                        "String.fromCharCode", "ActiveXObject"))):
            severity = "critical" if dangerous else "high"
            self.add("PDF_CODE_IN_STREAM", severity, "Исполняемый/подозрительный код внутри потока",
                     f"{path}: " + ", ".join(flags), path)
            check["code_flags"] = flags
        if stype == "/XFA" or subtype == "/XML":
            encoded = _long_encoded_blob(text)
            if encoded:
                self.add("PDF_XML_ENCODED", "medium", "Закодированные данные в XML/XFA-потоке",
                         f"{path}: " + "; ".join(encoded), path)
                check["encoded"] = encoded
        if stype == "/ObjStm":
            for token, label in ((b"/JavaScript", "JavaScript"), (b"/JS", "JS"), (b"/Launch", "Launch"),
                                 (b"/EmbeddedFiles", "EmbeddedFiles"), (b"/OpenAction", "OpenAction")):
                if token in data and not self.has_code("PDF_OBJSTM_ACTIVE"):
                    self.add("PDF_OBJSTM_ACTIVE", "high", "Активные конструкции в объектном потоке",
                             f"{path}: найден токен {label}", path)
                    break


# --------------------------------------------------------------------------- низкоуровневый разбор

def _object_headers(raw: bytes) -> List[Tuple[int, int, int]]:
    """Заголовки объектов из сырых байтов (номер, поколение, смещение)."""
    if PdfReader is not None:
        finder = getattr(PdfReader, "_find_pdf_objects", None)
        if callable(finder):
            try:
                return list(finder(raw))
            except Exception:
                pass
    return [(int(m.group(1)), int(m.group(2)), m.start()) for m in RAW_OBJ_RE.finditer(raw)]


def _raw_layout(raw: bytes) -> Dict[str, Any]:
    header_match = PDF_HEADER_RE.search(raw[:4096])
    header_pos = header_match.start() if header_match else -1
    version = header_match.group(1).decode("ascii", "replace") if header_match else None
    eofs = [m.start() for m in re.finditer(rb"%%EOF", raw)]
    trailing = raw[eofs[-1] + 5:] if eofs else b""
    trailing_meaningful = trailing.strip(b"\x00\t\n\r\f ")
    leading = raw[:header_pos] if header_pos > 0 else b""
    startxref = None
    sm = None
    for sm in STARTXREF_RE.finditer(raw):
        pass
    if sm is not None:
        startxref = int(sm.group(1))
    startxref_valid = False
    xref_kind = "нет"
    if startxref is not None and 0 < startxref < len(raw):
        probe = raw[startxref:startxref + 64].lstrip()
        if probe.startswith(b"xref"):
            startxref_valid = True
            xref_kind = "таблица xref"
        elif re.match(rb"\d+\s+\d+\s+obj\b", probe):
            startxref_valid = True
            xref_kind = "xref-поток/объект"
    if b"/Type" in raw and re.search(rb"/Type\s*/XRef", raw):
        xref_kind = "xref-поток"
    elif xref_kind == "нет" and re.search(rb"(?m)^\s*xref\s*$", raw):
        xref_kind = "таблица xref"
    obj_headers = _object_headers(raw)
    streams = list(STREAM_RE.finditer(raw))
    return {
        "header_pos": header_pos,
        "header": header_match.group(0).decode("latin1") if header_match else None,
        "version": version,
        "eof_count": len(eofs),
        "eof_positions": eofs,
        "trailing_bytes": len(trailing),
        "trailing_meaningful": len(trailing_meaningful),
        "trailing_preview": _bytes_preview(trailing_meaningful),
        "leading_bytes": len(leading),
        "leading_meaningful": len(leading.strip(b"\x00\t\n\r\f \xef\xbb\xbf")),
        "leading_preview": _bytes_preview(leading.strip(b"\x00\t\n\r\f \xef\xbb\xbf")),
        "startxref": startxref,
        "startxref_valid": startxref_valid,
        "xref_kind": xref_kind,
        "object_count": len(obj_headers),
        "stream_count": len(streams),
        "object_streams": len(re.findall(rb"/Type\s*/ObjStm", raw)),
        "linearized": b"/Linearized" in raw[:2048],
        "incremental_updates": max(0, len(eofs) - 1) if eofs else 0,
        "prev_links": len(re.findall(rb"/Prev\s+\d+", raw)),
    }


def _raw_token_counts(raw: bytes) -> Dict[str, int]:
    tokens = [
        b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/AA", b"/EmbeddedFiles", b"/AF",
        b"/RichMedia", b"/SubmitForm", b"/ImportData", b"/URI", b"/XFA", b"/AcroForm", b"/GoToR",
        b"/GoToE", b"/Movie", b"/Sound", b"/3D", b"/Rendition", b"/Screen", b"/ObjStm", b"/XRef",
        b"/Encrypt", b"/Sig", b"/ByteRange", b"/Metadata", b"/Collection", b"/Filespec", b"/EF",
    ]
    counts: Dict[str, int] = {}
    for token in tokens:
        pattern = re.escape(token) + rb"(?![A-Za-z0-9])"
        counts[token.decode("latin1")] = len(re.findall(pattern, raw))
    return counts


def _raw_stream_anomalies(raw: bytes, limit: int = 100) -> List[Dict[str, Any]]:
    """Проверка несоответствия /Length и фактических данных перед endstream."""
    out: List[Dict[str, Any]] = []
    for match in STREAM_RE.finditer(raw):
        if len(out) >= limit:
            break
        data_start = match.end()
        end = raw.find(b"endstream", data_start)
        if end < 0:
            continue
        data = raw[data_start:end]
        preceding = raw[max(0, match.start() - 8192):match.start()]
        obj_match = None
        for obj_match in RAW_OBJ_RE.finditer(preceding):
            pass
        objnum = int(obj_match.group(1)) if obj_match else None
        lengths = list(LENGTH_RE.finditer(preceding))
        if not lengths or objnum is None:
            continue
        declared = int(lengths[-1].group(1))
        if declared < 0 or declared > len(data):
            extra = data
        else:
            extra = data[declared:]
        extra = extra.strip(b"\x00\t\n\r\f ")
        if not extra:
            continue
        # Слишком короткие хвосты часто являются выравниванием/мусором.
        if len(extra) < 4:
            continue
        sigs = scan_signatures(extra[:4096], limit=4)
        entry = {
            "object": objnum,
            "offset": data_start,
            "declared_length": declared,
            "actual_length": len(data),
            "extra_bytes": len(extra),
            "entropy": round(shannon_entropy(extra), 3),
            "signatures": [f"{label} (+{offset})" for offset, label in sigs],
            "preview": _bytes_preview(extra),
        }
        out.append(entry)
    return out


def _raw_findings(audit: _PdfAudit, layout: Dict[str, Any], tokens: Dict[str, int]) -> None:
    if layout["header_pos"] < 0:
        audit.add("PDF_SIGNATURE_MISSING", "critical", "Файл не является корректным PDF",
                  "Сигнатура %PDF- не найдена; расширение может не соответствовать содержимому")
    elif layout["header_pos"] > 0:
        if layout["leading_meaningful"]:
            severity = "high"
            sigs = scan_signatures(bytes.fromhex(layout["leading_preview"].replace(" ", "")), limit=3)
            if sigs:
                severity = "critical"
            audit.add("PDF_LEADING_DATA", severity, "Данные перед заголовком PDF",
                      f"{layout['leading_meaningful']} байт до %PDF-; превью: {layout['leading_preview']}")
        else:
            audit.add("PDF_LEADING_PADDING", "low", "Выравнивание перед заголовком PDF",
                      f"{layout['leading_bytes']} байт перед %PDF-")

    if layout["eof_count"] == 0:
        audit.add("PDF_EOF_MISSING", "high", "Отсутствует маркер %%EOF",
                  "Файл может быть усечён или повреждён")
    elif layout["eof_count"] > 1:
        audit.add("PDF_INCREMENTAL_UPDATES", "low", "Инкрементальные обновления PDF",
                  f"Найдено маркеров %%EOF: {layout['eof_count']}. Старые версии объектов могут содержать скрытые данные")

    if layout["trailing_meaningful"]:
        severity = "high"
        sigs = scan_signatures(bytes.fromhex(layout["trailing_preview"].replace(" ", "")), limit=4)
        if sigs or layout["trailing_meaningful"] > 4096:
            severity = "critical"
        details = (f"{layout['trailing_meaningful']} байт после последнего %%EOF; "
                   f"превью: {layout['trailing_preview']}")
        if sigs:
            details += "; сигнатуры: " + ", ".join(f"{label} (+{offset})" for offset, label in sigs)
        audit.add("PDF_TRAILING_DATA", severity, "Данные после маркера EOF", details)

    if layout["startxref"] is None:
        audit.add("PDF_STARTXREF_MISSING", "medium", "Отсутствует startxref",
                  "Нарушение структуры PDF; возможна ручная модификация")
    elif not layout["startxref_valid"]:
        audit.add("PDF_STARTXREF_INVALID", "medium", "Некорректный startxref",
                  f"startxref={layout['startxref']} не указывает на xref/объект")

    if layout["version"] and not re.match(r"^(?:1\.\d|2\.0)$", layout["version"]):
        audit.add("PDF_VERSION_UNUSUAL", "low", "Необычная версия PDF", f"Версия {layout['version']}")

    if layout["linearized"]:
        audit.add("PDF_LINEARIZED", "info", "Линеаризованный PDF",
                  "Файл оптимизирован для потокового просмотра; проверка выполнена полностью")

    if tokens.get("/JavaScript", 0) or tokens.get("/JS", 0):
        if not audit.javascripts:
            audit.add("PDF_JAVASCRIPT_RAW", "high", "Токены JavaScript в сыром PDF",
                      f"/JavaScript: {tokens.get('/JavaScript', 0)}, /JS: {tokens.get('/JS', 0)}")
    for token, severity, title in (
        ("/Launch", "critical", "Токен Launch в сыром PDF"),
        ("/SubmitForm", "high", "Токен SubmitForm в сыром PDF"),
        ("/ImportData", "high", "Токен ImportData в сыром PDF"),
        ("/GoToR", "high", "Токен GoToR в сыром PDF"),
        ("/GoToE", "high", "Токен GoToE в сыром PDF"),
        ("/RichMedia", "high", "Токен RichMedia в сыром PDF"),
        ("/EmbeddedFiles", "high", "Токен EmbeddedFiles в сыром PDF"),
        ("/XFA", "high", "Токен XFA в сыром PDF"),
        ("/AcroForm", "low", "Токен AcroForm в сыром PDF"),
        ("/OpenAction", "medium", "Токен OpenAction в сыром PDF"),
        ("/AA", "medium", "Токены Additional Actions в сыром PDF"),
        ("/ObjStm", "info", "Объектные потоки в PDF"),
        ("/Encrypt", "medium", "Токен шифрования в сыром PDF"),
    ):
        if tokens.get(token, 0) and not any(token.strip("/").lower() in f["details"].lower()
                                           or token.strip("/").lower() in f["title"].lower()
                                           for f in audit.findings):
            audit.add("PDF_RAW_" + token.strip("/").upper(), severity, title,
                      f"Найдено вхождений: {tokens[token]}", count=tokens[token])

    for anomaly in _raw_stream_anomalies(bytes(audit.raw)):
        severity = "critical" if anomaly["signatures"] or anomaly["entropy"] > 7.2 else "high"
        details = (f"Объект {anomaly['object']}: /Length={anomaly['declared_length']}, "
                   f"фактически {anomaly['actual_length']} байт, лишних {anomaly['extra_bytes']} байт; "
                   f"энтропия {anomaly['entropy']:.2f}")
        if anomaly["signatures"]:
            details += "; сигнатуры: " + ", ".join(anomaly["signatures"])
        audit.add("PDF_STREAM_TRAILING", severity, "Данные после конца потока PDF",
                  details, f"/object[{anomaly['object']}]/stream", anomaly["offset"])


# --------------------------------------------------------------------------- метаданные, вложения

def _collect_info(reader: Any, audit: _PdfAudit) -> Dict[str, Any]:
    info: Dict[str, str] = {}
    try:
        meta = reader.metadata
    except Exception:
        meta = None
    if meta is not None:
        try:
            items = list(meta.items())
        except Exception:
            items = []
        for key, value in items:
            name = str(key).lstrip("/")
            text = _text_value(value, limit=8192)
            info[name] = text
            if not text:
                continue
            if len(text) > 1024:
                audit.add("PDF_METADATA_LONG", "medium", f"Длинное поле метаданных {name}",
                          f"{len(text)} символов", f"/Info/{name}")
            encoded = _long_encoded_blob(text)
            if encoded:
                audit.add("PDF_METADATA_ENCODED", "medium", f"Закодированные данные в метаданных {name}",
                          "; ".join(encoded), f"/Info/{name}")
            flags, dangerous = _js_flags(text)
            if dangerous or any(x in text for x in ("<script", "<?php", "powershell", "cmd.exe")):
                audit.add("PDF_METADATA_CODE", "critical", f"Код в метаданных {name}",
                          f"Признаки: {', '.join(flags) or 'подозрительный код'}", f"/Info/{name}")
            if scan_signatures(text.encode("utf-8", "ignore")[:4096], limit=2):
                audit.add("PDF_METADATA_SIGNATURE", "high", f"Сигнатура файла в метаданных {name}",
                          _safe_preview(text, 160), f"/Info/{name}")
    custom = [k for k in info if k not in STANDARD_INFO_KEYS]
    if custom:
        audit.add("PDF_METADATA_CUSTOM", "low", "Нестандартные поля метаданных",
                  ", ".join(custom[:20]), count=len(custom))
    for key in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer"):
        if info.get(key):
            audit.add("PDF_METADATA", "info", f"Метаданные: {key}", _safe_preview(info[key], 200), f"/Info/{key}")
    return info


def _collect_xmp(reader: Any, root: Any, audit: _PdfAudit, cfg: PdfSettings) -> Dict[str, Any]:
    metadata_ref = root.get("/Metadata") if hasattr(root, "get") else None
    data, truncated = _stream_bytes(metadata_ref, limit=max(cfg.max_stream_bytes, 1 << 20))
    if data is None:
        return {"present": False}
    if truncated:
        audit.add("PDF_XMP_LARGE", "medium", "Слишком большой XMP-пакет",
                  f"Анализ ограничен {cfg.max_stream_bytes} байт")
    if len(data) > 2 * 1024 * 1024:
        audit.add("PDF_XMP_LARGE", "medium", "Большой XMP-пакет", f"{len(data)} байт")
    text = data.decode("utf-8", "replace")
    fields: Dict[str, str] = {}
    for match in re.finditer(r"<([A-Za-z_][\w:.-]*)[^>]*>([^<]{1,2000})</\1>", text):
        name = match.group(1)
        value = _safe_preview(match.group(2), 300)
        if name not in fields:
            fields[name] = value
        if len(fields) >= 80:
            break
    for match in re.finditer(r"([A-Za-z_][\w:.-]*)=\"([^\"]{1,1000})\"", text):
        name = match.group(1)
        value = _safe_preview(match.group(2), 300)
        if name not in fields and len(fields) < 80:
            fields[name] = value
    history_events = len(re.findall(r"<stEvt:action\b", text, re.I))
    custom_fields = len(fields)
    if fields:
        audit.add("PDF_XMP", "info", "XMP-метаданные",
                  f"Полей: {custom_fields}, событий истории: {history_events}")
    if history_events:
        audit.add("PDF_XMP_HISTORY", "info", "История изменений в XMP",
                  f"Событий: {history_events}", count=history_events)
    flags, dangerous = _js_flags(text)
    if dangerous or any(x in text.lower() for x in ("javascript:", "<script", "<?php", "powershell")):
        audit.add("PDF_XMP_SCRIPT", "critical", "Код/активная ссылка в XMP",
                  ", ".join(flags) or "подозрительный код")
    encoded = _long_encoded_blob(text)
    if encoded:
        audit.add("PDF_XMP_ENCODED", "medium", "Закодированные данные в XMP", "; ".join(encoded))
    for label, value in fields.items():
        if len(value) > 500:
            audit.add("PDF_XMP_LONG_FIELD", "low", "Длинное поле XMP",
                      f"{label}: {len(value)} символов")
            break
    return {
        "present": True,
        "size": len(data),
        "fields": fields,
        "history_events": history_events,
        "custom_fields": custom_fields,
    }


def _attachment_items(reader: Any, limit: int) -> List[Any]:
    items: List[Any] = []
    try:
        for item in reader.attachment_list:
            items.append(item)
            if len(items) >= limit:
                break
    except Exception:
        items = []
    if items:
        return items
    try:
        attachments = reader.attachments
        names = list(attachments.keys())
        for name in names:
            for content in attachments[name]:
                items.append(type("_SimpleAttachment", (), {
                    "name": name,
                    "alternative_name": name,
                    "content": content,
                    "description": None,
                    "subtype": None,
                    "associated_file_relationship": None,
                })())
                if len(items) >= limit:
                    return items
    except Exception:
        pass
    return items


def _attachment_content(item: Any) -> Optional[bytes]:
    try:
        content = item.content
    except Exception:
        content = None
    if isinstance(content, str):
        return content.encode("latin-1", "replace")
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    return None


def _read_file_spec(spec: Any, audit: _PdfAudit, path: str) -> Optional[Dict[str, Any]]:
    spec = _resolve(spec)
    if not isinstance(spec, dict):
        return None
    name = _text_value(spec.get("/UF") or spec.get("/F"), limit=512)
    ef = _resolve(spec.get("/EF"))
    stream = None
    if isinstance(ef, dict):
        stream = ef.get("/UF") or ef.get("/F")
    data, truncated = _stream_bytes(stream, limit=audit.cfg.max_stream_bytes)
    if data is None:
        return None
    return _attachment_record(name or "attachment", data, audit, path, truncated=truncated)


def _attachment_record(name: str, data: bytes, audit: _PdfAudit, location: str,
                       truncated: bool = False) -> Dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    if digest in audit._attachment_digests:
        return next((a for a in audit.attachments if a.get("sha256") == digest), {})
    audit._attachment_digests.add(digest)
    flags = _attachment_flags(name, data)
    record = {
        "name": name,
        "size": len(data),
        "sha256": digest,
        "entropy": round(shannon_entropy(data), 3) if data else 0.0,
        "subtype": "",
        "description": "",
        "relationship": "",
        "location": location,
        "truncated": truncated,
        **flags,
    }
    record.pop("extension", None)
    audit.attachments.append(record)
    audit.add("PDF_ATTACHMENT", "high" if not flags["executable"] else "critical",
              "Вложенный файл" + (" (исполняемый/сценарный)" if flags["executable"] else ""),
              f"{name}: {len(data)} байт, формат {flags['format']}",
              location)
    if flags["executable"]:
        audit.add("PDF_ATTACHMENT_EXECUTABLE", "critical", "Исполняемый вложенный файл",
                  f"{name}: {flags['format']}", location)
    elif flags["nested_pdf"] or flags["archive"] or flags["office"]:
        audit.add("PDF_ATTACHMENT_NESTED", "high", "Вложенный контейнер/документ",
                  f"{name}: {flags['format']}", location)
    if flags["signatures"] and not flags["executable"]:
        audit.add("PDF_ATTACHMENT_SIGNATURE", "high", "Сигнатура файла внутри вложения",
                  f"{name}: " + ", ".join(flags["signatures"]), location)
    if truncated:
        audit.add("PDF_ATTACHMENT_TRUNCATED", "medium", "Вложение усечено при анализе",
                  f"{name}: {len(data)} байт", location)
    return record


def _collect_attachments(reader: Any, audit: _PdfAudit) -> List[Dict[str, Any]]:
    items = _attachment_items(reader, max(1, audit.cfg.max_attachments))
    for item in items:
        name = getattr(item, "name", None) or getattr(item, "alternative_name", None) or "attachment"
        data = _attachment_content(item)
        if data is None:
            continue
        record = _attachment_record(str(name), data, audit, f"/EmbeddedFiles/{name}")
        try:
            record["subtype"] = _name(getattr(item, "subtype", ""))
            record["description"] = _text_value(getattr(item, "description", ""), 500)
            record["relationship"] = _name(getattr(item, "associated_file_relationship", ""))
            created = getattr(item, "creation_date", None)
            modified = getattr(item, "modification_date", None)
            if created:
                record["created"] = str(created)
            if modified:
                record["modified"] = str(modified)
        except Exception:
            pass
    # Associated files, которые не попали в дерево /EmbeddedFiles.
    for spec, path in audit.af_specs:
        resolved = _resolve(spec)
        values = resolved if isinstance(resolved, (list, tuple)) else [resolved]
        for value in values:
            record = _read_file_spec(value, audit, path)
            if record:
                record["relationship"] = "AssociatedFile"
    if len(audit.attachments) > audit.cfg.max_attachments:
        audit.add("PDF_ATTACHMENT_LIMIT", "low", "Много вложений в PDF",
                  f"Проверено первых {audit.cfg.max_attachments} из {len(audit.attachments)}")
        audit.attachments = audit.attachments[:audit.cfg.max_attachments]
    return audit.attachments


def _collect_forms(reader: Any, root: Any, audit: _PdfAudit) -> Dict[str, Any]:
    acro = _resolve(root.get("/AcroForm")) if hasattr(root, "get") else None
    forms = {"acroform": isinstance(acro, dict), "xfa": False, "fields": 0, "need_appearances": False}
    if isinstance(acro, dict):
        forms["xfa"] = "/XFA" in acro
        forms["need_appearances"] = bool(_resolve(acro.get("/NeedAppearances", False)))
        try:
            fields = reader.get_fields()
            if isinstance(fields, dict):
                forms["fields"] = len(fields)
        except Exception:
            pass
    if forms["xfa"]:
        audit.add("PDF_XFA", "high", "Динамическая форма XFA",
                  "XFA может содержать сценарии, внешние ссылки и скрытые данные")
    if forms["acroform"]:
        audit.add("PDF_ACROFORM", "low", "Форма AcroForm",
                  f"Полей: {forms['fields']}")
    return forms


def _check_signature_coverage(audit: _PdfAudit, file_size: int) -> None:
    for sign in audit.signatures:
        ranges = sign.get("byte_range") or []
        if len(ranges) >= 4 and ranges[-1] >= 0:
            end = ranges[-2] + ranges[-1]
            sign["covered_bytes"] = end
            if end < file_size - 64:
                audit.add("PDF_SIGNATURE_COVERAGE", "high", "Подпись не покрывает весь файл",
                          f"Подписанные данные заканчиваются на {end} из {file_size} байт; "
                          "после подписи могут быть добавлены данные", sign.get("location"))


# --------------------------------------------------------------------------- изображения

def _collect_images(reader: Any, audit: _PdfAudit, cfg: Config) -> Tuple[List[Dict[str, Any]], int, float, float]:
    from .analysis import run_statistical
    from .image_io import load_image

    checks: List[Dict[str, Any]] = []
    total = 0
    analyzed = 0
    max_payload = 0.0
    max_detection = 0.0
    seen = set()
    pdf_cfg = cfg.pdf
    try:
        pages_iter = enumerate(reader.pages, 1)
    except Exception:
        return checks, 0, 0.0, 0.0
    for page_no, page in pages_iter:
        if pdf_cfg.max_pages and page_no > pdf_cfg.max_pages:
            audit.add("PDF_PAGE_LIMIT", "low", "Ограничение числа страниц PDF",
                      f"Проверены первые {pdf_cfg.max_pages} страниц")
            break
        try:
            images = list(page.images)
        except Exception as exc:
            audit.add("PDF_IMAGE_ENUMERATION", "low", "Не удалось перечислить изображения страницы",
                      f"Страница {page_no}: {str(exc)[:200]}")
            continue
        for image_no, image_file in enumerate(images, 1):
            total += 1
            if not pdf_cfg.analyze_images:
                continue
            if analyzed >= pdf_cfg.max_images:
                continue
            ref = getattr(image_file, "indirect_reference", None)
            idn = _idnum(ref)
            data = getattr(image_file, "data", None)
            if not isinstance(data, (bytes, bytearray)):
                data = b""
            digest = hashlib.sha256(bytes(data)).hexdigest() if data else ""
            key = idn if idn is not None else (digest, getattr(image_file, "is_inline", False))
            if key in seen:
                continue
            seen.add(key)
            analyzed += 1
            check: Dict[str, Any] = {
                "page": page_no,
                "image": image_no,
                "name": getattr(image_file, "name", f"image_{image_no}"),
                "inline": bool(getattr(image_file, "is_inline", False)),
                "displayed": bool(getattr(image_file, "is_displayed", False)),
                "sha256": digest or None,
                "encoded_size": len(data) if data else None,
            }
            obj = _resolve(ref) if ref is not None else None
            if isinstance(obj, dict):
                check["object_id"] = idn
                check["filters"] = _PdfAudit._filters(obj)
                check["colorspace"] = _name(_resolve(obj.get("/ColorSpace")))
                check["bits_per_component"] = int(_num(_resolve(obj.get("/BitsPerComponent")), 0) or 0)
            try:
                decoded = load_image(image_file.image)
                if decoded.width * decoded.height > cfg.analysis_max_pixels:
                    decoded = decoded.crop_center(cfg.analysis_max_pixels)
                stat = run_statistical(decoded.channels, decoded.max_value, cfg.thresholds,
                                       full=pdf_cfg.full_image_analysis, palette=decoded.is_palette)
                payload = float(stat.get("effective_payload", 0.0))
                detection = float(stat.get("detection_probability", 0.0))
                check.update({
                    "width": decoded.width,
                    "height": decoded.height,
                    "mode": decoded.mode,
                    "effective_payload": round(payload, 4),
                    "max_channel_payload": round(float(stat.get("payload_max_channel", 0.0)), 4),
                    "detection_probability": round(detection, 4),
                    "statistical_risk": round(detection * 100.0, 1),
                })
                max_payload = max(max_payload, payload)
                max_detection = max(max_detection, detection)
                if detection >= 0.8 or payload >= cfg.thresholds.payload_stego:
                    audit.add("PDF_IMAGE_STEGO", "high", "Подозрительные признаки в изображении PDF",
                              f"Страница {page_no}, изображение {image_no}: оценка вложения "
                              f"{payload:.1%}, вероятность обнаружения {detection:.1%}")
                elif detection >= 0.5 or payload >= cfg.thresholds.payload_suspicious:
                    audit.add("PDF_IMAGE_SUSPICIOUS", "medium", "Изображение PDF требует проверки",
                              f"Страница {page_no}, изображение {image_no}: оценка вложения "
                              f"{payload:.1%}, вероятность обнаружения {detection:.1%}")
            except Exception as exc:
                check["error"] = str(exc)[:300]
                audit.add("PDF_IMAGE_UNREADABLE", "low", "Изображение PDF не удалось декодировать",
                          f"Страница {page_no}, изображение {image_no}: {str(exc)[:200]}")
            checks.append(check)
    if total > analyzed:
        audit.notes.append(f"Изображений в PDF: {total}; проанализировано: {analyzed} "
                           f"(лимит {pdf_cfg.max_images})")
    return checks, total, max_payload, max_detection


# --------------------------------------------------------------------------- скрытый текст

def _bbox(page: Any) -> Tuple[float, float, float, float]:
    for key in ("/MediaBox", "/CropBox"):
        box = _resolve(page.get(key)) if hasattr(page, "get") else None
        if isinstance(box, (list, tuple)) and len(box) >= 4:
            try:
                return tuple(float(_num(v)) for v in box[:4])  # type: ignore[return-value]
            except Exception:
                pass
    return 0.0, 0.0, 612.0, 792.0


def _mat_mul(a: Sequence[float], b: Sequence[float]) -> List[float]:
    return [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]


def _string_operand(value: Any) -> str:
    value = _resolve(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1", "replace")
    return ""


def _operation_strings(operator: str, operands: Sequence[Any]) -> str:
    if operator == "TJ":
        out: List[str] = []
        for item in operands:
            out.append(_string_operand(item))
        return "".join(out)
    if operator in ("Tj", "'"):
        return _string_operand(operands[-1]) if operands else ""
    if operator == '"':
        return _string_operand(operands[-1]) if operands else ""
    return ""


def _analyze_operations(operations: Sequence[Any], page_box: Tuple[float, float, float, float],
                        location: str, acc: Dict[str, Any], depth: int = 0) -> None:
    state: Dict[str, Any] = {
        "font_size": 0.0, "render": 0, "fill": None, "cs": "",
        "ctm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "tm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "lm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "leading": 0.0, "hscale": 1.0, "char_space": 0.0, "word_space": 0.0,
    }
    stack: List[Dict[str, Any]] = []
    x0, y0, x1, y1 = page_box

    def add_segment(reason: str, text: str, snippet: str) -> None:
        acc["hidden_chars"] += len(text)
        acc["segments"] += 1
        if len(acc["examples"]) < 20:
            acc["examples"].append({
                "page": location, "reason": reason, "chars": len(text),
                "preview": _safe_preview(snippet, 160),
            })

    for item in operations:
        try:
            operands, op_raw = item
        except Exception:
            continue
        operands = list(operands) if isinstance(operands, (list, tuple)) else []
        operator = op_raw.decode("latin1", "replace") if isinstance(op_raw, (bytes, bytearray)) else str(op_raw)
        if operator == "q":
            stack.append({k: (list(v) if isinstance(v, list) else v) for k, v in state.items()})
            continue
        if operator == "Q":
            if stack:
                state = stack.pop()
            continue
        if operator == "cm" and len(operands) >= 6:
            state["ctm"] = _mat_mul([_num(v) for v in operands[:6]], state["ctm"])
            continue
        if operator == "BT":
            state["tm"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            state["lm"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            continue
        if operator == "Tf" and len(operands) >= 2:
            state["font_size"] = abs(_num(operands[-1]))
            continue
        if operator == "Tr" and operands:
            state["render"] = int(_num(operands[0]))
            continue
        if operator == "Tz" and operands:
            state["hscale"] = _num(operands[0], 100.0) / 100.0
            continue
        if operator == "TL" and operands:
            state["leading"] = _num(operands[0])
            continue
        if operator == "Tc" and operands:
            state["char_space"] = _num(operands[0])
            continue
        if operator == "Tw" and operands:
            state["word_space"] = _num(operands[0])
            continue
        if operator == "Tm" and len(operands) >= 6:
            state["tm"] = [_num(v) for v in operands[:6]]
            state["lm"] = list(state["tm"])
            continue
        if operator in ("Td", "TD") and len(operands) >= 2:
            tx, ty = _num(operands[0]), _num(operands[1])
            if operator == "TD":
                state["leading"] = -ty
            state["lm"] = [state["lm"][0], state["lm"][1], state["lm"][2], state["lm"][3],
                           state["lm"][4] + tx, state["lm"][5] + ty]
            state["tm"] = list(state["lm"])
            continue
        if operator == "T*":
            state["lm"] = [state["lm"][0], state["lm"][1], state["lm"][2], state["lm"][3],
                           state["lm"][4], state["lm"][5] - state["leading"]]
            state["tm"] = list(state["lm"])
            continue
        if operator in ("rg", "g", "k", "sc", "scn"):
            nums: List[float] = []
            for value in operands:
                try:
                    nums.append(float(_resolve(value)))
                except Exception:
                    continue
            if nums:
                state["fill"] = nums
                state["cs"] = "CMYK" if len(nums) == 4 else ("RGB" if len(nums) == 3 else "Gray")
            continue
        if operator == "cs":
            state["cs"] = _name(operands[0]) if operands else ""
            continue
        if operator not in ("Tj", "TJ", "'", '"'):
            continue
        text = _operation_strings(operator, operands)
        if not text:
            continue
        ctm = state["ctm"]
        tm = state["tm"]
        x = tm[4] * ctm[0] + tm[5] * ctm[2] + ctm[4]
        y = tm[4] * ctm[1] + tm[5] * ctm[3] + ctm[5]
        reasons: List[str] = []
        if state["render"] == 3:
            reasons.append("невидимый режим отрисовки Tr 3")
            acc["invisible_chars"] += len(text)
        if 0 < state["font_size"] <= 0.1:
            reasons.append("размер шрифта <= 0.1")
            acc["tiny_chars"] += len(text)
        if x < x0 - 2 or x > x1 + 2 or y < y0 - 2 or y > y1 + 2:
            reasons.append("текст вне области страницы")
            acc["offpage_chars"] += len(text)
        fill = state.get("fill")
        if fill and all(v >= 0.995 for v in fill):
            acc["white_chars"] += len(text)
        if reasons:
            add_segment("; ".join(reasons), text, text)
        else:
            acc["visible_chars"] += len(text)
        acc["total_chars"] += len(text)
        advance = (len(text) * max(state["font_size"], 0.1) * 0.5 * state["hscale"]
                   + state["char_space"] * len(text) + state["word_space"] * text.count(" "))
        state["tm"] = [tm[0], tm[1], tm[2], tm[3], tm[4] + advance, tm[5]]
        state["lm"] = list(state["tm"])


def _walk_forms(resources: Any, page_box: Tuple[float, float, float, float], location: str,
                acc: Dict[str, Any], seen: set, depth: int = 0) -> None:
    if depth > 8:
        return
    resources = _resolve(resources)
    if not isinstance(resources, dict):
        return
    xobjects = _resolve(resources.get("/XObject"))
    if not isinstance(xobjects, dict):
        return
    from pypdf.generic import ContentStream
    for name, ref in list(xobjects.items()):
        stream = _resolve(ref)
        if not isinstance(stream, dict) or _name(stream.get("/Subtype")) != "/Form":
            continue
        marker = id(stream)
        if marker in seen:
            continue
        seen.add(marker)
        try:
            cs = ContentStream(stream, None)
            _analyze_operations(cs.operations, page_box, f"{location}/XObject{name}", acc, depth + 1)
        except Exception:
            continue
        _walk_forms(stream.get("/Resources"), page_box, f"{location}/XObject{name}", acc, seen, depth + 1)


def _whitespace_stats(text: str) -> Dict[str, Any]:
    length = len(text)
    space_runs = re.findall(r"[ \t]{16,}", text)
    zero_width = sum(text.count(ch) for ch in "\u200b\u200c\u200d\u2060\ufeff")
    soft_hyphen = text.count("\u00ad")
    trailing_space_lines = len(re.findall(r"[ \t]+\r?\n", text))
    whitespace = sum(1 for ch in text if ch.isspace())
    return {
        "characters": length,
        "whitespace_ratio": round(whitespace / length, 4) if length else 0.0,
        "space_runs": len(space_runs),
        "max_space_run": max((len(x) for x in space_runs), default=0),
        "zero_width": zero_width,
        "soft_hyphen": soft_hyphen,
        "trailing_space_lines": trailing_space_lines,
    }


def _collect_hidden_text(reader: Any, audit: _PdfAudit, cfg: Config) -> Dict[str, Any]:
    from pypdf.generic import ContentStream

    acc: Dict[str, Any] = {
        "segments": 0, "hidden_chars": 0, "invisible_chars": 0, "tiny_chars": 0,
        "offpage_chars": 0, "white_chars": 0, "visible_chars": 0, "total_chars": 0,
        "examples": [], "pages_with_hidden_text": 0, "whitespace": {},
    }
    texts: List[str] = []
    text_size = 0
    try:
        pages = list(reader.pages)
    except Exception:
        pages = []
    for page_no, page in enumerate(pages, 1):
        if cfg.pdf.max_pages and page_no > cfg.pdf.max_pages:
            break
        box = _bbox(page)
        before = acc["hidden_chars"]
        try:
            content = page.get_contents()
            if content is not None:
                cs = ContentStream(content, reader)
                _analyze_operations(cs.operations, box, f"страница {page_no}", acc)
        except Exception:
            pass
        try:
            resources = page.get("/Resources")
            if resources is None:
                resources = page.get_inherited("/Resources") if hasattr(page, "get_inherited") else None
            _walk_forms(resources, box, f"страница {page_no}", acc, set())
        except Exception:
            pass
        if acc["hidden_chars"] > before:
            acc["pages_with_hidden_text"] += 1
        if cfg.pdf.analyze_text and text_size < cfg.pdf.max_text_chars:
            try:
                text = page.extract_text() or ""
                if text:
                    remaining = cfg.pdf.max_text_chars - text_size
                    texts.append(text[:remaining])
                    text_size += len(texts[-1])
            except Exception:
                pass
    combined = "\n".join(texts)
    ws = _whitespace_stats(combined)
    acc["whitespace"] = ws

    if acc["hidden_chars"]:
        severity = "critical" if acc["hidden_chars"] > 1000 else "high"
        audit.add("PDF_HIDDEN_TEXT", severity, "Обнаружен скрытый текстовый слой",
                  f"Скрытых символов: {acc['hidden_chars']} на страницах: {acc['pages_with_hidden_text']}; "
                  f"пример: {_safe_preview(acc['examples'][0]['preview'] if acc['examples'] else '', 120)}")
    if acc["invisible_chars"]:
        audit.add("PDF_INVISIBLE_TEXT", "high", "Невидимый текст (Tr 3)",
                  f"Символов: {acc['invisible_chars']}")
    if acc["tiny_chars"]:
        audit.add("PDF_TINY_TEXT", "high", "Микроскопический текст",
                  f"Символов: {acc['tiny_chars']}")
    if acc["offpage_chars"]:
        audit.add("PDF_OFFPAGE_TEXT", "medium", "Текст за пределами области страницы",
                  f"Символов: {acc['offpage_chars']}")
    if acc["white_chars"]:
        audit.add("PDF_WHITE_TEXT", "medium", "Белый текст (возможное сокрытие)",
                  f"Символов: {acc['white_chars']}")

    if ws["zero_width"] > 20:
        audit.add("PDF_ZERO_WIDTH_TEXT", "high", "Символы нулевой ширины в тексте",
                  f"Найдено {ws['zero_width']} символов U+200B/200C/200D/2060/FEFF")
    if ws["max_space_run"] >= 32 or ws["space_runs"] >= 10:
        audit.add("PDF_WHITESPACE_STEGO", "high", "Подозрительные последовательности пробелов",
                  f"Серий пробелов >=16: {ws['space_runs']}, максимальная длина: {ws['max_space_run']}")
    if ws["characters"] > 1000 and ws["whitespace_ratio"] > 0.7:
        audit.add("PDF_WHITESPACE_RATIO", "medium", "Аномально высокая доля пробельных символов",
                  f"{ws['whitespace_ratio']:.1%} из {ws['characters']} символов")
    if ws["trailing_space_lines"] > 50:
        audit.add("PDF_TRAILING_SPACES", "medium", "Следы кодирования в пробелах",
                  f"Строк с завершающими пробелами: {ws['trailing_space_lines']}")

    return acc


# --------------------------------------------------------------------------- орфаны

def _scan_orphans(reader: Any, audit: _PdfAudit) -> List[Dict[str, Any]]:
    if PdfReader is None or IndirectObject is None:
        return []
    out: List[Dict[str, Any]] = []
    headers = _object_headers(bytes(audit.raw))[:audit.cfg.max_objects]
    for num, gen, offset in headers:
        if num in audit.referenced:
            continue
        try:
            obj = reader.get_object(IndirectObject(num, gen, reader))
        except Exception:
            continue
        if not callable(getattr(obj, "get_data", None)):
            continue
        data, truncated = _stream_bytes(obj, limit=audit.cfg.max_stream_bytes)
        if data is None:
            continue
        sigs = scan_signatures(data[:4096], limit=3)
        entropy = shannon_entropy(data) if data else 0.0
        if sigs or (len(data) > 1024 and entropy > 7.5 and _is_textish(data) is False):
            out.append({
                "object": num, "offset": offset, "length": len(data),
                "entropy": round(entropy, 3),
                "signatures": [f"{label} (+{pos})" for pos, label in sigs],
                "preview": _bytes_preview(data),
            })
    if out:
        details = "; ".join(
            f"объект {x['object']}: {x['length']} байт, энтропия {x['entropy']:.2f}"
            + (", " + ", ".join(x["signatures"]) if x["signatures"] else "")
            for x in out[:8]
        )
        audit.add("PDF_ORPHAN_STREAM", "high" if any(x["signatures"] for x in out) else "medium",
                  "Неиспользуемые (осиротевшие) потоки PDF", details)
    count = len(out)
    if count:
        audit.add("PDF_UNREFERENCED_OBJECTS", "low", "Неиспользуемые объекты PDF",
                  f"Обнаружено {count} неиспользуемых потоков; могут содержать остатки предыдущих версий")
    return out


# --------------------------------------------------------------------------- оценка

_RAW_SEMANTIC_MAP = {
    "PDF_JAVASCRIPT_RAW": ("PDF_JAVASCRIPT", "PDF_JAVASCRIPT_DANGEROUS", "PDF_JAVASCRIPT_NAMES",
                           "PDF_JAVASCRIPT_OBFUSCATED", "PDF_CODE_IN_STREAM", "PDF_OBJSTM_ACTIVE"),
    "PDF_RAW_JAVASCRIPT": ("PDF_JAVASCRIPT", "PDF_JAVASCRIPT_DANGEROUS", "PDF_JAVASCRIPT_NAMES",
                           "PDF_JAVASCRIPT_OBFUSCATED", "PDF_CODE_IN_STREAM", "PDF_OBJSTM_ACTIVE"),
    "PDF_RAW_LAUNCH": ("PDF_LAUNCH", "PDF_ACTION_LAUNCH"),
    "PDF_RAW_SUBMITFORM": ("PDF_SUBMIT_FORM", "PDF_ACTION_SUBMITFORM"),
    "PDF_RAW_IMPORTDATA": ("PDF_IMPORT_DATA", "PDF_ACTION_IMPORTDATA"),
    "PDF_RAW_GOTOR": ("PDF_REMOTE_GOTO", "PDF_ACTION_GOTOR"),
    "PDF_RAW_GOTOE": ("PDF_REMOTE_GOTO", "PDF_ACTION_GOTOE"),
    "PDF_RAW_RICHMEDIA": ("PDF_RICH_MEDIA", "PDF_ACTION_RICHMEDIA"),
    "PDF_RAW_EMBEDDEDFILES": ("PDF_EMBEDDED_FILES", "PDF_EMBEDDED_STREAM", "PDF_ATTACHMENT"),
    "PDF_RAW_XFA": ("PDF_XFA",),
    "PDF_RAW_ACROFORM": ("PDF_ACROFORM",),
    "PDF_RAW_OPENACTION": ("PDF_OPEN_ACTION",),
    "PDF_RAW_AA": ("PDF_ADDITIONAL_ACTIONS",),
    "PDF_RAW_OBJSTM": ("PDF_OBJECT_STREAM",),
    "PDF_RAW_ENCRYPT": ("PDF_ENCRYPTED", "PDF_ENCRYPT"),
    "PDF_RAW_SIG": ("PDF_SIGNATURE",),
    "PDF_RAW_BYTERANGE": ("PDF_SIGNATURE",),
    "PDF_RAW_METADATA": ("PDF_XMP", "PDF_METADATA"),
    "PDF_RAW_COLLECTION": ("PDF_PORTFOLIO",),
    "PDF_RAW_FILESPEC": ("PDF_FILESPEC", "PDF_ATTACHMENT"),
    "PDF_RAW_EF": ("PDF_FILESPEC", "PDF_EMBEDDED_STREAM", "PDF_ATTACHMENT"),
    "PDF_RAW_MOVIE": ("PDF_MULTIMEDIA", "PDF_ACTION_MOVIE"),
    "PDF_RAW_SOUND": ("PDF_MULTIMEDIA", "PDF_ACTION_SOUND"),
    "PDF_RAW_3D": ("PDF_3D", "PDF_ACTION_3D"),
    "PDF_RAW_RENDITION": ("PDF_RENDITION", "PDF_ACTION_RENDITION"),
    "PDF_RAW_SCREEN": ("PDF_ACTION_SCREEN",),
}


def _prune_duplicate_findings(audit: _PdfAudit) -> None:
    """Убрать сырые токен-находки, если объектный разбор уже дал точную находку."""
    codes = {f["code"] for f in audit.findings}
    if not codes:
        return
    kept: List[Dict[str, Any]] = []
    for finding in audit.findings:
        semantic = _RAW_SEMANTIC_MAP.get(finding["code"])
        if semantic and any(code in codes for code in semantic):
            continue
        kept.append(finding)
    audit.findings = kept


def _findings_risk(findings: Sequence[Dict[str, Any]]) -> float:
    weights = [SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings]
    if not weights:
        return 0.0
    base = max(weights)
    if base == 0:
        return 0.0
    max_count = sum(1 for w in weights if w == base)
    lower = sum(w for w in weights if w < base)
    return round(min(100.0, base + 5.0 * max(0, max_count - 1) + 0.15 * lower), 1)


def _recommendations(findings: Sequence[Dict[str, Any]], pdf: Dict[str, Any]) -> List[str]:
    codes = {f["code"] for f in findings}
    recs = [
        "Открывать документ только в изолированной среде и с отключённым JavaScript.",
        "Не запускать вложения и не переходить по внешним ссылкам из документа.",
        "Результат статического анализа не является гарантией безопасности документа.",
    ]
    if codes & {"PDF_JAVASCRIPT", "PDF_JAVASCRIPT_DANGEROUS", "PDF_JAVASCRIPT_RAW", "PDF_ACTION_JAVASCRIPT",
                "PDF_JAVASCRIPT_OBFUSCATED", "PDF_CODE_IN_STREAM", "PDF_OBJSTM_ACTIVE"}:
        recs.insert(0, "Не открывать документ в настольном просмотрщике; изолировать и проверить в песочнице.")
        recs.insert(1, "Применить PDF-санитизацию (sanitize) для удаления JavaScript и активных действий.")
    if codes & {"PDF_LAUNCH", "PDF_RAW_LAUNCH", "PDF_ACTION_LAUNCH", "PDF_SUBMIT_FORM", "PDF_IMPORT_DATA",
                "PDF_REMOTE_GOTO", "PDF_RICH_MEDIA", "PDF_3D", "PDF_RENDITION"}:
        recs.insert(0, "Обнаружены активные конструкции: документ нельзя передавать в промышленный сегмент без очистки.")
    if codes & {"PDF_ATTACHMENT", "PDF_EMBEDDED_FILES", "PDF_EMBEDDED_STREAM", "PDF_ASSOCIATED_FILES",
                "PDF_ACTION_SUBMITFORM", "PDF_ACTION_IMPORTDATA"}:
        recs.insert(0, "Извлечь вложения (pdf-extract) и проверить отдельными средствами; удалить их из документа.")
    if codes & {"PDF_HIDDEN_TEXT", "PDF_INVISIBLE_TEXT", "PDF_TINY_TEXT", "PDF_OFFPAGE_TEXT",
                "PDF_WHITESPACE_STEGO", "PDF_ZERO_WIDTH_TEXT"}:
        recs.insert(0, "Удалить скрытый текстовый слой: выполнить PDF-санитизацию с фильтрацией скрытого текста.")
    if codes & {"PDF_TRAILING_DATA", "PDF_STREAM_TRAILING", "PDF_STARTXREF_INVALID",
                "PDF_UNREFERENCED_OBJECTS", "PDF_ORPHAN_STREAM", "PDF_INCREMENTAL_UPDATES"}:
        recs.insert(0, "Перезаписать PDF через санитайзер: удаляются хвостовые данные, старые и неиспользуемые объекты.")
    if codes & {"PDF_IMAGE_STEGO", "PDF_IMAGE_SUSPICIOUS"}:
        recs.insert(0, "Перекодировать изображения PDF: санитайзер перезаписывает их без LSB-канала.")
    if pdf.get("encrypted") and not pdf.get("decrypted"):
        recs.insert(0, "Получить пароль и повторить анализ в контролируемой среде; без пароля часть объектов не проверена.")
    return recs


def _verdict(risk: float, findings: Sequence[Dict[str, Any]], cfg: Config) -> Tuple[str, str]:
    critical = any(f.get("severity") == "critical" for f in findings)
    if critical or risk >= cfg.thresholds.risk_stego:
        return "STEGO_DETECTED", "Обнаружены опасные конструкции или скрытые данные PDF"
    if risk >= cfg.thresholds.risk_suspicious:
        return "SUSPICIOUS", "Требуется дополнительная проверка PDF"
    return "CLEAN", "Подозрительные PDF-конструкции не выявлены"


# --------------------------------------------------------------------------- публичный API

def analyze_pdf(path: str, config: Optional[Config] = None, password: Optional[str] = None) -> Dict[str, Any]:
    """Полный статический анализ PDF. Содержимое документа не исполняется."""
    started = time.perf_counter()
    cfg = config or Config()
    pdf_cfg = getattr(cfg, "pdf", None) or PdfSettings()
    with open(path, "rb") as fh:
        raw = fh.read()
    audit = _PdfAudit(raw, pdf_cfg)
    layout = _raw_layout(raw)
    tokens = _raw_token_counts(raw)
    _raw_findings(audit, layout, tokens)

    reader = None
    parse_error: Optional[str] = None
    encrypted = False
    decrypted = False
    pages: Optional[int] = None
    metadata: Dict[str, Any] = {}
    xmp: Dict[str, Any] = {"present": False}
    forms: Dict[str, Any] = {"acroform": False, "xfa": False, "fields": 0, "need_appearances": False}
    permissions: Dict[str, Any] = {}
    attachments: List[Dict[str, Any]] = []
    image_checks: List[Dict[str, Any]] = []
    image_total = 0
    max_image_payload = 0.0
    max_image_detection = 0.0
    hidden_text: Dict[str, Any] = {}
    root = None

    if PdfReader is None:
        parse_error = ("Для полного структурного разбора PDF требуется пакет pypdf. "
                       "Установите его из локального установочного комплекта.")
        audit.add("PDF_PARSER_MISSING", "high", "Отсутствует модуль разбора PDF",
                  "Выполнена только низкоуровневая проверка сырых байтов")
    else:
        try:
            reader = PdfReader(path, strict=False)
        except Exception as exc:
            parse_error = f"Не удалось открыть PDF: {exc}"
            audit.add("PDF_PARSE_ERROR", "high", "PDF не удалось корректно открыть", str(exc)[:500])
        if reader is not None:
            try:
                encrypted = bool(reader.is_encrypted)
            except Exception:
                encrypted = False
            if encrypted:
                try:
                    result = reader.decrypt(password or "")
                    decrypted = bool(result)
                except Exception as exc:
                    decrypted = False
                    parse_error = f"PDF зашифрован; требуется пароль: {exc}"
                if not decrypted:
                    audit.add("PDF_ENCRYPTED", "high", "PDF зашифрован",
                              "Содержимое не может быть полностью проверено без пароля")
                else:
                    audit.add("PDF_ENCRYPTED", "info", "PDF был зашифрован",
                              "Разбор выполнен с паролем; содержимое проверяется")
            try:
                root = reader.root_object
            except Exception as exc:
                parse_error = parse_error or f"Не удалось прочитать каталог PDF: {exc}"
                root = None
            if root is not None and not (encrypted and not decrypted):
                try:
                    pages = len(reader.pages)
                except Exception:
                    pages = None
                root_ref = None
                try:
                    root_ref = reader.trailer.get("/Root")
                except Exception:
                    root_ref = None
                if _idnum(root_ref) is not None:
                    audit.referenced.add(_idnum(root_ref))
                audit.walk(root, "/Root")
                metadata = _collect_info(reader, audit)
                xmp = _collect_xmp(reader, root, audit, pdf_cfg)
                forms = _collect_forms(reader, root, audit)
                try:
                    perms = reader.user_access_permissions
                    if perms is not None:
                        permissions = {k: bool(v) for k, v in vars(perms).items() if not k.startswith("_")}
                except Exception:
                    permissions = {}
                attachments = _collect_attachments(reader, audit)
                image_checks, image_total, max_image_payload, max_image_detection = \
                    _collect_images(reader, audit, cfg)
                hidden_text = _collect_hidden_text(reader, audit, cfg)
                audit.referenced.add(0)
                _scan_orphans(reader, audit)
            elif encrypted and not decrypted:
                # Даже без расшифровки доступны trailer/root в некоторых реализациях.
                try:
                    metadata = _collect_info(reader, audit)
                except Exception:
                    pass

    # Дополнительная сверка сырых токенов с результатами обхода.
    if tokens.get("/EmbeddedFiles", 0) and not attachments:
        audit.add("PDF_EMBEDDED_FILES_RAW", "high", "Каталог вложенных файлов в сыром PDF",
                  f"Найдено вхождений: {tokens['/EmbeddedFiles']}")
    if tokens.get("/Encrypt", 0) and not encrypted:
        audit.add("PDF_ENCRYPT_RAW", "medium", "Токен шифрования без распознанного словаря",
                  "Возможна повреждённая или обфусцированная структура")
    if tokens.get("/XFA", 0) and not forms.get("xfa"):
        audit.add("PDF_XFA_RAW", "high", "Токен XFA в сыром PDF",
                  f"Найдено вхождений: {tokens['/XFA']}")
    if tokens.get("/AcroForm", 0) and not forms.get("acroform"):
        audit.add("PDF_ACROFORM_RAW", "low", "Токен AcroForm в сыром PDF",
                  f"Найдено вхождений: {tokens['/AcroForm']}")

    _check_signature_coverage(audit, len(raw))
    _prune_duplicate_findings(audit)

    findings = audit.findings
    structural_risk = _findings_risk(findings)
    statistical_risk = round(max_image_detection * 100.0, 1)
    risk = round(100.0 * (1.0 - (1.0 - structural_risk / 100.0) * (1.0 - statistical_risk / 100.0)), 1)
    verdict, verdict_label = _verdict(risk, findings, cfg)

    reasons = [f"{f['title']}: {f['details']}" if f.get("details") else f["title"]
               for f in findings if f.get("severity") in ("medium", "high", "critical")]
    if statistical_risk >= cfg.thresholds.risk_suspicious and not any(
            f["code"].startswith("PDF_IMAGE") for f in findings):
        reasons.append(f"Статистическая оценка изображений PDF: риск {statistical_risk:.1f}")
    if not reasons:
        reasons = ["Статические индикаторы из проверяемого набора не обнаружены."]

    pdf = {
        "header": layout["header"],
        "version": layout["version"],
        "pages": pages,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "linearized": layout["linearized"],
        "objects": layout["object_count"],
        "streams": layout["stream_count"],
        "object_streams": max(layout["object_streams"], audit.object_streams),
        "xref_type": layout["xref_kind"],
        "startxref": layout["startxref"],
        "startxref_valid": layout["startxref_valid"],
        "eof_markers": layout["eof_count"],
        "incremental_updates": max(layout["incremental_updates"], layout["prev_links"]),
        "leading_bytes": layout["leading_bytes"],
        "trailing_bytes": layout["trailing_meaningful"],
        "metadata": metadata,
        "xmp": xmp,
        "javascript": bool(audit.javascripts or tokens.get("/JavaScript", 0) or tokens.get("/JS", 0)),
        "javascript_count": len(audit.javascripts),
        "actions": audit.actions[:200],
        "action_count": len(audit.actions),
        "attachments": len(attachments),
        "embedded_files": len(attachments),
        "attachment_list": attachments[:100],
        "images": image_total,
        "analyzed_images": len(image_checks),
        "image_checks": image_checks[:200],
        "max_image_payload": round(max_image_payload, 4),
        "max_image_detection": round(max_image_detection, 4),
        "hidden_text": hidden_text,
        "forms": forms,
        "signatures": audit.signatures,
        "signature_count": len(audit.signatures),
        "permissions": permissions,
        "producer": metadata.get("Producer"),
        "creator": metadata.get("Creator"),
        "created": metadata.get("CreationDate"),
        "modified": metadata.get("ModDate"),
        "notes": audit.notes[:100],
    }

    structure = {
        "findings": findings,
        "chunk_summary": {},
        "trailing_bytes": layout["trailing_meaningful"],
        "objects": layout["object_count"],
        "streams": layout["stream_count"],
        "object_streams": layout["object_streams"],
        "xref_type": layout["xref_kind"],
        "eof_markers": layout["eof_count"],
        "incremental_updates": layout["incremental_updates"],
        "structural_risk": structural_risk,
        "max_severity": max((f["severity"] for f in findings),
                            key=lambda s: SEVERITY_WEIGHTS.get(s, 0), default="info"),
    }

    result = {
        "tool": __app_name__,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "file": os.path.abspath(path),
        "file_name": os.path.basename(path),
        "file_size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "format": "PDF",
        "pdf": pdf,
        "structure": structure,
        "attachments": attachments,
        "embedded_image_checks": image_checks,
        "javascript_checks": audit.javascripts,
        "actions": audit.actions,
        "hidden_text": hidden_text,
        "stream_checks": audit.stream_checks,
        "xmp": xmp,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "risk_score": risk,
        "statistical_risk": statistical_risk,
        "structural_risk": structural_risk,
        "reasons": reasons,
        "recommendations": _recommendations(findings, pdf),
        "parse_error": parse_error,
        "elapsed_sec": round(time.perf_counter() - started, 3),
    }
    return to_jsonable(result)


def extract_pdf_attachments(path: str, out_dir: str, password: Optional[str] = None,
                            limit: int = 1000) -> List[Dict[str, Any]]:
    """Извлечь вложенные файлы PDF в каталог с безопасными именами."""
    if PdfReader is None:
        raise RuntimeError("Для извлечения вложений требуется пакет pypdf")
    reader = PdfReader(path, strict=False)
    if getattr(reader, "is_encrypted", False):
        if not reader.decrypt(password or ""):
            raise ValueError("PDF зашифрован: требуется корректный пароль")
    os.makedirs(out_dir, exist_ok=True)
    written: List[Dict[str, Any]] = []
    used: set = set()
    for item in _attachment_items(reader, limit):
        data = _attachment_content(item)
        if data is None:
            continue
        name = str(getattr(item, "name", None) or getattr(item, "alternative_name", None) or "attachment")
        name = os.path.basename(name.replace("\\", "/"))
        name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]+", "_", name).strip(" .") or "attachment"
        base, ext = os.path.splitext(name)
        candidate = name
        k = 1
        while candidate.lower() in used or os.path.exists(os.path.join(out_dir, candidate)):
            k += 1
            candidate = f"{base}_{k}{ext}"
        used.add(candidate.lower())
        target = os.path.abspath(os.path.join(out_dir, candidate))
        if os.path.commonpath([os.path.abspath(out_dir), target]) != os.path.abspath(out_dir):
            continue
        with open(target, "wb") as fh:
            fh.write(data)
        written.append({
            "name": name,
            "path": target,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "format": _guess_format(name, data),
        })
    return written
