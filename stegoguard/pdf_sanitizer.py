"""CDR-санитизация PDF: удаление активного содержимого, вложений, форм, аннотаций,
метаданных, скрытого текста и перекодирование изображений без LSB-канала.

Документ пересобирается через ``PdfWriter``: в результат попадают только страницы и
ресурсы, необходимые для отображения. JavaScript, действия, вложенные файлы, формы,
ссылки, цифровые подписи, метаданные и данные после EOF в очищенную копию не переносятся.
Содержимое PDF не исполняется.
"""
from __future__ import annotations

import hashlib
import io
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

try:  # pypdf импортируется мягко: без него санитизация PDF недоступна
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ContentStream,
        DecodedStreamObject,
        NameObject,
        NumberObject,
    )
except Exception:  # pragma: no cover - зависит от окружения
    PdfReader = None
    PdfWriter = None
    ContentStream = None
    DecodedStreamObject = None
    NameObject = None
    NumberObject = None

from .metrics import psnr
from .sanitizer import rewrite_lsb_predictive

ROOT_REMOVE_KEYS = (
    "/OpenAction", "/AA", "/Metadata", "/Names", "/AcroForm", "/AF", "/Collection",
    "/Outlines", "/Perms", "/PieceInfo", "/SpiderInfo", "/DSS", "/OCProperties",
    "/StructTreeRoot", "/MarkInfo", "/Requirements", "/Dests",
)
PAGE_REMOVE_KEYS = (
    "/Annots", "/AA", "/OpenAction", "/Metadata", "/PieceInfo", "/AF", "/Thumb",
    "/B", "/Dur", "/Trans", "/PresSteps", "/StructParents",
)
FORM_REMOVE_KEYS = ("/AA", "/OpenAction", "/Metadata", "/PieceInfo", "/AF", "/OC")
MAX_IMAGE_PIXELS = 80_000_000


def _resolve(obj: Any) -> Any:
    if obj is None:
        return None
    getter = getattr(obj, "get_object", None)
    if callable(getter):
        try:
            resolved = getter()
            if resolved is not obj:
                return resolved
        except Exception:
            return None
    return obj


def _name(value: Any) -> str:
    value = _resolve(value)
    return "" if value is None else str(value)


def _idnum(value: Any) -> Optional[int]:
    try:
        return int(value.idnum)
    except Exception:
        return None


def _pop_keys(obj: Any, keys: Sequence[str], removed: Dict[str, int], category: str) -> int:
    count = 0
    if not hasattr(obj, "pop"):
        return 0
    for key in keys:
        try:
            if key in obj:
                obj.pop(key, None)
                count += 1
        except Exception:
            continue
    if count:
        removed[category] = removed.get(category, 0) + count
    return count


def _filter_operations(operations: Sequence[Any], page_box: Tuple[float, float, float, float],
                       stats: Dict[str, int]) -> List[Any]:
    """Удалить операторы показа текста, которые заведомо не видны читателю.

    Удаляются только целиком скрытые текстовые операторы: Tr 3, явно заданный
    микроскопический кегль и текст, начинающийся за пределами области страницы.
    Белый текст сохраняется, поскольку он может быть видимым на цветном фоне.
    """
    kept: List[Any] = []
    state: Dict[str, Any] = {
        "font_size": 0.0, "render": 0, "fill": None,
        "ctm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "tm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "lm": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "leading": 0.0, "hscale": 1.0, "char_space": 0.0, "word_space": 0.0,
    }
    stack: List[Dict[str, Any]] = []
    x0, y0, x1, y1 = page_box

    for item in operations:
        try:
            operands, op_raw = item
        except Exception:
            kept.append(item)
            continue
        operands = list(operands) if isinstance(operands, (list, tuple)) else []
        operator = op_raw.decode("latin1", "replace") if isinstance(op_raw, (bytes, bytearray)) else str(op_raw)
        if operator == "q":
            stack.append({k: (list(v) if isinstance(v, list) else v) for k, v in state.items()})
            kept.append(item)
            continue
        if operator == "Q":
            if stack:
                state = stack.pop()
            kept.append(item)
            continue
        if operator == "cm" and len(operands) >= 6:
            state["ctm"] = _mat_mul([_num(v) for v in operands[:6]], state["ctm"])
            kept.append(item)
            continue
        if operator == "BT":
            state["tm"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            state["lm"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            kept.append(item)
            continue
        if operator == "Tf" and len(operands) >= 2:
            state["font_size"] = abs(_num(operands[-1]))
            kept.append(item)
            continue
        if operator == "Tr" and operands:
            state["render"] = int(_num(operands[0]))
            kept.append(item)
            continue
        if operator == "Tz" and operands:
            state["hscale"] = _num(operands[0], 100.0) / 100.0
            kept.append(item)
            continue
        if operator == "TL" and operands:
            state["leading"] = _num(operands[0])
            kept.append(item)
            continue
        if operator == "Tc" and operands:
            state["char_space"] = _num(operands[0])
            kept.append(item)
            continue
        if operator == "Tw" and operands:
            state["word_space"] = _num(operands[0])
            kept.append(item)
            continue
        if operator == "Tm" and len(operands) >= 6:
            state["tm"] = [_num(v) for v in operands[:6]]
            state["lm"] = list(state["tm"])
            kept.append(item)
            continue
        if operator in ("Td", "TD") and len(operands) >= 2:
            tx, ty = _num(operands[0]), _num(operands[1])
            if operator == "TD":
                state["leading"] = -ty
            state["lm"] = [state["lm"][0], state["lm"][1], state["lm"][2], state["lm"][3],
                           state["lm"][4] + tx, state["lm"][5] + ty]
            state["tm"] = list(state["lm"])
            kept.append(item)
            continue
        if operator == "T*":
            state["lm"] = [state["lm"][0], state["lm"][1], state["lm"][2], state["lm"][3],
                           state["lm"][4], state["lm"][5] - state["leading"]]
            state["tm"] = list(state["lm"])
            kept.append(item)
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
            kept.append(item)
            continue
        if operator not in ("Tj", "TJ", "'", '"'):
            kept.append(item)
            continue
        text = _operation_strings(operator, operands)
        if not text:
            kept.append(item)
            continue
        ctm, tm = state["ctm"], state["tm"]
        x = tm[4] * ctm[0] + tm[5] * ctm[2] + ctm[4]
        y = tm[4] * ctm[1] + tm[5] * ctm[3] + ctm[5]
        hidden = False
        reason = ""
        if state["render"] == 3:
            hidden, reason = True, "tr3"
        elif 0 < state["font_size"] <= 0.1:
            hidden, reason = True, "tiny"
        elif x < x0 - 2 or x > x1 + 2 or y < y0 - 2 or y > y1 + 2:
            hidden, reason = True, "offpage"
        if hidden:
            stats[reason] = stats.get(reason, 0) + len(text)
            stats["removed_text_ops"] = stats.get("removed_text_ops", 0) + 1
            continue
        kept.append(item)
        advance = (len(text) * max(state["font_size"], 0.1) * 0.5 * state["hscale"]
                   + state["char_space"] * len(text) + state["word_space"] * text.count(" "))
        state["tm"] = [tm[0], tm[1], tm[2], tm[3], tm[4] + advance, tm[5]]
        state["lm"] = list(state["tm"])
    return kept


def _mat_mul(a: Sequence[float], b: Sequence[float]) -> List[float]:
    return [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(_resolve(value))
    except (TypeError, ValueError):
        return default


def _string_operand(value: Any) -> str:
    value = _resolve(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1", "replace")
    return ""


def _operation_strings(operator: str, operands: Sequence[Any]) -> str:
    if operator == "TJ":
        return "".join(_string_operand(item) for item in operands)
    if operator in ("Tj", "'", '"'):
        return _string_operand(operands[-1]) if operands else ""
    return ""


def _page_box(page: Any) -> Tuple[float, float, float, float]:
    for key in ("/MediaBox", "/CropBox"):
        box = _resolve(page.get(key)) if hasattr(page, "get") else None
        if isinstance(box, (list, tuple)) and len(box) >= 4:
            try:
                return tuple(float(_num(v)) for v in box[:4])  # type: ignore[return-value]
            except Exception:
                pass
    return 0.0, 0.0, 612.0, 792.0


def _stream_data(stream: Any) -> Optional[bytes]:
    getter = getattr(_resolve(stream), "get_data", None)
    if not callable(getter):
        return None
    try:
        data = getter()
    except Exception:
        return None
    return bytes(data) if isinstance(data, (bytes, bytearray)) else None


def _copy_stream_with_data(stream: Any, data: bytes) -> Any:
    new = DecodedStreamObject()
    for key, value in stream.items():
        if str(key) in ("/Length", "/Filter", "/DecodeParms"):
            continue
        new[key] = value
    new.set_data(data)
    return new.flate_encode()


def _sanitize_form(stream: Any, writer: Any, box: Tuple[float, float, float, float],
                   remove_hidden_text: bool, stats: Dict[str, Any], removed: Dict[str, int],
                   cache: Dict[int, Any], depth: int = 0) -> Any:
    marker = id(stream)
    if marker in cache:
        return cache[marker]
    if depth > 8:
        return None
    _pop_keys(stream, FORM_REMOVE_KEYS, removed, "form_keys")
    new_data = None
    if remove_hidden_text and ContentStream is not None:
        try:
            cs = ContentStream(stream, writer)
            ops = _filter_operations(cs.operations, box, stats)
            if len(ops) != len(cs.operations):
                cs.operations = ops
                new_data = cs.get_data() if len(ops) else b"q Q"
        except Exception as exc:
            stats.setdefault("warnings", []).append(f"Form XObject: {str(exc)[:160]}")
    if new_data is not None:
        new_stream = _copy_stream_with_data(stream, new_data)
        ref = writer._add_object(new_stream)
    else:
        ref = writer._add_object(stream)
    cache[marker] = ref
    return ref


def _image_files(page: Any) -> Dict[int, Any]:
    files: Dict[int, Any] = {}
    try:
        for image in page.images:
            ref = getattr(image, "indirect_reference", None)
            idn = _idnum(ref)
            if idn is not None and getattr(image, "image", None) is not None:
                files[idn] = image
    except Exception:
        pass
    return files


def _manual_image(stream: Any) -> Optional[Any]:
    from PIL import Image

    filters = _resolve(stream.get("/Filter"))
    if isinstance(filters, (list, tuple)):
        names = [_name(x) for x in filters]
    else:
        names = [_name(filters)] if filters is not None else []
    data = _stream_data(stream)
    if data is None:
        return None
    if any(name in ("/DCTDecode", "/JPXDecode") for name in names):
        try:
            return Image.open(io.BytesIO(data))
        except Exception:
            return None
    if names and names not in (["/FlateDecode"], ["/LZWDecode"]):
        return None
    try:
        width = int(_num(stream.get("/Width")))
        height = int(_num(stream.get("/Height")))
        bpc = int(_num(stream.get("/BitsPerComponent"), 8))
        cs = _name(stream.get("/ColorSpace"))
        channels = {"/DeviceGray": 1, "/DeviceRGB": 3, "/DeviceCMYK": 4}.get(cs)
        if not channels or bpc != 8:
            return None
        mode = {1: "L", 3: "RGB", 4: "CMYK"}[channels]
        return Image.frombytes(mode, (width, height), data)
    except Exception:
        return None


def _rewrite_array(ch: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    return rewrite_lsb_predictive(ch, rng)


def _alpha_mask_stream(alpha: np.ndarray, rng: np.random.Generator) -> Any:
    values = _rewrite_array(alpha.astype(np.int64), rng).astype(np.uint8)
    new = DecodedStreamObject()
    new[NameObject("/Type")] = NameObject("/XObject")
    new[NameObject("/Subtype")] = NameObject("/Image")
    new[NameObject("/Width")] = NumberObject(values.shape[1])
    new[NameObject("/Height")] = NumberObject(values.shape[0])
    new[NameObject("/ColorSpace")] = NameObject("/DeviceGray")
    new[NameObject("/BitsPerComponent")] = NumberObject(8)
    new.set_data(values.tobytes())
    return new.flate_encode()


def _rewrite_image(stream: Any, writer: Any, image_file: Any, rng: np.random.Generator,
                   stats: Dict[str, Any]) -> Optional[Any]:
    from PIL import Image

    if bool(_resolve(stream.get("/ImageMask"))):
        stats["images_skipped"] = stats.get("images_skipped", 0) + 1
        return None
    img = getattr(image_file, "image", None) if image_file is not None else None
    if img is None:
        img = _manual_image(stream)
    if img is None:
        stats["images_skipped"] = stats.get("images_skipped", 0) + 1
        stats.setdefault("warnings", []).append("Изображение пропущено: формат не декодируется Pillow")
        return None
    try:
        img.load()
    except Exception:
        stats["images_skipped"] = stats.get("images_skipped", 0) + 1
        return None
    width, height = img.size
    if width * height > MAX_IMAGE_PIXELS:
        stats["images_skipped"] = stats.get("images_skipped", 0) + 1
        stats.setdefault("warnings", []).append(
            f"Изображение {width}x{height} пропущено: превышен лимит пикселей")
        return None
    mode = img.mode
    alpha = None
    if mode in ("RGBA", "LA"):
        alpha = np.asarray(img.getchannel("A"))
        img = img.convert("RGB" if mode == "RGBA" else "L")
    elif mode == "P":
        has_alpha = "transparency" in img.info
        img = img.convert("RGBA" if has_alpha else "RGB")
        if has_alpha:
            alpha = np.asarray(img.getchannel("A"))
            img = img.convert("RGB")
    elif mode not in ("L", "RGB", "CMYK", "I;16", "I"):
        img = img.convert("RGB")
    if img.mode in ("I;16", "I"):
        arr = np.asarray(img).astype(np.int64)
        if arr.max(initial=0) > 65535:
            arr = arr.astype(np.int32)
        color_space, bits = "/DeviceGray", 16
        original = arr.copy()
        work = _rewrite_array(arr, rng)
        raw = work.astype(">u2").tobytes()
        maxv = 65535
    else:
        if img.mode not in ("L", "RGB", "CMYK"):
            img = img.convert("RGB")
        arr = np.asarray(img)
        color_space = {1: "/DeviceGray", 3: "/DeviceRGB", 4: "/DeviceCMYK"}[arr.shape[2] if arr.ndim == 3 else 1]
        bits = 8
        original = arr.copy()
        work = arr.astype(np.int64).copy()
        if work.ndim == 3:
            for c in range(work.shape[2]):
                work[..., c] = _rewrite_array(work[..., c], rng)
        else:
            work = _rewrite_array(work, rng)
        raw = work.astype(np.uint8).tobytes()
        maxv = 255
    new = DecodedStreamObject()
    new[NameObject("/Type")] = NameObject("/XObject")
    new[NameObject("/Subtype")] = NameObject("/Image")
    new[NameObject("/Width")] = NumberObject(width)
    new[NameObject("/Height")] = NumberObject(height)
    new[NameObject("/ColorSpace")] = NameObject(color_space)
    new[NameObject("/BitsPerComponent")] = NumberObject(bits)
    if "/Intent" in stream:
        new[NameObject("/Intent")] = stream["/Intent"]
    if "/Interpolate" in stream:
        new[NameObject("/Interpolate")] = stream["/Interpolate"]
    new.set_data(raw)
    encoded = new.flate_encode()
    # Прозрачность: маска перекодируется тем же способом и не содержит исходного LSB-канала.
    if alpha is not None:
        try:
            mask = _alpha_mask_stream(alpha, rng)
            encoded[NameObject("/SMask")] = writer._add_object(mask)
        except Exception:
            stats.setdefault("warnings", []).append("Не удалось перекодировать альфа-маску изображения")
    else:
        old_mask = _resolve(stream.get("/SMask"))
        if isinstance(old_mask, dict):
            mask_data = _stream_data(old_mask)
            if mask_data is not None:
                try:
                    if len(mask_data) == width * height:
                        mask_img = np.frombuffer(mask_data, dtype=np.uint8).reshape(height, width)
                    else:
                        m = _manual_image(old_mask)
                        mask_img = np.asarray(m.convert("L")) if m is not None else None
                    if mask_img is not None:
                        encoded[NameObject("/SMask")] = writer._add_object(
                            _alpha_mask_stream(mask_img, rng))
                except Exception:
                    stats.setdefault("warnings", []).append("SMask изображения сохранён без перекодирования")
                    try:
                        encoded[NameObject("/SMask")] = old_mask
                    except Exception:
                        pass
    try:
        value = psnr(original, work, maxv)
        stats.setdefault("image_psnr", []).append(round(float(value), 2))
    except Exception:
        pass
    stats["images_reencoded"] = stats.get("images_reencoded", 0) + 1
    return encoded


def _sanitize_resources(resources: Any, writer: Any, page: Any, remove_hidden_text: bool,
                        reencode_images: bool, stats: Dict[str, Any], removed: Dict[str, int],
                        form_cache: Dict[int, Any], image_seen: set,
                        image_map: Dict[int, Any], depth: int = 0) -> None:
    if depth > 8:
        return
    resources = _resolve(resources)
    if not isinstance(resources, dict):
        return
    xobjects = _resolve(resources.get("/XObject"))
    if not isinstance(xobjects, dict):
        return
    box = _page_box(page)
    for name, ref in list(xobjects.items()):
        stream = _resolve(ref)
        if not isinstance(stream, dict):
            continue
        subtype = _name(stream.get("/Subtype"))
        if subtype == "/Form":
            marker = id(stream)
            if marker in form_cache:
                xobjects[name] = form_cache[marker]
                continue
            new_ref = _sanitize_form(stream, writer, box, remove_hidden_text, stats, removed,
                                     form_cache, depth + 1)
            if new_ref is not None:
                xobjects[name] = new_ref
                _sanitize_resources(stream.get("/Resources"), writer, page, remove_hidden_text,
                                    reencode_images, stats, removed, form_cache, image_seen,
                                    image_map, depth + 1)
        elif subtype == "/Image" and reencode_images:
            marker = _idnum(ref) or id(stream)
            if marker in image_seen:
                continue
            image_seen.add(marker)
            image_file = image_map.get(_idnum(ref)) if _idnum(ref) is not None else None
            encoded = _rewrite_image(stream, writer, image_file, stats["rng"], stats)
            if encoded is not None:
                xobjects[name] = writer._add_object(encoded)


def _filter_page_text(page: Any, writer: Any, stats: Dict[str, Any]) -> None:
    if ContentStream is None:
        return
    try:
        content = page.get_contents()
    except Exception as exc:
        stats.setdefault("warnings", []).append(f"Не удалось прочитать содержимое страницы: {str(exc)[:160]}")
        return
    if content is None:
        return
    try:
        cs = ContentStream(content, writer)
        before = len(cs.operations)
        filtered = _filter_operations(cs.operations, _page_box(page), stats)
        if len(filtered) != before:
            cs.operations = filtered
            page.replace_contents(cs)
    except Exception as exc:
        stats.setdefault("warnings", []).append(f"Скрытый текст страницы не отфильтрован: {str(exc)[:160]}")


def _prune_writer_objects(writer: Any) -> int:
    """Пометить недостижимые объекты как свободные.

    ``PdfWriter`` записывает все объекты из своего списка, даже если после очистки
    на них больше нет ссылок. Оставлять их нельзя: в них остаются исходные
    изображения с LSB-каналом, старые потоки и удалённые вложения. Номера объектов
    не меняются, поэтому ссылки пересобирать не требуется.
    """
    objects = getattr(writer, "_objects", None)
    if not isinstance(objects, list):
        return 0
    seen: set = set()
    root_index = next((i for i, item in enumerate(objects, 1) if item is getattr(writer, "_root_object", None)), None)
    if root_index is not None:
        seen.add(root_index)
    stack: List[Any] = [getattr(writer, "_root_object", None)]
    while stack:
        obj = stack.pop()
        if obj is None:
            continue
        if isinstance(obj, dict):
            own_id = _idnum(getattr(obj, "indirect_reference", None))
            if own_id is not None and own_id not in seen and 1 <= own_id <= len(objects):
                seen.add(own_id)
            for value in obj.values():
                stack.append(value)
            continue
        if isinstance(obj, (list, tuple)):
            stack.extend(obj)
            continue
        idn = _idnum(obj)
        if idn is None or idn in seen or not (1 <= idn <= len(objects)):
            continue
        seen.add(idn)
        try:
            stack.append(objects[idn - 1])
        except Exception:
            continue
    pruned = 0
    for index in range(1, len(objects) + 1):
        if index not in seen and objects[index - 1] is not None:
            objects[index - 1] = None
            pruned += 1
    return pruned


def sanitize_pdf(src: str, dst: str, password: Optional[str] = None,
                 reencode_images: bool = True, remove_hidden_text: bool = True,
                 seed: Optional[int] = None, verify: bool = True) -> Dict[str, Any]:
    """Создать очищенную копию PDF.

    :param password: пароль только для чтения исходного документа; в отчёт не попадает.
    :param reencode_images: перекодировать изображения с перезаписью LSB.
    :param remove_hidden_text: удалить заведомо невидимые текстовые операторы.
    :param verify: повторно проанализировать результат встроенным анализатором.
    """
    if PdfReader is None or PdfWriter is None:
        raise RuntimeError("Для санитизации PDF требуется пакет pypdf")
    with open(src, "rb") as fh:
        raw = fh.read()
    reader = PdfReader(src, strict=False)
    encrypted = bool(getattr(reader, "is_encrypted", False))
    decrypted = False
    if encrypted:
        try:
            decrypted = bool(reader.decrypt(password or ""))
        except Exception as exc:
            raise ValueError(f"PDF зашифрован; не удалось расшифровать: {exc}") from exc
        if not decrypted:
            raise ValueError("PDF зашифрован: требуется корректный пароль")
    writer = PdfWriter()
    try:
        writer.pdf_header = reader.pdf_header
    except Exception:
        pass
    removed: Dict[str, int] = {}
    stats: Dict[str, Any] = {
        "rng": np.random.default_rng(seed if seed is not None else int.from_bytes(os.urandom(8), "big")),
        "warnings": [],
    }
    pages = 0
    for page in reader.pages:
        try:
            writer.add_page(page)
            pages += 1
        except Exception as exc:
            stats["warnings"].append(f"Страница {pages + 1} не перенесена: {str(exc)[:200]}")
    _pop_keys(writer._root_object, ROOT_REMOVE_KEYS, removed, "root_keys")
    try:
        writer.metadata = None
    except Exception:
        pass

    form_cache: Dict[int, Any] = {}
    image_seen: set = set()
    for page in writer.pages:
        _pop_keys(page, PAGE_REMOVE_KEYS, removed, "page_keys")
        image_map = _image_files(page)
        try:
            resources = page.get("/Resources")
            if resources is None and hasattr(page, "get_inherited"):
                resources = page.get_inherited("/Resources")
            _sanitize_resources(resources, writer, page, remove_hidden_text, reencode_images,
                                stats, removed, form_cache, image_seen, image_map)
        except Exception as exc:
            stats["warnings"].append(f"Ресурсы страницы не очищены: {str(exc)[:200]}")
        if remove_hidden_text:
            _filter_page_text(page, writer, stats)

    if reencode_images:
        stats["inline_images_note"] = ("Встроенные (inline) изображения в потоках содержимого "
                                       "сохраняются без перекодирования")
    removed["unreferenced_objects"] = _prune_writer_objects(writer)
    buf = io.BytesIO()
    writer.write(buf)
    data = buf.getvalue()
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(data)

    report: Dict[str, Any] = {
        "input": src,
        "output": dst,
        "format": "PDF",
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "output_sha256": hashlib.sha256(data).hexdigest(),
        "input_size": len(raw),
        "output_size": len(data),
        "pages": pages,
        "encrypted_input": encrypted,
        "decrypted_input": decrypted,
        "removed": removed,
        "removed_javascript": 1 if any(k in raw for k in (b"/JavaScript", b"/JS")) else 0,
        "removed_hidden_chars": sum(stats.get(k, 0) for k in ("tr3", "tiny", "offpage")),
        "hidden_text_ops_removed": stats.get("removed_text_ops", 0),
        "images_reencoded": stats.get("images_reencoded", 0),
        "images_skipped": stats.get("images_skipped", 0),
        "inline_images_note": stats.get("inline_images_note"),
        "image_psnr_min": min(stats.get("image_psnr", []), default=None),
        "image_psnr_mean": (round(float(np.mean(stats["image_psnr"])), 2)
                            if stats.get("image_psnr") else None),
        "reencode_images": bool(reencode_images),
        "remove_hidden_text": bool(remove_hidden_text),
        "warnings": stats.get("warnings", []),
        "notes": [
            "Документ пересобран: неиспользуемые объекты, старые версии и данные после EOF удалены.",
            "JavaScript, действия, вложения, формы, ссылки, подписи и метаданные в очищенную копию не переносятся.",
            "Содержимое PDF при санитизации не исполняется.",
        ] + ([stats["inline_images_note"]] if stats.get("inline_images_note") else []),
    }
    if verify:
        try:
            from .pdf_analyzer import analyze_pdf
            post = analyze_pdf(dst)
            residual = [f for f in post.get("structure", {}).get("findings", [])
                        if f.get("severity") in ("medium", "high", "critical")]
            report["verification"] = {
                "verdict": post.get("verdict"),
                "risk_score": post.get("risk_score"),
                "residual_findings": [
                    {"code": f.get("code"), "severity": f.get("severity"),
                     "title": f.get("title")} for f in residual
                ],
            }
        except Exception as exc:
            report["verification"] = {"error": str(exc)[:300]}
    return report
