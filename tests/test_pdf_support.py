import csv
import json
import os
import tempfile
import unittest

import numpy as np
from PIL import Image
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject, NumberObject, TextStringObject

from stegoguard.analyzer import Analyzer
from stegoguard.embedding import embed_message
from stegoguard.image_io import load_image
from stegoguard.pdf_analyzer import analyze_pdf, extract_pdf_attachments
from stegoguard.pdf_sanitizer import sanitize_pdf
from stegoguard.report import csv_row, render_html, write_reports
from stegoguard.utils import collect_files

from .helpers import camera_png


def _action(action_type, **kwargs):
    action = DictionaryObject()
    action[NameObject("/S")] = NameObject(action_type)
    for key, value in kwargs.items():
        action[NameObject("/" + key)] = value
    return action


def _add_attachment(writer, name, data):
    try:
        writer.add_attachment(name, data)          # pypdf >= 4.3
    except TypeError:
        writer.add_attachment(data, name)          # старые версии pypdf


def _add_hidden_text(page, writer):
    stream = DecodedStreamObject()
    stream.set_data(b"BT /F1 12 Tf 3 Tr 72 100 Td (SECRET HIDDEN TEXT) Tj ET")
    page[NameObject("/Contents")] = writer._add_object(stream)


def _image_pdf(path, with_payload=False, hidden=False):
    data = camera_png(5, 96, 96)
    img = load_image(data)
    if with_payload:
        img = embed_message(img, b"X" * 3000)
    pil = img.to_pil().convert("RGB")
    arr = np.asarray(pil, dtype=np.uint8)
    writer = PdfWriter()
    page = writer.add_blank_page(width=220, height=220)
    stream = DecodedStreamObject()
    stream[NameObject("/Type")] = NameObject("/XObject")
    stream[NameObject("/Subtype")] = NameObject("/Image")
    stream[NameObject("/Width")] = NumberObject(arr.shape[1])
    stream[NameObject("/Height")] = NumberObject(arr.shape[0])
    stream[NameObject("/ColorSpace")] = NameObject("/DeviceRGB")
    stream[NameObject("/BitsPerComponent")] = NumberObject(8)
    stream.set_data(arr.tobytes())
    ref = writer._add_object(stream.flate_encode())
    resources = DictionaryObject()
    xobjects = DictionaryObject()
    xobjects[NameObject("/Im0")] = ref
    resources[NameObject("/XObject")] = xobjects
    page[NameObject("/Resources")] = resources
    content = DecodedStreamObject()
    content.set_data(b"q 96 0 0 96 20 20 cm /Im0 Do Q")
    page[NameObject("/Contents")] = writer._add_object(content)
    if hidden:
        _add_hidden_text(page, writer)
    with open(path, "wb") as fh:
        writer.write(fh)
    return arr


class PdfAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _clean_pdf(self, name="clean.pdf"):
        path = os.path.join(self.d, name)
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        with open(path, "wb") as fh:
            writer.write(fh)
        return path

    def test_clean_pdf_without_active_actions(self):
        result = Analyzer().analyze_file(self._clean_pdf())
        self.assertEqual(result["format"], "PDF")
        self.assertEqual(result["verdict"], "CLEAN")
        self.assertFalse(result["pdf"]["javascript"])

    def test_pdf_javascript_and_open_action(self):
        path = os.path.join(self.d, "active.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        action = _action("/JavaScript", JS=TextStringObject('app.alert("test"); this.exportDataObject(1)'))
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(action)
        with open(path, "wb") as fh:
            writer.write(fh)
        result = Analyzer().analyze_file(path)
        self.assertEqual(result["format"], "PDF")
        self.assertTrue(result["pdf"]["javascript"])
        self.assertGreaterEqual(result["pdf"]["javascript_count"], 1)
        self.assertIn(result["verdict"], ("SUSPICIOUS", "STEGO_DETECTED"))
        codes = {f["code"] for f in result["structure"]["findings"]}
        self.assertTrue(codes & {"PDF_JAVASCRIPT", "PDF_JAVASCRIPT_DANGEROUS"})

    def test_pdf_launch_action_is_critical(self):
        path = os.path.join(self.d, "launch.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        action = _action("/Launch", F=TextStringObject("cmd.exe"))
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(action)
        with open(path, "wb") as fh:
            writer.write(fh)
        result = Analyzer().analyze_file(path)
        self.assertEqual(result["verdict"], "STEGO_DETECTED")
        titles = " ".join(f["title"] for f in result["structure"]["findings"])
        self.assertIn("Launch", titles)

    def test_attachment_detection_and_extraction(self):
        path = os.path.join(self.d, "attachment.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        _add_attachment(writer, "payload.exe", b"MZ\x90\x00" + b"A" * 64)
        with open(path, "wb") as fh:
            writer.write(fh)
        result = Analyzer().analyze_file(path)
        self.assertEqual(result["pdf"]["attachments"], 1)
        self.assertTrue(result["attachments"][0]["executable"])
        self.assertEqual(result["verdict"], "STEGO_DETECTED")
        out = os.path.join(self.d, "extracted")
        written = extract_pdf_attachments(path, out)
        self.assertEqual(len(written), 1)
        self.assertTrue(os.path.exists(written[0]["path"]))
        with open(written[0]["path"], "rb") as fh:
            self.assertTrue(fh.read().startswith(b"MZ"))

    def test_trailing_data_after_eof(self):
        path = self._clean_pdf("trailing.pdf")
        with open(path, "ab") as fh:
            fh.write(b"\nPK\x03\x04" + b"hidden trailing archive")
        result = Analyzer().analyze_file(path)
        codes = {f["code"] for f in result["structure"]["findings"]}
        self.assertIn("PDF_TRAILING_DATA", codes)
        self.assertEqual(result["verdict"], "STEGO_DETECTED")

    def test_encrypted_pdf_password(self):
        path = os.path.join(self.d, "encrypted.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer.encrypt("secret")
        with open(path, "wb") as fh:
            writer.write(fh)
        locked = Analyzer().analyze_file(path)
        self.assertTrue(locked["pdf"]["encrypted"])
        self.assertFalse(locked["pdf"]["decrypted"])
        self.assertIn(locked["verdict"], ("SUSPICIOUS", "STEGO_DETECTED"))
        opened = Analyzer().analyze_file(path, password="secret")
        self.assertTrue(opened["pdf"]["decrypted"])
        self.assertEqual(opened["verdict"], "CLEAN")

    def test_hidden_text_detection(self):
        path = os.path.join(self.d, "hidden.pdf")
        writer = PdfWriter()
        page = writer.add_blank_page(width=200, height=200)
        _add_hidden_text(page, writer)
        with open(path, "wb") as fh:
            writer.write(fh)
        result = Analyzer().analyze_file(path)
        self.assertGreater(result["hidden_text"]["hidden_chars"], 0)
        codes = {f["code"] for f in result["structure"]["findings"]}
        self.assertIn("PDF_HIDDEN_TEXT", codes)
        self.assertEqual(result["verdict"], "STEGO_DETECTED")

    def test_pdf_image_analysis(self):
        path = os.path.join(self.d, "image.pdf")
        _image_pdf(path, with_payload=True)
        result = Analyzer().analyze_file(path)
        self.assertEqual(result["pdf"]["images"], 1)
        self.assertEqual(result["pdf"]["analyzed_images"], 1)
        self.assertTrue(result["embedded_image_checks"])
        self.assertIn("effective_payload", result["embedded_image_checks"][0])

    def test_signature_detection(self):
        path = self._clean_pdf("signed.pdf")
        raw = open(path, "rb").read()
        # Вставляем минимальный словарь подписи в каталог и корректируем ссылку через pypdf.
        from pypdf import PdfReader
        reader = PdfReader(path)
        writer = PdfWriter()
        writer.add_page(reader.pages[0])
        sig = DictionaryObject()
        sig[NameObject("/Type")] = NameObject("/Sig")
        sig[NameObject("/ByteRange")] = writer._add_object(
            __import__("pypdf").generic.ArrayObject([
                NumberObject(0), NumberObject(10), NumberObject(20), NumberObject(30)]))
        writer._root_object[NameObject("/Perms")] = writer._add_object(
            DictionaryObject({NameObject("/DocMDP"): writer._add_object(sig)}))
        with open(path, "wb") as fh:
            writer.write(fh)
        result = Analyzer().analyze_file(path)
        self.assertGreaterEqual(result["pdf"]["signature_count"], 1)
        self.assertIn("PDF_SIGNATURE", {f["code"] for f in result["structure"]["findings"]})
        self.assertTrue(raw.startswith(b"%PDF-"))

    def test_report_contains_pdf_sections(self):
        path = os.path.join(self.d, "active.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(
            _action("/JavaScript", JS=TextStringObject("app.alert(1)")))
        with open(path, "wb") as fh:
            writer.write(fh)
        result = Analyzer().analyze_file(path)
        html = render_html(result)
        self.assertIn("Структурный анализ PDF", html)
        self.assertIn("JavaScript", html)
        row = csv_row(result)
        self.assertEqual(row["format"], "PDF")
        self.assertEqual(row["pdf_javascript"], 1)
        out = os.path.join(self.d, "reports")
        written = write_reports([result], out)
        self.assertTrue(os.path.exists(written["json"][0]))
        self.assertTrue(os.path.exists(os.path.join(out, "summary.csv")))
        with open(os.path.join(out, "summary.csv"), encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh, delimiter=";"))
        self.assertEqual(rows[0]["format"], "PDF")


class PdfSanitizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _active_pdf(self):
        path = os.path.join(self.d, "active.pdf")
        writer = PdfWriter()
        page = writer.add_blank_page(width=200, height=200)
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(
            _action("/JavaScript", JS=TextStringObject("app.alert(1)")))
        _add_attachment(writer, "payload.exe", b"MZ\x90\x00evil")
        _add_hidden_text(page, writer)
        with open(path, "wb") as fh:
            writer.write(fh)
        return path

    def test_sanitize_removes_active_content(self):
        src = self._active_pdf()
        dst = os.path.join(self.d, "clean.pdf")
        report = sanitize_pdf(src, dst)
        self.assertTrue(os.path.exists(dst))
        self.assertGreater(report["removed_hidden_chars"], 0)
        self.assertEqual(report["verification"]["residual_findings"], [])
        result = analyze_pdf(dst)
        self.assertEqual(result["verdict"], "CLEAN")
        self.assertFalse(result["pdf"]["javascript"])
        self.assertEqual(result["pdf"]["attachments"], 0)
        self.assertEqual(result["hidden_text"].get("hidden_chars", 0), 0)

    def test_sanitize_image_reencoding(self):
        src = os.path.join(self.d, "image.pdf")
        _image_pdf(src, with_payload=True)
        dst = os.path.join(self.d, "image_clean.pdf")
        report = sanitize_pdf(src, dst)
        self.assertEqual(report["images_reencoded"], 1)
        self.assertIsNotNone(report["image_psnr_min"])
        result = analyze_pdf(dst)
        self.assertEqual(result["pdf"]["images"], 1)
        self.assertNotIn("PDF_IMAGE_STEGO", {f["code"] for f in result["structure"]["findings"]})

    def test_sanitize_encrypted_pdf(self):
        src = os.path.join(self.d, "enc.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer.encrypt("secret")
        with open(src, "wb") as fh:
            writer.write(fh)
        dst = os.path.join(self.d, "enc_clean.pdf")
        with self.assertRaises(ValueError):
            sanitize_pdf(src, dst)
        with self.assertRaises(ValueError):
            sanitize_pdf(src, dst, password="wrong")
        report = sanitize_pdf(src, dst, password="secret")
        self.assertTrue(report["encrypted_input"])
        self.assertEqual(analyze_pdf(dst)["verdict"], "CLEAN")

    def test_sanitize_removes_trailing_and_orphans(self):
        src = os.path.join(self.d, "trailing.pdf")
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        with open(src, "wb") as fh:
            writer.write(fh)
        with open(src, "ab") as fh:
            fh.write(b"\nPK\x03\x04" + b"x" * 64)
        dst = os.path.join(self.d, "trailing_clean.pdf")
        report = sanitize_pdf(src, dst)
        result = analyze_pdf(dst)
        self.assertEqual(result["pdf"]["trailing_bytes"], 0)
        codes = {f["code"] for f in result["structure"]["findings"]}
        self.assertNotIn("PDF_TRAILING_DATA", codes)
        self.assertNotIn("PDF_UNREFERENCED_OBJECTS", codes)
        self.assertGreaterEqual(report["removed"].get("unreferenced_objects", 0), 0)


class PdfCompatibilityTest(unittest.TestCase):
    def test_jpeg_pixel_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "image.jpg")
            Image.new("RGB", (96, 96), (80, 120, 160)).save(path)
            result = Analyzer().analyze_file(path)
            self.assertEqual(result["format"], "JPG")
            self.assertIn("image", result)
            self.assertIn(result["verdict"], ("CLEAN", "SUSPICIOUS", "STEGO_DETECTED"))

    def test_folder_collection_includes_pdf_and_images(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("a.png", "b.pdf", "c.jpg", "d.txt"):
                open(os.path.join(d, name), "wb").close()
            names = {os.path.basename(p) for p in collect_files([d])}
            self.assertEqual(names, {"a.png", "b.pdf", "c.jpg"})

    def test_pdf_signature_detected_by_content_with_other_extension(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "document.bin")
            writer = PdfWriter()
            writer.add_blank_page(width=100, height=100)
            with open(path, "wb") as fh:
                writer.write(fh)
            result = Analyzer().analyze_file(path)
            self.assertEqual(result["format"], "PDF")
            self.assertEqual(result["verdict"], "CLEAN")


if __name__ == "__main__":
    unittest.main()
