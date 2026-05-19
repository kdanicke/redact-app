"""
extraction/extractors.py
Handles converting uploaded files of any type into plain text for redaction.

Supported formats
─────────────────
Structured binary  PDF, DOCX, XLSX/XLS (all sheets), PPTX
Everything else    Any file that can be decoded as UTF-8, UTF-8-BOM,
                   Latin-1, or CP-1252 — regardless of extension.
                   This covers all source-code, config, log, and env
                   files without maintaining a whitelist.
"""

import io
import os
import re
import zipfile


# ── Magic-byte signatures ──────────────────────────────────────────────────────
# Checked before falling back to text decode so we parse binary containers
# correctly even when the file extension is wrong or absent.
_MAGIC: dict[bytes, str] = {
    b"%PDF":        "pdf",
    b"PK\x03\x04":  "zip",   # DOCX / XLSX / PPTX are all ZIP-based
}


def _detect_magic(raw: bytes) -> str | None:
    for sig, fmt in _MAGIC.items():
        if raw[: len(sig)] == sig:
            return fmt
    return None


# ── Public entry point ─────────────────────────────────────────────────────────

def extract_text_from_file(file_storage) -> tuple[str | None, str | None]:
    """
    Extract plain text from any uploaded file.

    Parameters
    ----------
    file_storage : werkzeug.datastructures.FileStorage
        The uploaded file object from Flask's request.files.

    Returns
    -------
    (text, error_message)
        On success  → (str, None)
        On failure  → (None, str)
    """
    filename = (file_storage.filename or "unknown").lower()
    raw: bytes = file_storage.read()
    ext: str = os.path.splitext(filename)[1].lower()
    magic: str | None = _detect_magic(raw)

    # ── PDF ───────────────────────────────────────────────────────────────────
    if ext == ".pdf" or magic == "pdf":
        return _extract_pdf(raw)

    # ── ZIP-based Office formats (DOCX / XLSX / PPTX) ─────────────────────────
    if magic == "zip" or ext in (".docx", ".xlsx", ".xls", ".pptx", ".ppt"):
        # Validate it is actually a ZIP before attempting to parse
        try:
            zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile:
            pass  # not a real ZIP — fall through to text decode below
        else:
            if ext == ".docx":
                return _extract_docx(raw)
            if ext in (".xlsx", ".xls"):
                return _extract_xlsx(raw)
            if ext in (".pptx", ".ppt"):
                return _extract_pptx(raw)

    # ── Universal text fallback ────────────────────────────────────────────────
    # Covers every source-code, config, log, env, and other text-based format
    # regardless of extension (or no extension at all).
    for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            return raw.decode(encoding), None
        except (UnicodeDecodeError, ValueError):
            continue

    return None, (
        "Could not decode this file as text (tried UTF-8, Latin-1, CP1252). "
        "Binary files such as images, executables, and compiled code cannot be "
        "scanned. Try copying the text content and pasting it directly."
    )


# ── Format-specific extractors ─────────────────────────────────────────────────

def _extract_pdf(raw: bytes) -> tuple[str | None, str | None]:
    try:
        from pdfminer.high_level import extract_text as pdf_extract  # type: ignore
        text = pdf_extract(io.BytesIO(raw))
        return text, None
    except ImportError:
        return None, (
            "PDF support requires pdfminer.six.\n"
            "Install it with:  pip install pdfminer.six"
        )
    except Exception as exc:
        return None, f"PDF parse error: {exc}"


def _extract_docx(raw: bytes) -> tuple[str | None, str | None]:
    try:
        import xml.etree.ElementTree as ET

        NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        lines: list[str] = []

        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            with zf.open("word/document.xml") as f:
                tree = ET.parse(f)
            for para in tree.findall(".//w:p", NS):
                parts = [t.text or "" for t in para.findall(".//w:t", NS)]
                lines.append("".join(parts))

        return "\n".join(lines), None
    except Exception as exc:
        return None, f"DOCX parse error: {exc}"


def _extract_xlsx(raw: bytes) -> tuple[str | None, str | None]:
    """Extract text from all sheets in an XLSX/XLS workbook."""
    try:
        import xml.etree.ElementTree as ET

        NS = {"ns": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        lines: list[str] = []

        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            # Build shared-strings lookup
            shared: list[str] = []
            if "xl/sharedStrings.xml" in zf.namelist():
                with zf.open("xl/sharedStrings.xml") as f:
                    tree = ET.parse(f)
                for si in tree.findall(".//ns:si", NS):
                    shared.append(
                        "".join(t.text or "" for t in si.findall(".//ns:t", NS))
                    )

            # Read every sheet (not just the first)
            sheet_files = sorted(
                n for n in zf.namelist() if n.startswith("xl/worksheets/sheet")
            )
            for sheet_path in sheet_files:
                with zf.open(sheet_path) as f:
                    tree = ET.parse(f)
                for row in tree.findall(".//ns:row", NS):
                    cells: list[str] = []
                    for c in row.findall("ns:c", NS):
                        v_el = c.find("ns:v", NS)
                        val = ""
                        if v_el is not None and v_el.text:
                            if c.get("t") == "s":
                                idx = int(v_el.text)
                                val = shared[idx] if idx < len(shared) else ""
                            else:
                                val = v_el.text
                        cells.append(val)
                    lines.append("\t".join(cells))

        return "\n".join(lines), None
    except Exception as exc:
        return None, f"XLSX parse error: {exc}"


def _extract_pptx(raw: bytes) -> tuple[str | None, str | None]:
    """Extract all text runs from every slide in a PPTX presentation."""
    try:
        import xml.etree.ElementTree as ET

        DML_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
        lines: list[str] = []

        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            slide_files = sorted(
                n for n in zf.namelist()
                if re.match(r"ppt/slides/slide\d+\.xml", n)
            )
            for slide_path in slide_files:
                with zf.open(slide_path) as f:
                    tree = ET.parse(f)
                for t_el in tree.findall(f".//{{{DML_NS}}}t"):
                    if t_el.text:
                        lines.append(t_el.text)

        return "\n".join(lines), None
    except Exception as exc:
        return None, f"PPTX parse error: {exc}"
