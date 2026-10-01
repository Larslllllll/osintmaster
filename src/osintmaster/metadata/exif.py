"""Read local image metadata with optional ExifTool and a Pillow fallback."""

from __future__ import annotations

import json
import mimetypes
import shutil
import subprocess
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError


def _plain(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")[:500]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _pillow_metadata(path: Path) -> dict[str, Any]:
    try:
        with Image.open(path) as image:
            result: dict[str, Any] = {
                "format": image.format,
                "mime_type": Image.MIME.get(image.format or "", "application/octet-stream"),
                "dimensions": list(image.size),
                "exif": {},
                "xmp": {},
            }
            exif = image.getexif()
            for key, value in exif.items():
                name = ExifTags.TAGS.get(key, str(key))
                if name == "GPSInfo":
                    gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
                    result["exif"]["GPSInfo"] = {
                        str(ExifTags.GPSTAGS.get(gps_key, gps_key)): _plain(gps_value)
                        for gps_key, gps_value in gps.items()
                    }
                else:
                    result["exif"][str(name)] = _plain(value)
            for key, value in exif.get_ifd(ExifTags.IFD.Exif).items():
                name = str(ExifTags.TAGS.get(key, key))
                result["exif"][name] = _plain(value)
            selected_info = {
                str(key): _plain(value)
                for key, value in image.info.items()
                if str(key).lower()
                in {"comment", "description", "author", "artist", "software", "copyright"}
            }
            result["file_info"] = selected_info
            result["camera_make"] = result["exif"].get("Make")
            result["camera_model"] = result["exif"].get("Model")
            result["software"] = result["exif"].get("Software") or selected_info.get("software")
            result["author"] = result["exif"].get("Artist") or selected_info.get("author")
            result["comments"] = result["exif"].get("UserComment") or selected_info.get("comment")
            result["captured_timestamp"] = result["exif"].get("DateTimeOriginal")
            getxmp = getattr(image, "getxmp", None)
            if callable(getxmp):
                result["xmp"] = _plain(getxmp())
            return result
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("Unsupported or unreadable image") from exc


def analyze_metadata(
    path: Path, *, use_exiftool: bool = True, timeout: float = 10
) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError("File does not exist")
    stat = path.stat()
    result: dict[str, Any] = {
        "file": str(path),
        "size_bytes": stat.st_size,
        "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        "modified_timestamp": stat.st_mtime,
        "filesystem_ctime": stat.st_ctime,
        "gps_warning": "GPS metadata can reveal a precise location; no geolocation lookup was performed.",
    }
    result.update(_pillow_metadata(path))
    result["gps_present"] = "GPSInfo" in result["exif"]
    executable = shutil.which("exiftool") if use_exiftool else None
    if executable:
        try:
            completed = subprocess.run(
                [executable, "-j", "-G1", "-n", str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if completed.returncode == 0:
                parsed = json.loads(completed.stdout)
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    result["exiftool"] = parsed[0]
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            result["exiftool_error"] = "ExifTool failed; Pillow metadata is available"
    return result
