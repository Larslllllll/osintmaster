"""Non-biometric exact and perceptual image hashes."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError

from osintmaster.metadata.exif import analyze_metadata


def _bits(values: list[bool]) -> str:
    return f"{int(''.join('1' if value else '0' for value in values), 2):016x}"


def _average_hash(image: Image.Image) -> str:
    pixels = list(image.convert("L").resize((8, 8), Image.Resampling.LANCZOS).getdata())
    mean = sum(pixels) / 64
    return _bits([value >= mean for value in pixels])


def _difference_hash(image: Image.Image) -> str:
    pixels = list(image.convert("L").resize((9, 8), Image.Resampling.LANCZOS).getdata())
    return _bits(
        [
            pixels[row * 9 + column] > pixels[row * 9 + column + 1]
            for row in range(8)
            for column in range(8)
        ]
    )


def _perceptual_hash(image: Image.Image) -> str:
    pixels = list(image.convert("L").resize((32, 32), Image.Resampling.LANCZOS).getdata())
    coefficients = []
    for u in range(8):
        for v in range(8):
            value = sum(
                pixels[y * 32 + x]
                * math.cos((2 * x + 1) * u * math.pi / 64)
                * math.cos((2 * y + 1) * v * math.pi / 64)
                for y in range(32)
                for x in range(32)
            )
            coefficients.append(value)
    median = sorted(coefficients[1:])[len(coefficients[1:]) // 2]
    return _bits([value >= median for value in coefficients])


def analyze_image(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError("File does not exist")
    sha = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            sha.update(chunk)
    try:
        with Image.open(path) as image:
            image.load()
            return {
                "file": str(path),
                "sha256": sha.hexdigest(),
                "dimensions": list(image.size),
                "average_hash": _average_hash(image),
                "difference_hash": _difference_hash(image),
                "perceptual_hash": _perceptual_hash(image),
            }
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("Unsupported or unreadable image") from exc


def compare_images(left: Path, right: Path) -> dict[str, Any]:
    a, b = analyze_image(left), analyze_image(right)
    exact = a["sha256"] == b["sha256"]
    distance = (int(a["perceptual_hash"], 16) ^ int(b["perceptual_hash"], 16)).bit_count()
    similarity = round((1 - distance / 64) * 100, 1)
    assessment = (
        "Exact same file"
        if exact
        else "Visually similar; inspect manually"
        if similarity >= 85
        else "No strong visual similarity"
    )
    left_exif = analyze_metadata(left, use_exiftool=False)["exif"]
    right_exif = analyze_metadata(right, use_exiftool=False)["exif"]
    shared_tags = left_exif.keys() & right_exif.keys()
    matching_exif = sorted(key for key in shared_tags if left_exif[key] == right_exif[key])
    conflicting_exif = sorted(key for key in shared_tags if left_exif[key] != right_exif[key])
    return {
        "left": a,
        "right": b,
        "exact_sha256_match": exact,
        "perceptual_similarity_percent": similarity,
        "assessment": assessment,
        "matching_exif_tags": matching_exif,
        "conflicting_exif_tags": conflicting_exif,
        "caveat": "Perceptual similarity is heuristic and does not identify people.",
    }
