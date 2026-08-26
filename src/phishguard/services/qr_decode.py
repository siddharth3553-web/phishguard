"""QR / quishing decode via OpenCV QRCodeDetector (no system zbar required)."""

from __future__ import annotations

from typing import Any

import numpy as np


def decode_qr_bytes(data: bytes) -> dict[str, Any]:
    """Decode QR payload from image bytes. Returns empty payload if undecodable."""
    try:
        import cv2
    except ImportError:
        return {"ok": False, "error": "opencv not installed", "payloads": []}

    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return {"ok": False, "error": "invalid_image", "payloads": []}

    detector = cv2.QRCodeDetector()
    # detectAndDecodeMulti if available
    payloads: list[str] = []
    try:
        ok, decoded, _, _ = detector.detectAndDecodeMulti(img)
        if ok and decoded is not None:
            for d in decoded:
                if d:
                    payloads.append(str(d))
    except Exception:
        val, _, _ = detector.detectAndDecode(img)
        if val:
            payloads.append(str(val))

    if not payloads:
        val, _, _ = detector.detectAndDecode(img)
        if val:
            payloads.append(str(val))

    return {"ok": bool(payloads), "payloads": payloads, "error": None if payloads else "no_qr_found"}
