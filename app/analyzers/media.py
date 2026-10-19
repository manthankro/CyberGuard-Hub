import hashlib
import io
import warnings

from PIL import Image, UnidentifiedImageError

IMAGE_MIMES = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp", "GIF": "image/gif", "BMP": "image/bmp", "TIFF": "image/tiff"}
EXTENSION_FORMATS = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".webp": "WEBP", ".gif": "GIF", ".bmp": "BMP", ".tif": "TIFF", ".tiff": "TIFF"}


def inspect_media(data: bytes, filename: str, content_type: str) -> dict:
    """Inspect media bytes and metadata without claiming authenticity."""
    import os

    extension = os.path.splitext(filename.lower())[1]
    result = {
        "content_type": content_type,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "signals": [],
        "assessment": "inconclusive",
        "analysis_mode": "local file and metadata inspection",
        "recommendations": [
            "Verify who shared the file and where it came from using an independent channel.",
            "Compare with an original from a trusted source if authenticity matters.",
            "Treat metadata and visual clues as weak signals; they can be removed or edited.",
        ],
        "disclaimer": "This prototype does not detect deepfakes or determine authenticity. File properties and metadata cannot prove whether media is authentic or AI-generated.",
    }
    if content_type.startswith("image/"):
        try:
            # Verify once before reading dimensions/EXIF; Pillow guards against
            # malformed and decompression-bomb images.
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                image = Image.open(io.BytesIO(data))
                image.verify()
                image = Image.open(io.BytesIO(data))
                image_format = image.format or "unknown"
                exif = image.getexif()
                from PIL.ExifTags import TAGS
                metadata = sorted({str(TAGS.get(key, key))[:80] for key in exif.keys()})[:30]
                exif_details = {}
                for key, val in exif.items():
                    tag_name = str(TAGS.get(key, key))
                    if isinstance(val, (str, int, float, bool)):
                        exif_details[tag_name] = str(val)[:120]
                    elif isinstance(val, bytes):
                        try:
                            exif_details[tag_name] = val.decode("utf-8", errors="ignore")[:120]
                        except Exception:
                            pass

                result.update({
                    "format": image_format,
                    "dimensions": {"width": image.width, "height": image.height},
                    "metadata_fields": metadata,
                    "exif_details": exif_details,
                })
                actual_mime = IMAGE_MIMES.get(image_format)
                if actual_mime and content_type != actual_mime:
                    result["signals"].append({"rule_id": "MEDIA-MIME-MISMATCH", "category": "Declared media type differs from image signature", "evidence": f"Declared {content_type}; detected {actual_mime}", "why_it_matters": "A filename or HTTP content type can disagree with the file's actual format.", "severity": "low"})
                if extension and EXTENSION_FORMATS.get(extension) and EXTENSION_FORMATS[extension] != image_format:
                    result["signals"].append({"rule_id": "MEDIA-EXTENSION-MISMATCH", "category": "File extension differs from image format", "evidence": f"Extension {extension}; detected {image_format}", "why_it_matters": "Extensions can be renamed and should not be trusted as proof of file type.", "severity": "low"})
                if not exif:
                    result["signals"].append({"rule_id": "MEDIA-NO-EXIF", "category": "No EXIF metadata found", "evidence": "No EXIF fields present", "why_it_matters": "Metadata is commonly stripped during normal sharing, so absence is inconclusive.", "severity": "low"})
                else:
                    result["signals"].append({"rule_id": "MEDIA-EXIF", "category": "Image metadata present", "evidence": ", ".join(metadata) or f"{len(exif)} EXIF fields", "why_it_matters": "Metadata can provide context but is editable and does not verify when or how an image was created.", "severity": "low"})
                    software_tag = str(exif_details.get("Software", "") or exif_details.get("ProcessingSoftware", ""))
                    if any(sw in software_tag.lower() for sw in ["photoshop", "gimp", "canva", "midjourney", "stable diffusion", "dall-e", "picsart", "facetune", "lightroom"]):
                        result["signals"].append({"rule_id": "MEDIA-SOFTWARE-EDITED", "category": "Post-processing software indicated in metadata", "evidence": f"Software signature: {software_tag}", "why_it_matters": "The file's metadata explicitly references editing or generation software.", "severity": "medium"})
                if image.width * image.height > 40_000_000:
                    result["signals"].append({"rule_id": "MEDIA-LARGE-IMAGE", "category": "Large image dimensions", "evidence": f"{image.width} × {image.height}", "why_it_matters": "Very large images may require extra care when processing or sharing.", "severity": "low"})
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning):
            result["signals"].append({"rule_id": "MEDIA-IMAGE-INVALID", "category": "Image could not be safely decoded", "evidence": "Image signature or structure was not recognized", "why_it_matters": "The declared image type does not match a supported, readable image.", "severity": "medium"})
    elif content_type.startswith("video/") or content_type.startswith("audio/"):
        if not data:
            result["signals"].append({"rule_id": "MEDIA-EMPTY", "category": "No media bytes found", "evidence": "Empty file", "why_it_matters": "An empty file cannot be inspected.", "severity": "medium"})
        else:
            result["signals"].append({"rule_id": "MEDIA-AUDIO-VIDEO-METADATA-ONLY", "category": "Audio/video authenticity not analyzed", "evidence": "Local file hash and size recorded; no frame or waveform detector is configured", "why_it_matters": "This prototype does not inspect audio waveforms, video frames, or provenance credentials.", "severity": "low"})
    else:
        result["signals"].append({"rule_id": "MEDIA-UNSUPPORTED", "category": "Unsupported media type", "evidence": content_type, "why_it_matters": "Only common image, audio, and video uploads are accepted for inspection.", "severity": "medium"})
    return result
