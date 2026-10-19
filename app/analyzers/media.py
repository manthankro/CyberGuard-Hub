from PIL import Image, UnidentifiedImageError
import io

def inspect_media(data: bytes, filename: str, content_type: str) -> dict:
    result={"filename":filename,"content_type":content_type,"size_bytes":len(data),"signals":[],"assessment":"inconclusive","disclaimer":"This prototype does not detect deepfakes and cannot determine whether media is authentic or AI-generated. Metadata and image properties are weak, editable clues only."}
    if content_type.startswith("image/"):
        try:
            image=Image.open(io.BytesIO(data))
            result.update({"format":image.format,"dimensions":{"width":image.width,"height":image.height},"metadata_fields":sorted(str(k)[:80] for k in image.getexif().keys())[:30]})
            if not image.getexif(): result["signals"].append("No EXIF metadata found (metadata is often stripped during normal sharing)")
            if image.width*image.height > 40_000_000: result["signals"].append("Large image dimensions; review processing limits")
        except (UnidentifiedImageError, OSError): result["signals"].append("Image could not be decoded as a supported image")
    else:
        result["signals"].append("File stored for inspection; no audio/video authenticity model is configured")
    return result
