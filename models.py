from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class ApkBasicInfo():
    app_id: str = None
    version_code: int = None
    version_name: str = None
    apk_sha256: str = None

@dataclass
class ApkContentFileInfo():
    relative_path: str = None
    filename: str = None
    extension: str = None
    content_text: str = None
    content_blob: bytes = None
    content_mode: str = None
    file_sha256: str = None
