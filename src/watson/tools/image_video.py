"""Image & Video verification tool — reverse image search, EXIF, verification."""

from __future__ import annotations

import re
from urllib.parse import quote

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client, BaseHTTPClient
from ..utils.helpers import is_url


class ImageVideoTool(OSINTTool):
    """Reverse image search, EXIF extraction, and visual verification."""

    category = FindingSource.IMAGE_VIDEO
    name = "image-video"
    description = "Reverse image search (Google, Yandex, TinEye), EXIF metadata, verification"
    free_tier_available = True
    rate_limit_rps = 0.5

    GOOGLE_IMAGE_SEARCH = "https://lens.google.com/uploadbyurl?url={image_url}"
    YANDEX_IMAGE_SEARCH = "https://yandex.com/images/search?rpt=imageview&url={image_url}"
    TINEYE_SEARCH = "https://tineye.com/search?url={image_url}"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Extract image URLs from the query
        image_urls = self._extract_image_urls(query)

        if image_urls:
            for url in image_urls[:3]:  # Max 3 images
                findings.append(
                    self._make_finding(
                        title=f"🖼 Reverse image search ready: {url[:60]}",
                        description=(
                            f"Submit this image to reverse image search engines:\n"
                            f"- [Google Lens]({self.GOOGLE_IMAGE_SEARCH.format(image_url=quote(url))})\n"
                            f"- [Yandex]({self.YANDEX_IMAGE_SEARCH.format(image_url=quote(url))})\n"
                            f"- [TinEye]({self.TINEYE_SEARCH.format(image_url=quote(url))})\n\n"
                            f"Tip: Yandex is often best for faces and Eastern European content. "
                            f"Google Lens excels at objects and locations."
                        ),
                        evidence=[
                            self.GOOGLE_IMAGE_SEARCH.format(image_url=quote(url)),
                            self.YANDEX_IMAGE_SEARCH.format(image_url=quote(url)),
                            self.TINEYE_SEARCH.format(image_url=quote(url)),
                        ],
                        confidence=0.7,
                        image_url=url,
                    )
                )

        # Check for image/video file references even without full URLs
        if not image_urls:
            image_refs = self._find_image_references(query)
            if image_refs:
                findings.append(
                    self._make_finding(
                        title="📸 Image/video reference detected",
                        description=(
                            f"Found references to: {', '.join(image_refs[:5])}. "
                            "To run reverse image search, provide the full image URL. "
                            "Use `watson investigate \"[image_url]\"` with the direct URL."
                        ),
                        confidence=0.4,
                        references=image_refs,
                    )
                )

        return findings

    def _extract_image_urls(self, text: str) -> list[str]:
        """Extract image URLs from text."""
        urls = re.findall(
            r"https?://[^\s]+?\.(?:jpg|jpeg|png|gif|webp|bmp|svg)(?:\?[^\s]*)?",
            text,
            re.IGNORECASE,
        )
        # Also catch URLs that might be images without extensions
        if not urls:
            for word in text.split():
                if word.startswith("http") and any(
                    kw in word.lower() for kw in ["image", "photo", "img", "pic"]
                ):
                    urls.append(word.strip(".,;:!?"))
        return urls

    def _find_image_references(self, text: str) -> list[str]:
        """Find references to images/videos in text."""
        keywords = ["photo", "image", "video", "screenshot", "picture", "footage"]
        refs = []
        for kw in keywords:
            idx = text.lower().find(kw)
            if idx >= 0:
                # Get surrounding context
                start = max(0, idx - 20)
                end = min(len(text), idx + len(kw) + 30)
                refs.append(text[start:end].strip())
        return refs


# Register
image_video_tool = ImageVideoTool()
registry.register(image_video_tool)
