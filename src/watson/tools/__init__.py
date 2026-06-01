"""OSINT tool modules — each implements the OSINTTool base class.

To add a new tool:
1. Create a new .py file in this directory
2. Inherit from `base.OSINTTool`
3. Import and register it here
"""

from . import satellite
from . import geolocation
from . import image_video
from . import social_media
from . import people
from . import websites
from . import corporate
from . import conflict

__all__ = [
    "satellite",
    "geolocation",
    "image_video",
    "social_media",
    "people",
    "websites",
    "corporate",
    "conflict",
]
