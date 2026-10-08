"""Single source of truth for "which OS am I on" — every module that
needs to branch between Linux and Windows imports IS_WINDOWS from here
rather than calling platform.system() itself, so a grep for
"platform.system" finds exactly one place to look.
"""
from __future__ import annotations

import platform

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
