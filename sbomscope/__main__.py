"""支持 python -m sbomscope 调用。"""

from __future__ import annotations

from .cli import main

raise SystemExit(main())
