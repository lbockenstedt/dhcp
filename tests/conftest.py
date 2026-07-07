"""pytest path bootstrap for the dhcp spoke test suite.

``dhcp_spoke`` imports its sibling ``kea_manager`` as a bare name, so
``dhcp/src`` must be on ``sys.path``. It also inherits ``BaseSpoke`` from the LM
``core`` repo (``core.src.base_spoke`` / bare ``base_spoke``), so core's parent
dir must be on the path too — in dev that's the sibling ``lm`` repo
(``vscode/lm/core``), in prod ``/opt/lm/core`` alongside the dhcp checkout.
Mirrors the cs lm-spoke conftest.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("LM_DEP_GUARD_DISABLE", "1")

HERE = Path(__file__).resolve().parent        # dhcp/tests
DHCP_REPO = HERE.parent                        # dhcp
SRC = DHCP_REPO / "src"
for p in (str(SRC), str(DHCP_REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

VSROOT = DHCP_REPO.parent                      # .../vscode (dev)
for cand in (VSROOT / "lm" / "core", VSROOT / "core", DHCP_REPO / "core"):
    if (cand / "src" / "base_spoke.py").is_file():
        core_parent = str(cand.parent)
        core_src = str(cand / "src")
        for cp in (core_parent, core_src):
            if cp not in sys.path:
                sys.path.insert(0, cp)
        break