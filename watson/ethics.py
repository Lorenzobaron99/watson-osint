"""Re-export from src.watson.ethics — the Sidney Ledger.

The real implementation lives in src/watson/ethics.py.
This module bridges the import path so watson.* imports work.
"""

from src.watson.ethics import (
    SidneyLedger,
    apply_editorial_checks,
    get_ledger,
    BELLINGCAT_DATA_ETHICS_APPENDIX,
    EditorialFramework,
    generate_compliance_header,
)

__all__ = [
    "SidneyLedger", "apply_editorial_checks", "get_ledger",
    "BELLINGCAT_DATA_ETHICS_APPENDIX", "EditorialFramework",
    "generate_compliance_header",
]
