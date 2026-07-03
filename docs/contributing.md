# Contributing to Watson

Watson is built for community contributions. Adding a new tool or improving an existing one should be straightforward.

## Adding a New Investigation Tool

### Step 1: Create your tool class

Create a new file in `src/watson/tools/` (e.g., `crypto.py`):

```python
from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource

class CryptoTool(OSINTTool):
    category = FindingSource.CORPORATE  # or propose a new category
    name = "crypto-tracker"
    description = "Track cryptocurrency transactions and wallet addresses"
    free_tier_available = True
    rate_limit_rps = 0.5

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings = []

        # Your investigation logic
        # Use self._make_finding() to create Finding objects
        # Use the shared HTTP client: from ..utils.http import get_client

        return findings

# Register the tool
crypto_tool = CryptoTool()
registry.register(crypto_tool)
```

### Step 2: Register it

Add your import to `src/watson/tools/__init__.py`:

```python
from . import crypto
```

### Step 3: Test it

```bash
pip install -e ".[dev]"
watson tools          # Your tool should appear
watson investigate "0x1234...abcd" --tools corporate
```

### Step 4: Submit a PR

Open a pull request with:
- Your tool module
- Updated `__init__.py`
- Any new dependencies in `pyproject.toml`
- A brief description of what the tool does

## Tool Guidelines

- **Use free APIs where possible.** Watson v0.1 is zero-config — users shouldn't need API keys
- **Handle failures gracefully.** Never crash the whole investigation if your tool fails
- **Provide evidence links.** Every finding should have URLs to source data
- **Set realistic confidence scores.** 0.95 = "confirmed from official source", 0.3 = "educated guess"
- **Rate limit responsibly.** Respect API limits with `rate_limit_rps`

## Adding a New Category

If your tool doesn't fit existing categories, open an issue to discuss adding a new `FindingSource` value.

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Code Style

We use `ruff` for linting:

```bash
ruff check src/
ruff format src/  # auto-format
```
