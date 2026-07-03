"""Blockchain investigation tool — Ethereum + Bitcoin, no API key needed.

Uses Blockscout (open-source Etherscan alternative) for Ethereum and
Blockchain.info for Bitcoin. Both are free with generous rate limits.

Capabilities:
  - Wallet balance lookup (ETH/BTC)
  - Transaction history (recent 50)
  - ENS domain resolution
  - Token holdings (ERC-20)
  - Exchange attribution (known exchange addresses)
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSeverity, FindingSource
from ..utils.http import get_client

logger = logging.getLogger("watson.crypto")

# Known exchange addresses (for attribution)
KNOWN_EXCHANGES = {
    "0x28C6c06298d514Db089934071355E5743bf21d60": "Binance",
    "0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE": "Binance",
    "0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8": "Binance",
    "0xF977814e90dA44bFA03b6295A0616a89744199C5": "Binance",
    "0x5E3346444010135322268a4630d2ed5F8D09446C": "Binance",
    "0xA7EFAe728D2936e78BDA97dc267687568dD593f3": "Binance",
    "0xDFd5293D8e347dFe59E90eFd55429C5D26259a91": "Binance",
    "0x56Eddb7aa87536c09CCc2793473599fD21A8b17F": "Binance",
    "0xD688AEA8f7dC9088D009e8eFdCE6d0877fC8DF4c": "Coinbase",
    "0x71660c4005BA85c37c855d479861432c0Fb787b17": "Coinbase",
    "0x503828976D22510aad0201ac7EC2421ae51c927A": "Coinbase",
    "0xddfAbCdc4D8FfC6d5beaf154f18B778f892A074a": "Kraken",
    "0x267be1C1D684F78cb4F6c176783921476d2b7da9": "Kraken",
    "0x22c264eD08d9E47A28E380F3a93e5990cC42f4F0": "FTX",
    "0xC098B2a3Aa256D2140208C3de674f736a6746528": "Bitfinex",
    "0x1151314c646Ce4E0eFD76d1aF4760aE66a9Fe30F": "Bitfinex",
    "0x36A85757645E8e8aeA06c2D52A2449c4b226BeC4": "KuCoin",
    "0x689c56AEf474Df92D44A1B70850f808488F9769C": "KuCoin",
    "0x8894E0a0c962CB723c1976a4421c95949bE2D4E3": "Interpol Seized",
    "0x8576aCC5C05D6Ce88f4e49bf65BdF0C62F91353C": "DEA Seized",
    "0x9F4cda45B4D3f1f6cB4aB9D5dA2A6c6c4b9c5b3a": "USDT Tether Treasury",
}

# ERC-20 token contracts to check
TOKEN_CONTRACTS = {
    "0xdAC17F958D2ee523a2206206994597C13D831ec7": "USDT",
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": "USDC",
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "WETH",
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599": "WBTC",
    "0x514910771AF9Ca656af840dff83E8264EcF986CA": "LINK",
}


class BlockchainTool(OSINTTool):
    """Investigate cryptocurrency wallets — Ethereum + Bitcoin, no API key needed."""

    category = FindingSource.CORPORATE
    name = "blockchain"
    description = "Ethereum (Blockscout) + Bitcoin (Blockchain.info) wallet investigation — balance, TXs, ENS, tokens"
    free_tier_available = True
    rate_limit_rps = 2.0

    BLOCKSCOUT_API = "https://eth.blockscout.com/api/v2"
    BLOCKCHAIN_INFO = "https://blockchain.info/rawaddr"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []
        client = get_client(rate_limit=self.rate_limit_rps)

        # Extract wallet address from query
        address = self._extract_address(query)
        if not address:
            return findings

        # Route by chain
        if address.startswith("0x") and len(address) == 42:
            # Ethereum
            findings.extend(await self._investigate_ethereum(client, address))
        elif len(address) in (34, 42) and address[0] in ("1", "3", "b", "B"):
            # Bitcoin
            findings.extend(await self._investigate_bitcoin(client, address))
        else:
            # Unknown format — try Ethereum first
            findings.extend(await self._investigate_ethereum(client, address))

        return findings

    def _extract_address(self, query: str) -> str | None:
        """Extract a crypto wallet address from query text."""
        # Ethereum (0x + 40 hex chars)
        match = re.search(r'(0x[a-fA-F0-9]{40})', query)
        if match:
            return match.group(1)

        # Bitcoin (legacy P2PKH: 1..., P2SH: 3..., Bech32: bc1...)
        match = re.search(r'(\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b)', query)
        if match:
            return match.group(1)

        # If the entire query looks like an address
        query = query.strip()
        if re.match(r'^0x[a-fA-F0-9]{40}$', query):
            return query
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', query):
            return query
        if re.match(r'^bc1[a-z0-9]{39,59}$', query, re.I):
            return query

        return None

    # ── Ethereum ──────────────────────────────────────────────

    async def _investigate_ethereum(self, client, address: str) -> list[Finding]:
        findings: list[Finding] = []
        addr_lower = address.lower()

        # 1. Address info (balance, ENS, TX count)
        try:
            data = await client.get_json(f"{self.BLOCKSCOUT_API}/addresses/{address}")
            balance_wei = int(data.get("coin_balance", "0"))
            balance_eth = balance_wei / 1e18
            tx_count = data.get("transactions_count", 0)
            ens = data.get("ens_domain_name")
            is_contract = data.get("is_contract", False)

            desc_parts = [
                f"**Balance:** {balance_eth:.4f} ETH",
                f"**Total transactions:** {tx_count:,}",
            ]
            if ens:
                desc_parts.append(f"**ENS domain:** {ens}")
            if is_contract:
                desc_parts.append("**Type:** Smart contract")
            else:
                desc_parts.append("**Type:** Externally owned account (EOA)")

            # Check if known exchange
            exchange = KNOWN_EXCHANGES.get(address)
            if exchange:
                desc_parts.append(f"**⚠️ Known exchange:** {exchange}")

            # Token balances
            token_balances = await self._get_token_balances(client, address)
            if token_balances:
                desc_parts.append("\n**Token holdings:**")
                for symbol, balance in token_balances.items():
                    desc_parts.append(f"  - {balance} {symbol}")

            findings.append(self._make_finding(
                title=f"💎 Ethereum Wallet: {balance_eth:.2f} ETH — {address[:12]}...",
                description="\n".join(desc_parts),
                evidence=[f"https://eth.blockscout.com/address/{address}"],
                confidence=0.95,
                severity=FindingSeverity.HIGH if balance_eth > 1 else FindingSeverity.INFO,
                address=address,
                balance_eth=balance_eth,
                tx_count=tx_count,
                ens_domain=ens,
                is_exchange=bool(exchange),
                exchange_name=exchange,
            ))
        except Exception as e:
            logger.warning("blockscout_address_failed: %s", e)
            findings.append(self._make_finding(
                title=f"⚠️ Blockscout lookup failed for {address[:12]}...",
                description=f"Could not retrieve address data: {str(e)[:200]}. View manually: https://etherscan.io/address/{address}",
                evidence=[f"https://etherscan.io/address/{address}"],
                confidence=0.2,
                severity=FindingSeverity.LOW,
            ))

        # 2. Recent transactions + counterparty analysis
        try:
            tx_data = await client.get_json(
                f"{self.BLOCKSCOUT_API}/addresses/{address}/transactions",
                params={"filter": "from"},
            )
            txs = tx_data.get("items", [])

            if txs:
                tx_lines = []
                counterparties = {}  # addr -> count
                contracts_found = set()
                exchanges_found = set()

                for tx in txs[:10]:
                    value_eth = int(tx.get("value", "0")) / 1e18
                    to_addr = tx.get("to", {}).get("hash", "?")
                    to_short = to_addr[:14]
                    tx_hash = tx.get("hash", "?")[:20]
                    timestamp = tx.get("timestamp", "?")[:10]

                    # Track counterparties for analysis
                    counterparties[to_addr] = counterparties.get(to_addr, 0) + 1

                    # Check if destination is a known exchange
                    to_full = tx.get("to", {}).get("hash", "")
                    ex = KNOWN_EXCHANGES.get(to_full, KNOWN_EXCHANGES.get(to_full.lower(), ""))
                    if ex:
                        exchanges_found.add(ex)

                    # Identify token contracts
                    contract_id = TOKEN_CONTRACTS.get(to_full)
                    if contract_id:
                        contracts_found.add(contract_id)

                    # Build marker — prioritize contract ID over exchange
                    if contract_id:
                        marker = f" [ERC-20: {contract_id}]"
                    elif ex:
                        marker = f" → {ex}"
                    else:
                        marker = ""

                    tx_lines.append(
                        f"  - [{timestamp}] {value_eth:.4f} ETH → {to_short}...{marker}"
                    )

                findings.append(self._make_finding(
                    title=f"💸 Recent ETH transactions: {len(txs)} from {address[:12]}...",
                    description="\n".join(tx_lines),
                    evidence=[f"https://eth.blockscout.com/address/{address}/transactions"],
                    confidence=0.9,
                    severity=FindingSeverity.MEDIUM,
                    address=address,
                    tx_count=len(txs),
                ))

                # Counterparty analysis: summary of who this wallet interacts with
                unique_counterparties = len(counterparties)
                summary_parts = []
                if contracts_found:
                    summary_parts.append(f"**Token contracts:** {', '.join(sorted(contracts_found))} (0 ETH transfers are ERC-20 token interactions, not value transfers)")
                if exchanges_found:
                    summary_parts.append(f"**Exchanges:** {', '.join(sorted(exchanges_found))}")
                summary_parts.append(f"**Unique counterparties:** {unique_counterparties}")
                if unique_counterparties <= 5:
                    # Show all counterparties for low-activity wallets
                    for addr, count in sorted(counterparties.items(), key=lambda x: -x[1]):
                        label = KNOWN_EXCHANGES.get(addr, TOKEN_CONTRACTS.get(addr, ""))
                        label_str = f" [{label}]" if label else ""
                        summary_parts.append(f"  - {addr}{label_str} ({count} txn{'s' if count > 1 else ''})")

                findings.append(self._make_finding(
                    title=f"🔍 Counterparty analysis: {unique_counterparties} unique wallets",
                    description="\n".join(summary_parts),
                    evidence=[f"https://eth.blockscout.com/address/{address}/transactions"],
                    confidence=0.85,
                    severity=FindingSeverity.MEDIUM,
                    address=address,
                    counterparty_count=unique_counterparties,
                ))
        except Exception as e:
            logger.warning("blockscout_txs_failed: %s", e)

        return findings

    async def _get_token_balances(self, client, address: str) -> dict[str, float]:
        """Check ERC-20 token balances via Blockscout."""
        balances: dict[str, float] = {}
        try:
            data = await client.get_json(
                f"{self.BLOCKSCOUT_API}/addresses/{address}/token-balances"
            )
            for token in data if isinstance(data, list) else []:
                symbol = token.get("token", {}).get("symbol", "?")
                decimals = int(token.get("token", {}).get("decimals", 18))
                raw_balance = int(token.get("value", "0"))
                if raw_balance > 0:
                    balance = raw_balance / (10 ** decimals)
                    if balance > 0.01:  # Skip dust
                        balances[symbol] = round(balance, 4)
        except Exception:
            pass
        return balances

    # ── Bitcoin ──────────────────────────────────────────────

    async def _investigate_bitcoin(self, client, address: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = await client.get_json(f"{self.BLOCKCHAIN_INFO}/{address}?limit=10")

            balance_btc = data.get("final_balance", 0) / 1e8
            total_received = data.get("total_received", 0) / 1e8
            total_sent = data.get("total_sent", 0) / 1e8
            n_tx = data.get("n_tx", 0)

            desc_parts = [
                f"**Balance:** {balance_btc:.4f} BTC",
                f"**Total received:** {total_received:.4f} BTC",
                f"**Total sent:** {total_sent:.4f} BTC",
                f"**Transaction count:** {n_tx:,}",
            ]

            findings.append(self._make_finding(
                title=f"₿ Bitcoin Wallet: {balance_btc:.4f} BTC — {address[:12]}...",
                description="\n".join(desc_parts),
                evidence=[f"https://blockchain.info/address/{address}"],
                confidence=0.95,
                severity=FindingSeverity.HIGH if balance_btc > 0.1 else FindingSeverity.INFO,
                address=address,
                balance_btc=balance_btc,
                tx_count=n_tx,
            ))

            # Recent transactions
            txs = data.get("txs", [])
            if txs:
                tx_lines = []
                for tx in txs[:10]:
                    import time
                    ts = tx.get("time", 0)
                    date_str = time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "?"

                    # Calculate net amount
                    total_in = sum(o.get("value", 0) for o in tx.get("out", []) if o.get("addr") == address)
                    total_out = sum(i.get("value", 0) for i in tx.get("inputs", []) if i.get("prev_out", {}).get("addr") == address)
                    net = (total_in - total_out) / 1e8

                    tx_hash = tx.get("hash", "?")[:20]
                    direction = "received" if net > 0 else "sent"
                    tx_lines.append(f"  - [{date_str}] {abs(net):.4f} BTC {direction} (TX: {tx_hash}...)")

                findings.append(self._make_finding(
                    title=f"💸 Recent BTC transactions: {len(txs)} for {address[:12]}...",
                    description="\n".join(tx_lines),
                    evidence=[f"https://blockchain.info/address/{address}"],
                    confidence=0.9,
                    severity=FindingSeverity.MEDIUM,
                    address=address,
                ))

        except Exception as e:
            logger.warning("blockchain_info_failed: %s", e)
            findings.append(self._make_finding(
                title=f"⚠️ Blockchain.info lookup failed for {address[:12]}...",
                description=f"Could not retrieve address data: {str(e)[:200]}. View manually: https://blockchain.info/address/{address}",
                evidence=[f"https://blockchain.info/address/{address}"],
                confidence=0.2,
                severity=FindingSeverity.LOW,
            ))

        return findings


# Register
blockchain_tool = BlockchainTool()
registry.register(blockchain_tool)
