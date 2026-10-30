"""CyberGuard AI - YARA Pattern Matching Scanner.

Compiles and evaluates modular YARA rules against uploaded files.
Extracts structured rule metadata, severity rankings, and match context.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.utils.logger import logger

# Try importing yara-python
try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except ImportError:
    yara = None
    _YARA_AVAILABLE = False


class YaraStatus(str, Enum):
    """Execution status of the YARA scanner."""

    CLEAN = "CLEAN"
    MATCHES_FOUND = "MATCHES_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


@dataclass
class YaraMatch:
    """Represents an individual YARA rule match."""

    rule: str
    namespace: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings_matched: List[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """Normalized severity level: critical, high, medium, low."""
        return str(self.meta.get("severity", "medium")).lower()

    @property
    def description(self) -> str:
        return str(self.meta.get("description", self.rule))


@dataclass
class YaraResult:
    """Outcome of running YARA rules across a file."""

    status: YaraStatus
    matches: List[YaraMatch] = field(default_factory=list)
    rules_loaded_count: int = 0
    error_message: Optional[str] = None

    @property
    def is_match(self) -> bool:
        return len(self.matches) > 0


class YaraScanner:
    """Manages compilation and evaluation of YARA rules."""

    def __init__(
        self,
        rules_dir: Path | str = "rules",
        timeout: float = 15.0,
        enabled: bool = True,
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.timeout = timeout
        self.enabled = enabled
        self._compiled_rules: Optional[Any] = None
        self._rules_loaded_count: int = 0
        self._compile_lock = asyncio.Lock()

    @property
    def is_available(self) -> bool:
        return _YARA_AVAILABLE and self.enabled

    @property
    def rules_loaded_count(self) -> int:
        return self._rules_loaded_count

    def load_rules(self) -> bool:
        """Loads and compiles all .yar / .yara files in rules_dir."""
        if not self.is_available:
            logger.warning("YARA scanner is disabled or yara-python is not installed.")
            return False

        if not self.rules_dir.is_dir():
            logger.warning("YARA rules directory does not exist: %s", self.rules_dir)
            return False

        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not rule_files:
            logger.warning("No .yar files found in %s", self.rules_dir)
            return False

        file_map = {f"ns_{idx}_{f.stem}": str(f.resolve()) for idx, f in enumerate(rule_files)}
        try:
            self._compiled_rules = yara.compile(filepaths=file_map)
            self._rules_loaded_count = len(rule_files)
            logger.info("Compiled %d YARA rule files from %s", len(rule_files), self.rules_dir)
            return True
        except Exception as e:
            logger.error("Failed to compile YARA rules: %s", e)
            self._compiled_rules = None
            self._rules_loaded_count = 0
            return False

    async def scan_bytes(self, file_bytes: bytes, filename: str = "memory") -> YaraResult:
        """Asynchronously evaluates loaded YARA rules directly against in-memory bytes."""
        if not self.is_available:
            return YaraResult(
                status=YaraStatus.UNAVAILABLE,
                error_message="YARA scanner is not available on this host.",
            )

        if self._compiled_rules is None:
            async with self._compile_lock:
                if self._compiled_rules is None:
                    success = await asyncio.to_thread(self.load_rules)
                    if not success or self._compiled_rules is None:
                        return YaraResult(
                            status=YaraStatus.UNAVAILABLE,
                            error_message="No valid YARA rules compiled.",
                        )

        try:
            matches_raw = await asyncio.to_thread(
                self._compiled_rules.match,
                data=file_bytes,
                timeout=int(self.timeout),
            )

            matches: List[YaraMatch] = []
            for m in matches_raw:
                snippets = []
                for s in getattr(m, "strings", []):
                    try:
                        identifier = s[1]
                        val = s[2][:40].decode("latin-1", errors="replace")
                        snippets.append(f"{identifier}:{val}")
                    except Exception:
                        pass

                matches.append(
                    YaraMatch(
                        rule=m.rule,
                        namespace=m.namespace,
                        tags=list(m.tags),
                        meta=dict(m.meta),
                        strings_matched=snippets[:5],
                    )
                )

            status = YaraStatus.MATCHES_FOUND if matches else YaraStatus.CLEAN
            return YaraResult(
                status=status,
                matches=matches,
                rules_loaded_count=self._rules_loaded_count,
            )
        except yara.TimeoutError:
            safe_fn = filename.encode("ascii", errors="backslashreplace").decode("ascii")
            logger.error("YARA scan timed out for %s", safe_fn)
            return YaraResult(
                status=YaraStatus.FAILED,
                error_message="YARA scan timed out.",
                rules_loaded_count=self._rules_loaded_count,
            )
        except Exception as e:
            safe_fn = filename.encode("ascii", errors="backslashreplace").decode("ascii")
            logger.error("YARA scan error for %s: %s", safe_fn, e)
            return YaraResult(
                status=YaraStatus.FAILED,
                error_message=str(e),
                rules_loaded_count=self._rules_loaded_count,
            )

    async def scan_file(self, file_path: Path | str) -> YaraResult:
        """Asynchronously evaluates loaded YARA rules against a file."""
        if not self.is_available:
            return YaraResult(
                status=YaraStatus.UNAVAILABLE,
                error_message="YARA scanner is not available on this host.",
            )

        p = Path(file_path)
        # Attempt to read in-memory first to avoid native C path issues or OS locks
        try:
            with open(p, "rb") as f:
                data = f.read()
            return await self.scan_bytes(data, filename=p.name)
        except OSError:
            pass

        if not p.is_file():
            return YaraResult(
                status=YaraStatus.FAILED,
                error_message=f"File not found: {file_path}",
            )

        try:
            matches_raw = await asyncio.to_thread(
                self._compiled_rules.match,
                str(p.resolve()),
                timeout=int(self.timeout),
            )

            matches: List[YaraMatch] = []
            for m in matches_raw:
                # Extract string identifiers/samples (truncate for safety and brevity)
                snippets = []
                for s in getattr(m, "strings", []):
                    # s is tuple: (offset, identifier, data_bytes)
                    try:
                        identifier = s[1]
                        val = s[2][:40].decode("latin-1", errors="replace")
                        snippets.append(f"{identifier}:{val}")
                    except Exception:
                        pass

                matches.append(
                    YaraMatch(
                        rule=m.rule,
                        namespace=m.namespace,
                        tags=list(m.tags),
                        meta=dict(m.meta),
                        strings_matched=snippets[:5],
                    )
                )

            status = YaraStatus.MATCHES_FOUND if matches else YaraStatus.CLEAN
            return YaraResult(
                status=status,
                matches=matches,
                rules_loaded_count=self._rules_loaded_count,
            )

        except yara.TimeoutError:
            logger.error("YARA scan timed out for %s", p.name)
            return YaraResult(
                status=YaraStatus.FAILED,
                error_message="YARA scan timed out.",
                rules_loaded_count=self._rules_loaded_count,
            )
        except Exception as e:
            logger.error("YARA scan error: %s", e)
            return YaraResult(
                status=YaraStatus.FAILED,
                error_message=str(e),
                rules_loaded_count=self._rules_loaded_count,
            )
