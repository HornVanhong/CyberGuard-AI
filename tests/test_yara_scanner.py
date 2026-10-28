"""Tests for YARA scanner and rule evaluation."""

import pytest
from pathlib import Path
from app.scanners.yara_scanner import YaraScanner, YaraStatus


@pytest.mark.asyncio
async def test_yara_compile_and_match(temp_dir):
    scanner = YaraScanner(rules_dir=Path("rules"))
    loaded = scanner.load_rules()
    assert loaded is True
    assert scanner.rules_loaded_count > 0

    # Test file containing synthetic benign fixture token
    test_file = temp_dir / "test_fixture.txt"
    test_file.write_text("Prefix text CYBERGUARD_AI_BENIGN_TEST_PAYLOAD suffix text")

    result = await scanner.scan_file(test_file)
    assert result.status == YaraStatus.MATCHES_FOUND
    assert len(result.matches) >= 1
    match_names = [m.rule for m in result.matches]
    assert "Synthetic_Harmless_Test_Rule" in match_names


@pytest.mark.asyncio
async def test_yara_clean_file(temp_dir):
    scanner = YaraScanner(rules_dir=Path("rules"))
    scanner.load_rules()

    clean_file = temp_dir / "clean.txt"
    clean_file.write_text("Hello, this is a normal benign text file with no suspicious tokens.")

    result = await scanner.scan_file(clean_file)
    assert result.status == YaraStatus.CLEAN
    assert len(result.matches) == 0


@pytest.mark.asyncio
async def test_yara_disabled(temp_dir):
    scanner = YaraScanner(rules_dir=Path("rules"), enabled=False)
    test_file = temp_dir / "any.txt"
    test_file.write_text("any")

    result = await scanner.scan_file(test_file)
    assert result.status == YaraStatus.UNAVAILABLE


def test_yara_invalid_dir(temp_dir):
    scanner = YaraScanner(rules_dir=temp_dir / "non_existent_rules")
    assert scanner.load_rules() is False
