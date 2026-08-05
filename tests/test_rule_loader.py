from pathlib import Path

from app.rule_loader import (
    load_all_rules,
)


def test_default_rules_load_successfully() -> None:
    rules = load_all_rules()

    assert set(rules.keys()) == {
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
    }

    assert rules["AUTH-001"]["enabled"] is True
    assert rules["AUTH-001"]["threshold"] == 5

    assert rules["AUTH-002"]["severity"] == (
        "critical"
    )

    assert (
        rules["AUTH-003"]["account_threshold"]
        == 5
    )


def test_disabled_rules_are_skipped(
    tmp_path: Path,
) -> None:
    enabled_rule = """
id: TEST-001
name: Enabled Test Rule
enabled: true
severity: low
mitre:
  tactic: Test
  technique_id: T0001
  technique_name: Test Technique
"""

    disabled_rule = """
id: TEST-002
name: Disabled Test Rule
enabled: false
severity: low
mitre:
  tactic: Test
  technique_id: T0002
  technique_name: Disabled Technique
"""

    (
        tmp_path
        / "enabled_rule.yml"
    ).write_text(
        enabled_rule,
        encoding="utf-8",
    )

    (
        tmp_path
        / "disabled_rule.yml"
    ).write_text(
        disabled_rule,
        encoding="utf-8",
    )

    rules = load_all_rules(tmp_path)

    assert "TEST-001" in rules
    assert "TEST-002" not in rules
    assert len(rules) == 1