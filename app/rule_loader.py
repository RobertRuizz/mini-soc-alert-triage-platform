from pathlib import Path
from typing import Any

import yaml


DEFAULT_RULES_DIRECTORY = (
    Path(__file__).resolve().parent.parent / "rules"
)


def load_rule(
    filename: str,
    rules_directory: str | Path = DEFAULT_RULES_DIRECTORY,
) -> dict[str, Any]:
    """Load and validate one YAML detection rule."""
    rule_path = Path(rules_directory) / filename

    with rule_path.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError(
            f"Rule file must contain a YAML dictionary: {filename}"
        )

    required_fields = {
        "id",
        "name",
        "enabled",
        "severity",
        "mitre",
    }

    missing_fields = required_fields - rule.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise ValueError(
            f"Rule {filename} is missing fields: {missing}"
        )

    return rule


def load_all_rules(
    rules_directory: str | Path = DEFAULT_RULES_DIRECTORY,
) -> dict[str, dict[str, Any]]:
    """Load every enabled YAML rule in the rules directory."""
    directory = Path(rules_directory)
    loaded_rules: dict[str, dict[str, Any]] = {}

    for rule_path in sorted(directory.glob("*.yml")):
        rule = load_rule(rule_path.name, directory)

        if rule.get("enabled", True):
            loaded_rules[rule["id"]] = rule

    return loaded_rules