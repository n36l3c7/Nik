"""The validation of Sigma rule texts (``POST /sigma/check``): what the editor and the import of rules ask.

A text may hold several YAML documents. For each document the answer is either a ``RuleInfo`` or errors with their
line in the whole text; ``supported`` says whether Nik can run the rule (and, when not, why in a sentence).

pySigma parses and validates; its errors carry no position, so the YAML node graph is kept next to the plain
values and each error is placed on the key it is about (the way an editor wants it). A rule without an ``id``
is an error: the id is what a detection, a correlation and a pack refer to.
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from sigma import exceptions as X
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.rule.detection import SigmaDetectionItem

from . import ENGINE_VERSION, correlate, documents, logsource
from .compile import Unsupported, compile_rule, refused

LEVELS = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
MAX_DOCUMENTS = 2000
# exception class -> the top-level key the error is about
KEY_OF = {
    X.SigmaTitleError: "title",
    X.SigmaIdentifierError: "id",
    X.SigmaLevelError: "level",
    X.SigmaStatusError: "status",
    X.SigmaDateError: "date",
    X.SigmaLogsourceError: "logsource",
    X.SigmaDetectionError: "detection",
    X.SigmaConditionError: "detection",
    X.SigmaTagError: "tags",
    X.SigmaAuthorError: "author",
    X.SigmaModifiedError: "modified",
    X.SigmaNameError: "name",
    X.SigmaReferencesError: "references",
    X.SigmaFieldsError: "fields",
    X.SigmaFalsePositivesError: "falsepositives",
    X.SigmaRelatedError: "related",
    X.SigmaScopeError: "scope",
    X.SigmaTaxonomyError: "taxonomy",
    X.SigmaDescriptionError: "description",
    X.SigmaLicenseError: "license",
    X.SigmaCorrelationRuleError: "correlation",
}


def check(texts: list[dict]) -> dict:
    """``[{"source": "<yaml>"}]`` -> ``{"engine", "documents": [{"rules": [...], "errors": [...]}]}``."""
    return {"engine": ENGINE_VERSION, "documents": [check_text(str(item.get("source") or "")) for item in texts]}


def check_text(text: str) -> dict:
    rules: list[dict] = []
    errors: list[dict] = []
    seen: dict[str, int] = {}
    chunks = documents.split(text)
    if not chunks:
        errors.append({"line": 1, "column": 1, "message": "the text holds no rule"})
    for chunk in chunks[:MAX_DOCUMENTS]:
        info, found = _chunk(chunk)
        errors.extend(found)
        if info is not None:
            if info["id"] in seen:
                errors.append(
                    {
                        "line": chunk.line,
                        "column": 1,
                        "message": f"the id {info['id']} is already used by the rule at line {seen[info['id']]}",
                    }
                )
                continue
            seen[info["id"]] = chunk.line
            rules.append(info)
    if len(chunks) > MAX_DOCUMENTS:
        errors.append(
            {
                "line": chunks[MAX_DOCUMENTS].line,
                "column": 1,
                "message": f"a text may hold {MAX_DOCUMENTS} rules at most; the rest are not read",
            }
        )
    return {"rules": rules, "errors": sorted(errors, key=lambda e: (e["line"], e["column"]))}


def _get(node: Any, key: str) -> tuple[Any, Any]:
    if isinstance(node, yaml.MappingNode):
        for name, value in node.value:
            if name.value == key:
                return name, value
    return None, None


def _pos(node: Any) -> tuple[int, int]:
    return node.start_mark.line + 1, node.start_mark.column + 1


def _key_for(error: Exception) -> str | None:
    for cls in type(error).__mro__:
        if cls in KEY_OF:
            return KEY_OF[cls]
    return None


def _duplicates(node: Any, found: list[tuple[int, int, str]]) -> None:
    """pySigma keeps the last of two equal keys without a word: a rule that says one thing twice is an error."""
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, yaml.MappingNode):
            seen: set[Any] = set()
            for key, value in current.value:
                if key.value in seen:
                    found.append((*_pos(key), f"the key {key.value} is written twice"))
                seen.add(key.value)
                stack.append(value)
        elif isinstance(current, yaml.SequenceNode):
            stack.extend(current.value)


def _chunk(chunk: documents.Chunk) -> tuple[dict | None, list[dict]]:
    errors: list[dict] = []

    def error(line: int, column: int, message: str) -> None:
        errors.append({"line": chunk.line - 1 + line, "column": column, "message": message})

    try:
        node, document = documents.load(chunk.text)
    except documents.DocumentError as failure:
        error(failure.line, failure.column, failure.message)
        return None, errors
    if not isinstance(document, dict):
        error(*_pos(node), "a Sigma rule is a mapping of keys")
        return None, errors
    found: list[tuple[int, int, str]] = []
    _duplicates(node, found)
    for line, column, message in found:
        error(line, column, message)
    if document.get("action") in ("global", "reset", "repeat") or "filter" in document:
        error(
            *_pos(node),
            "Sigma collection actions (global, reset, repeat) and filters are not read: write each rule in full",
        )
        return None, errors
    is_correlation = "correlation" in document
    cls = SigmaCorrelationRule if is_correlation else SigmaRule
    try:
        rule = cls.from_dict(document, collect_errors=True)
    except X.SigmaError as failure:  # not everything is collected
        error(*_pos(node), str(failure))
        return None, errors
    except (KeyError, TypeError, ValueError, AttributeError) as failure:
        error(*_pos(node), f"not a Sigma rule ({type(failure).__name__}: {failure})")
        return None, errors
    # A regular expression RE2 refuses is not an error of the text: the rule is fine Sigma and Nik cannot run it.
    refusals = [str(refused(failure)) for failure in rule.errors if isinstance(failure, X.SigmaRegularExpressionError)]
    rule.errors = [failure for failure in rule.errors if not isinstance(failure, X.SigmaRegularExpressionError)]
    for failure in rule.errors:
        key = _key_for(failure)
        name, _value = _get(node, key) if key else (None, None)
        error(*_pos(name if name is not None else node), str(failure))
    if "id" not in document or not document.get("id"):
        name, _value = _get(node, "title")
        error(*_pos(name if name is not None else node), "a rule needs an id (a UUID)")
    if not is_correlation:
        refusals.extend(_detection(node, document, rule, error, bool(refusals)))
    # The generic copy of an error that was also placed precisely is noise.
    noise = {
        i
        for i, one in enumerate(errors)
        for j, other in enumerate(errors)
        if i != j and other["message"].endswith(one["message"]) and other["message"] != one["message"]
    }
    errors[:] = [one for i, one in enumerate(errors) if i not in noise]
    if errors:
        return None, errors
    return _info(chunk, document, rule, is_correlation, refusals), errors


def _detection(node: Any, document: dict, rule: SigmaRule, error, refused_before: bool) -> list[str]:
    """Each detection item on its own (a modifier or a value that is wrong is placed on its key), then the
    condition, which pySigma parses lazily."""
    detection_key, detection = _get(node, "detection")
    items_ok = True
    refusals: list[str] = []
    if isinstance(detection, yaml.MappingNode) and isinstance(document.get("detection"), dict):
        for search_key, search in detection.value:
            if search_key.value in ("condition", "timeframe") or not isinstance(search, yaml.MappingNode):
                continue
            for item_key, _item in search.value:
                try:
                    SigmaDetectionItem.from_mapping(
                        item_key.value, document["detection"][search_key.value][item_key.value]
                    )
                except KeyError:
                    continue  # shadowed by a duplicate key, which is reported
                except X.SigmaRegularExpressionError as failure:
                    if not refused_before:
                        refusals.append(refused(failure))
                except X.SigmaError as failure:
                    items_ok = False
                    error(*_pos(item_key), f"{search_key.value}.{item_key.value}: {failure}")
    if rule.errors or not items_ok or refused_before or refusals:
        return refusals
    condition_key, condition = _get(detection, "condition")
    try:
        for parsed in rule.detection.parsed_condition:
            _ = parsed.parsed
    except X.SigmaError as failure:
        line, column = _pos(condition) if condition is not None else _pos(detection_key or node)
        found = re.search(r"col:(\d+)", str(failure))
        if found and condition is not None and condition.style is None:  # a plain scalar: add the column in it
            column += int(found.group(1)) - 1
        error(line, column, str(failure))
    except RecursionError:
        error(*_pos(detection_key or node), "the condition is nested too deep")
    return refusals


def _info(chunk: documents.Chunk, document: dict, rule: Any, is_correlation: bool, refusals: list[str]) -> dict:
    supported, reason = True, ""
    product = category = service = ""
    try:
        if is_correlation:
            correlate.plan(chunk.text)
        else:
            source = rule.logsource
            product, category, service = source.product or "", source.category or "", source.service or ""
            logsource.places(product, category, service)
            if refusals:
                raise Unsupported(refusals[0])
            compile_rule(rule)
    except (logsource.NoRecords, Unsupported) as failure:
        supported, reason = False, str(failure)
    return {
        "id": str(rule.id),
        "name": rule.name or "",
        "title": rule.title,
        "author": rule.author or "",
        # A rule that names no level is a medium one: written in a hurry, it is still seen.
        "level": LEVELS.get(rule.level.name.lower(), 3) if rule.level is not None else 3,
        "status": rule.status.name.lower() if rule.status is not None else "",
        "kind": "correlation" if is_correlation else "rule",
        "product": product,
        "category": category,
        "service": service,
        "tags": [str(tag) for tag in rule.tags],
        "supported": supported,
        "reason": reason,
        "source": chunk.text,
        "line": chunk.line,
    }
