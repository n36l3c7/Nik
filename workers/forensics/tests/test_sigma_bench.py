"""The speed of the engine with a rule set of the size of a real one (SigmaHQ's Windows rules are about 2,700).

The rules and the records are made here, at random but always the same: harmless text, never evidence. The bound is
loose on purpose (the design asks for 0.1 ms a record on average; this test fails at five times that), the measured
numbers are printed (``pytest -s``) so a regression can be read, not only detected.
"""

from __future__ import annotations

import random
import time

from sigma_support import rule

from nik_forensics.sigma import logsource
from nik_forensics.sigma.engine import Engine

RULES = 3000
RECORDS = 30000
BOUND_MS = 0.5
WORDS = [
    f"{random.Random(n).choice(['cmd', 'ps', 'net', 'reg', 'wmi', 'sc', 'at', 'mshta', 'cert', 'rundll'])}{n}"
    for n in range(1500)
]


def make_rules(generator: random.Random) -> list[dict]:
    """About a third of the rules per kind of log source: a service (a channel), a Sysmon category, Nik's own."""
    services = sorted(logsource.SERVICE)
    categories = sorted(logsource.CATEGORY)
    made = []
    for number in range(RULES):
        pick = generator.random()
        if pick < 0.45:
            where = {"product": "windows", "category": None, "service": generator.choice(services)}
        elif pick < 0.9:
            where = {"product": "windows", "category": generator.choice(categories), "service": None}
        else:
            where = {"product": "nik", "category": None, "service": generator.choice(logsource.NIK_SERVICES)}
        detection: dict = {
            "selection": {
                "Image|endswith": [f"\\{generator.choice(WORDS)}.exe" for _ in range(2)],
                "CommandLine|contains": generator.choice(WORDS),
            },
            "condition": "selection",
        }
        if number % 3 == 0:
            detection["filter"] = {"User": generator.choice(WORDS)}
            detection["condition"] = "selection and not filter"
        if number % 7 == 0:
            detection["keywords"] = [generator.choice(WORDS), generator.choice(WORDS)]
            detection["condition"] = "selection or keywords"
        made.append(rule(f"bench-{number}", detection, **where))
    return made


def make_records(generator: random.Random, count: int) -> list[tuple]:
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    channels = [sysmon] * 6 + ["Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational"]
    made = []
    for number in range(count):
        data = {
            "Image": f"C:\\Windows\\{generator.choice(WORDS)}.exe",
            "CommandLine": f"{generator.choice(WORDS)} -x {generator.choice(WORDS)} {generator.choice(WORDS)}",
            "User": generator.choice(WORDS),
            "ParentImage": f"C:\\{generator.choice(WORDS)}.exe",
            "Hashes": "SHA256=" + "ab" * 32,
            "provider": "p",
        }
        if number % 10 == 0:
            made.append(
                (
                    "commands",
                    f"k{number}",
                    "command",
                    1_700_000_000_000 + number,
                    "H",
                    "u",
                    None,
                    "",
                    "x",
                    data,
                    "powershell",
                )
            )
        else:
            channel = generator.choice(channels)
            event_id = (
                generator.randint(1, 29)
                if channel == sysmon
                else generator.choice([4624, 4625, 4688, 4104, 7045, 1000])
            )
            made.append(
                (
                    "eventlog",
                    f"k{number}",
                    "event",
                    1_700_000_000_000 + number,
                    "H",
                    "u",
                    event_id,
                    channel,
                    "x",
                    data,
                    "evtx",
                )
            )
    return made


def test_a_set_of_three_thousand_rules_costs_a_fraction_of_a_millisecond_a_record():
    generator = random.Random(2024)
    engine = Engine(make_rules(generator))
    records = make_records(generator, RECORDS)
    # The first record of every place pays for parsing and compiling the rules that may apply to it: that is
    # done once per file, and measured apart.
    begun = time.perf_counter()
    for one in records:
        engine.see(*one)
    warm = time.perf_counter() - begun
    begun = time.perf_counter()
    matched = 0
    for one in records:
        matched += len(engine.see(*one))
    cost = (time.perf_counter() - begun) * 1000 / len(records)
    compiled = sum(1 for slot in engine.slots if slot.state)
    print(
        f"\nsigma bench: {RULES} rules ({compiled} compiled on demand, {len(engine.failed)} not evaluated), "
        f"{RECORDS} records, {matched} matches: warm-up {warm:.2f} s, {cost:.4f} ms a record"
    )
    assert engine.errors == 0
    assert cost < BOUND_MS, f"{cost:.3f} ms a record"


def test_the_worst_case_is_every_rule_applying_to_every_record_and_is_said():
    """Sigma's process-creation rules are about half of the Windows ones: a log of Sysmon event 1 and nothing else
    makes every one of them a candidate of every record. The number is printed; it is allowed to be larger."""
    generator = random.Random(7)
    rules = []
    for number in range(1200):
        detection = {
            "selection": {
                "Image|endswith": f"\\{generator.choice(WORDS)}.exe",
                "CommandLine|contains": generator.choice(WORDS),
            },
            "condition": "selection",
        }
        rules.append(rule(f"hot-{number}", detection))
    engine = Engine(rules)
    records = [
        r for r in make_records(generator, 60000) if r[0] == "eventlog" and r[6] == 1
    ]  # (the Sysmon process events of a random mix)
    for one in records:
        engine.see(*one)
    begun = time.perf_counter()
    for one in records:
        engine.see(*one)
    cost = (time.perf_counter() - begun) * 1000 / len(records)
    print(f"\nsigma bench, worst case: 1200 rules for every one of {len(records)} records: {cost:.4f} ms a record")
    assert cost < 5
