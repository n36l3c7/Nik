"""The event-log records a person reads first (7.0): the channels and event IDs Nik curates.

The list lives here alone: the screens ask for it with the filter ``matter`` and hold no copy.
Keys are the lower-case channel name, as the frontend keys them and as the worker matches a
channel (a log is spelled as its file spelled it, so a filter compares in lower case).
"""

from __future__ import annotations

# fmt: off
CURATED: dict[str, tuple[int, ...]] = {
    "security": (
        1102, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4699, 4702, 4719, 4720, 4722, 4724, 4726,
        4728, 4732, 4740, 4756, 4771, 4776, 4778, 4779,
    ),
    "system": (104, 1074, 6005, 6006, 6008, 7040, 7045),
    "microsoft-windows-powershell/operational": (4103, 4104),
    "windows powershell": (400, 800),
    "microsoft-windows-terminalservices-localsessionmanager/operational": (21, 22, 23, 24, 25),
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": (1149,),
    "microsoft-windows-windows defender/operational": (1116, 1117, 5001),
    "microsoft-windows-taskscheduler/operational": (106, 141, 200),
    "microsoft-windows-sysmon/operational": (1, 3, 22),
}
# fmt: on
