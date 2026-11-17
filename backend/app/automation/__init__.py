"""Nik's own automation engine: playbooks as graphs, durable runs, scripts in a sandbox."""

# Importing these registers their actions (the "Nik", HTTP and e-mail nodes).
from . import nik_actions, outbound  # noqa: E402, F401
