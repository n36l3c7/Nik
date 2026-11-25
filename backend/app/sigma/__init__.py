"""Sigma detection on host evidence (7.0): the rules Nik keeps, and what it asks of the worker.

The rules live in ``sigma_rules`` (``rules.py``): one row for one YAML document, with what the lists
need read out of it. **Nothing here judges a rule.** The forensics worker holds the Sigma library and
the evaluator: it says whether a text is a rule, whether it can run it and why not
(``checking.py``), runs the set of enabled rules over a file while it reads it (the set is handed over
by its digest, ``ruleset.py``), and runs a rule over records given to it (``trying.py``). This side
keeps the rules, hands the set over, and turns the answers of the worker into rows
(``detections.py``). The rules Nik ships are in ``pack/`` (``seed.py``).
"""
