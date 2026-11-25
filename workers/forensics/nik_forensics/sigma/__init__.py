"""Sigma detection on the records of host evidence, in the forensics worker.

    documents.py   where each YAML document of a rule text is, and a bounded, safe load of it
    logsource.py   which records a rule's ``logsource`` applies to (the table is Nik's own)
    compile.py     one parsed rule -> a predicate over the fields of a record (pySigma parses, we evaluate)
    correlate.py   the four correlation types, run over the matches of their base rules
    engine.py      a set of rules, indexed by log source, evaluated on the records a parser finds
    hours.py       the working hours of a request and the ``NikOffHours`` field
    check.py       the validation of rule texts for the editor (``POST /sigma/check``)

pySigma is used to parse and validate, never to evaluate; regular expressions run in RE2 only. Everything that
reads a rule text runs in a child process with the limits of a job (``sigma_job.py``, ``run_job.py``).
"""

# Bumped when the same rule could give a different result (a fix of the evaluator, a field added to the records):
# the backend then checks its rules again, and the detections already made stay as they are.
ENGINE_VERSION = "1"
