"""Whether the server is well: one page, the warnings before things break, and the metrics.

``thresholds.py``  what counts as attention and as a problem, set by an administrator;
``checks.py``      every row of the page: a value, a state, what to do;
``watch.py``       the pass that keeps a little history (the growth of the disks, since
                   when a row is in its state) and tells the administrators what changed;
``metrics.py``     the same numbers for Prometheus, and the token a scraper presents.

``/api/health`` stays what a load balancer asks: nothing of this is behind it.
"""
