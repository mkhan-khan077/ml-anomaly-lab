# ML Anomaly Detection on API Logs (practice project)

Practice project: compare machine-learning anomaly detection with fixed-threshold rules on the nginx log format used in
[api-abuse-detections](../api-abuse-detections). This is practice work on synthetic data, not production experience.

## Question
Do thresholds I tuned by hand catch the same things as a model fit on a "normal" baseline, and what does each miss?

## Method
1. `gen_synthetic.py` creates 8 hours of labeled traffic: 20 normal clients, plus seven attack scenarios starting after
   hour 3 (ID enumeration, failed-login burst, request flood, token reuse, debug endpoint, and two "low and slow"
   variants that stay under my rule thresholds).
2. `anomaly.py` turns the log into per-client, per-minute features: request count, distinct paths, small (failed-login
   size) login responses, error rate, mean response size, debug-path hits, and how many clients used the same token.
3. Three detectors are fit or set on the first 3 hours (the baseline) and scored on the rest:
   - **Rules:** fixed thresholds (the same numbers as the lab rules, applied to one-minute windows).
   - **Isolation Forest** (scikit-learn), alert above the 99.5th percentile of baseline scores.
   - **Z-score:** largest feature z-score against the baseline mean and standard deviation, same percentile cutoff.

## Results (synthetic data, seed 7)
```
baseline windows: 2201  test windows: 3641  ML threshold: 0.682

Per-scenario detection (attack windows caught / total):
           scenario  windows  rule_caught  iforest_caught  zscore_caught
     debug_endpoint        1            1               0              0
     id_enumeration        1            1               0              1
     login_failures        2            1               2              2
         rate_abuse        1            1               0              1
   slow_enumeration        3            0               0              3
slow_login_failures        3            0               3              3
        token_reuse        4            4               0              4

False positives on 3626 normal windows: rule=35  iforest=19  zscore=36
rule     precision=0.19 recall=0.53 (tp=8 fp=35 fn=7)
iforest  precision=0.21 recall=0.33 (tp=5 fp=19 fn=10)
zscore   precision=0.28 recall=0.93 (tp=14 fp=36 fn=1)
```

## What I learned
- **Isolation Forest missed the most extreme attacks.** A 300-request-per-minute flood scored below the alert cutoff.
  Trees can only split inside the range seen in training, so a value far outside that range is not scored as more
  unusual than one just outside it. It did catch the failed-login scenarios.
- **A plain z-score against the baseline did better here** (recall 0.93 vs 0.33 for Isolation Forest, 0.53 for rules),
  including both low-and-slow scenarios that the fixed rules missed. A simple model is a fair baseline to beat before
  using a complex one.
- **Most "false positives" are one client.** Of the rule's 35 false positives, all are one client (10.0.0.12), the
  owner of the stolen token, whose normal traffic gets flagged because the token is shared. That is arguably a useful
  alert but it is not in my attack labels, so it counts against precision. Precision numbers here should be read with
  that in mind.
- The debug endpoint (a single request) is a signature, not an anomaly. The z-score missed it and the rule caught it.
  This is why I would keep rules for known-bad paths and use a model for volume and behavior shifts.

## Limitations
- Synthetic traffic that I generated. Attack shapes were written by me, so the results say little about real attacks.
- One run (seed 7), 20 clients, a clean baseline assumed. A baseline that contains attacks would hurt both models.
- Alert cutoffs are a percentile of baseline scores, not tuned further.
- Not run on a real production log. To try it on the lab's real log: `python3 anomaly.py logs/access.log`
  (no labels; it lists the top anomalous client-minutes).

## Run it
    pip install pandas scikit-learn
    python3 gen_synthetic.py
    python3 anomaly.py logs/synthetic.log logs/synthetic_labels.csv
