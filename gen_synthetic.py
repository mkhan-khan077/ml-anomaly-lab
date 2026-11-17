"""Generate a SYNTHETIC log in the same format as the api-abuse-lab nginx log, with ground-truth labels.
Usage: python3 gen_synthetic.py [seed]   -> logs/synthetic.log and logs/synthetic_labels.csv
Synthetic data: results from it say how the method behaves on made-up traffic, not on real traffic."""
import csv, os, random, sys
from datetime import datetime, timedelta

seed = int(sys.argv[1]) if len(sys.argv) > 1 else 7
rnd = random.Random(seed)
START = datetime(2026, 11, 1, 9, 0, 0)
HOURS = 8
TITLES = [f"book{i}" for i in range(1, 40)]
clients = [f"10.0.0.{i}" for i in range(10, 30)]
tokens = {c: "".join(rnd.choice("abcdef0123456789") for _ in range(8)) for c in clients}
events, labels = [], []  # events: (ts, client, method, path, status, bytes, tok)


def add(ts, client, method, path, status, size, tok, label=None):
    events.append((ts, client, method, path, status, size, tok, label))


# Normal traffic: each client makes 1-6 requests in about 60% of minutes
for m in range(HOURS * 60):
    for c in clients:
        if rnd.random() < 0.6:
            for _ in range(rnd.randint(1, 6)):
                ts = START + timedelta(minutes=m, seconds=rnd.randint(0, 59))
                r = rnd.random()
                if r < 0.08:
                    add(ts, c, "POST", "/users/v1/login", 200, rnd.randint(221, 224), tokens[c])
                elif r < 0.12:
                    add(ts, c, "POST", "/users/v1/login", 200, 81, tokens[c])  # an occasional typo
                elif r < 0.55:
                    add(ts, c, "GET", "/books/v1", 200, rnd.randint(900, 1400), tokens[c])
                else:
                    add(ts, c, "GET", f"/books/v1/{rnd.choice(TITLES)}", 200, rnd.randint(150, 400), tokens[c])

# Attacks start after hour 3, so the first 3 hours are a clean baseline
def at(h, mm, s=0):
    return START + timedelta(hours=h, minutes=mm, seconds=s)

def attack(kind, client, start, build):
    for ev in build(start):
        add(*ev, label=kind)

# 1. ID enumeration (obvious): 40 distinct paths in one minute
attack("id_enumeration", "10.0.0.99", at(3, 10), lambda t: [(t + timedelta(seconds=i), "10.0.0.99", "GET", f"/users/v1/{i}", 200, 120, "none0000") for i in range(40)])
# 2. Login failure burst: 25 failed logins in two minutes
attack("login_failures", "10.0.0.98", at(4, 5), lambda t: [(t + timedelta(seconds=i * 4), "10.0.0.98", "POST", "/users/v1/login", 200, 81, "none0001") for i in range(25)])
# 3. Request flood: 300 requests in one minute
attack("rate_abuse", "10.0.0.97", at(5, 20), lambda t: [(t + timedelta(milliseconds=i * 190), "10.0.0.97", "GET", "/books/v1", 200, 1000, "none0002") for i in range(300)])
# 4. Token reuse: one stolen token used from 4 clients
stolen = tokens["10.0.0.12"]
for k, c in enumerate(["10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53"]):
    for i in range(6):
        add(at(5, 40, k * 10 + i), c, "GET", "/users/v1/_debug", 200, 600, stolen, label="token_reuse")
# 5. Debug endpoint: one request
add(at(6, 15), "10.0.0.96", "GET", "/users/v1/_debug", 200, 560, "none0003", label="debug_endpoint")
# 6. Low and slow enumeration: 14 distinct paths in a minute, below the rule threshold, repeated over 3 minutes
for k in range(3):
    attack("slow_enumeration", "10.0.0.95", at(6, 40 + k * 7), lambda t, k=k: [(t + timedelta(seconds=i * 4), "10.0.0.95", "GET", f"/users/v1/{k * 20 + i}", 200, 120, "none0004") for i in range(14)])
# 7. Slow login failures: 8 failures a minute for 3 minutes, below the rule threshold
for k in range(3):
    attack("slow_login_failures", "10.0.0.94", at(7, 10 + k), lambda t: [(t + timedelta(seconds=i * 7), "10.0.0.94", "POST", "/users/v1/login", 200, 81, "none0005") for i in range(8)])

events.sort(key=lambda e: e[0])
os.makedirs("logs", exist_ok=True)
with open("logs/synthetic.log", "w") as f:
    for ts, c, me, p, st, sz, tok, _ in events:
        f.write(f'{c} [{ts.isoformat()}] "{me} {p}" {st} {sz} tok={tok}\n')
with open("logs/synthetic_labels.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["ts", "client", "label"])
    for ts, c, *_rest, label in events:
        if label: w.writerow([ts.isoformat(), c, label])
print(f"wrote {len(events)} events, {sum(1 for e in events if e[-1])} attack events")
