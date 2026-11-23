"""
Mini Project 5.1 - Part B
Rule-based, telecom-aware intrusion detection over a SYNTHETIC signaling log.

Every event is a plain Python dictionary - no real network, no capture tools.
Rules implemented:
  R1  implausible travel     (country change faster than a travel-time threshold)
  R2  schema / conformance   (missing fields, empty values, unknown event_type,
                              unparseable timestamp)
  R3  auth_request rate      (too many auth_request events in a sliding window)  [Lab Task 2]
  R4  non-monotonic time     (a subscriber's timestamps go backwards in arrival
                              order)                                              [Lab Task 6]
Lab Task 5: a larger log is generated and the R1 threshold is swept to show the
false-positive / false-negative trade-off.

Python 3 standard library only.  Run:  python part_b_signaling_ids.py
Outputs written to ../outputs/
"""

import csv
import json
import os
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "outputs")

REQUIRED_FIELDS = ("event_id", "timestamp", "subscriber_id", "event_type", "country")
ALLOWED_EVENTS = {"attach", "detach", "location_update", "auth_request", "sms_mo", "call_setup"}

# Home country of subscribers (ISO-3166 alpha-2) and plausible roaming partners.
HOME_COUNTRIES = ["RW", "RW", "RW", "KE", "UG", "TZ"]
NEIGHBOURS = {"RW": ["UG", "TZ", "KE", "CD", "BI"], "KE": ["UG", "TZ", "RW"],
              "UG": ["RW", "KE", "TZ"], "TZ": ["RW", "KE", "UG"]}
FAR_AWAY = ["US", "GB", "CN", "BR", "DE", "AU"]
# Countries that share a land border: a few minutes is enough to cross.
ADJACENT = {frozenset(p) for p in [("RW", "UG"), ("RW", "TZ"), ("RW", "CD"), ("RW", "BI"),
                                   ("KE", "UG"), ("KE", "TZ"), ("UG", "TZ"), ("UG", "CD"),
                                   ("TZ", "BI"), ("TZ", "CD")]}
BORDER_THRESHOLD_MIN = 5       # border-aware variant of R1

# Approximate reference point per country (lat, lon) - main city / border town
COORDS = {"RW": (-1.95, 30.06), "KE": (-1.29, 36.82), "UG": (0.35, 32.58),
          "TZ": (-6.80, 39.28), "CD": (-1.68, 29.22), "BI": (-3.38, 29.36),
          "US": (40.71, -74.00), "GB": (51.50, -0.12), "CN": (39.90, 116.40),
          "BR": (-23.55, -46.63), "DE": (50.11, 8.68), "AU": (-33.87, 151.21)}
MAX_SPEED_KMH = 900            # airliner cruise speed
AIRPORT_OVERHEAD_MIN = 60      # check-in / boarding / taxi


def distance_km(a, b):
    """Great-circle (haversine) distance between two countries' reference points."""
    from math import radians, sin, cos, asin, sqrt
    (la1, lo1), (la2, lo2) = COORDS[a], COORDS[b]
    dla, dlo = radians(la2 - la1), radians(lo2 - lo1)
    h = sin(dla / 2) ** 2 + cos(radians(la1)) * cos(radians(la2)) * sin(dlo / 2) ** 2
    return 2 * 6371 * asin(sqrt(h))


def min_travel_minutes(a, b, speed_kmh=MAX_SPEED_KMH):
    """Shortest physically plausible time to move from country a to country b."""
    if frozenset((a, b)) in ADJACENT:
        return BORDER_THRESHOLD_MIN
    return distance_km(a, b) / speed_kmh * 60 + AIRPORT_OVERHEAD_MIN

START = datetime(2026, 11, 23, 0, 0, tzinfo=timezone.utc)

# Detector parameters
TRAVEL_THRESHOLD_MIN = 60      # R1: country change inside 60 min is implausible
AUTH_RATE_MAX = 5              # R3: more than 5 auth_request ...
AUTH_RATE_WINDOW_S = 60        # ... within 60 seconds


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Synthetic log generation (Procedure steps 10-11)
# ---------------------------------------------------------------------------
def generate_signaling_log(n, n_subscribers=40, seed=7, inject=True,
                           n_far_jumps=2, n_border=1, n_bursts=1,
                           n_flights=0, n_malformed=2, n_backwards=1):
    """Return (events, ground_truth).

    events       : list of dicts in ARRIVAL order (as a probe would see them)
    ground_truth : dict anomaly_type -> list of event_ids deliberately injected.
                   'legit_border' marks a REAL but fast border crossing that a
                   naive travel rule will (wrongly) flag - used to show a false positive.
    """
    rng = random.Random(seed)
    subs = [f"IMSI-635{rng.randint(10**9, 10**10 - 1)}" for _ in range(n_subscribers)]
    home = {s: rng.choice(HOME_COUNTRIES) for s in subs}
    events, truth = [], defaultdict(list)
    counter = [0]

    def new_event(ts, sub, etype, country):
        counter[0] += 1
        return {"event_id": counter[0], "timestamp": iso(ts), "subscriber_id": sub,
                "event_type": etype, "country": country}

    # --- normal traffic: subscribers stay in their home country ----------
    span_s = 24 * 3600
    for _ in range(n):
        sub = rng.choice(subs)
        ts = START + timedelta(seconds=rng.randint(0, span_s))
        etype = rng.choices(["location_update", "attach", "auth_request", "sms_mo",
                             "call_setup", "detach"], [40, 10, 20, 15, 10, 5])[0]
        events.append(new_event(ts, sub, etype, home[sub]))

    if inject:
        # Each injected scenario uses its own fresh subscriber, so its events
        # are not mixed with unrelated random traffic.
        def take():
            sub = f"IMSI-635{rng.randint(10**9, 10**10 - 1)}"
            home[sub] = rng.choice(HOME_COUNTRIES)
            return sub

        # Legitimate long-gap roaming (flights) - must NOT be flagged
        for _ in range(n_flights):
            sub = take()
            t0 = START + timedelta(seconds=rng.randint(0, span_s - 20 * 3600))
            dest = rng.choice([c for c in NEIGHBOURS.get(home[sub], ["KE"]) if c != "CD"]
                              + FAR_AWAY)
            # realistic: at least the flight time, plus waiting/connection time
            gap = int(min_travel_minutes(home[sub], dest)) + rng.randint(30, 360)
            events.append(new_event(t0, sub, "location_update", home[sub]))
            e = new_event(t0 + timedelta(minutes=gap), sub, "attach", dest)
            events.append(e)
            truth["legit_roaming"].append(e["event_id"])

        # A1: implausible roaming - distant country minutes later
        for _ in range(n_far_jumps):
            sub = take()
            t0 = START + timedelta(seconds=rng.randint(3600, span_s - 3600))
            gap = rng.randint(5, 150)                   # far too fast for intercontinental travel
            events.append(new_event(t0, sub, "location_update", home[sub]))
            e = new_event(t0 + timedelta(minutes=gap), sub, "location_update",
                          rng.choice(FAR_AWAY))
            events.append(e)
            truth["implausible_travel"].append(e["event_id"])

        # Legit fast border crossing (Rubavu RW -> Goma CD), 10-40 min
        for _ in range(n_border):
            sub = take()
            home[sub] = "RW"
            t0 = START + timedelta(seconds=rng.randint(3600, span_s - 3600))
            events.append(new_event(t0, sub, "location_update", "RW"))
            e = new_event(t0 + timedelta(minutes=rng.randint(10, 40)), sub,
                          "location_update", "CD")
            events.append(e)
            truth["legit_border"].append(e["event_id"])

        # A2: malformed messages - missing field / invalid event_type
        for i in range(n_malformed):
            sub = take()
            t = START + timedelta(seconds=rng.randint(0, span_s))
            if i % 2 == 0:
                e = new_event(t, sub, "location_update", home[sub])
                del e["country"]                            # missing field
            else:
                e = new_event(t, sub, "purge_all_subs", home[sub])  # bad type
            events.append(e)
            truth["malformed"].append(e["event_id"])

        # A3: auth_request burst (e.g. credential-guessing / signalling storm)
        for _ in range(n_bursts):
            sub = take()
            t0 = START + timedelta(seconds=rng.randint(0, span_s - 600))
            for k in range(rng.randint(15, 25)):
                e = new_event(t0 + timedelta(seconds=k * 2), sub, "auth_request", home[sub])
                events.append(e)
                truth["auth_burst"].append(e["event_id"])

    # Arrival order = time order ...
    events.sort(key=lambda e: e["timestamp"])

    # ... except A4: delayed / replayed message arriving out of order (Lab Task 6)
    if inject:
        for _ in range(n_backwards):
            sub = take()
            # the subscriber is seen at 20:00, then a message stamped 02:00
            # arrives AFTER it (delayed, replayed or clock-manipulated)
            events.append(new_event(START + timedelta(hours=20), sub, "attach", home[sub]))
            e = new_event(START + timedelta(hours=2), sub, "location_update", home[sub])
            events.append(e)                              # appended at the END
            truth["non_monotonic"].append(e["event_id"])
    return events, dict(truth)


# ---------------------------------------------------------------------------
# Detection rules (Procedure step 12 + Lab Tasks 2 and 6)
# ---------------------------------------------------------------------------
def rule_schema(events):
    """R2: required fields present and non-empty, event_type allowed, timestamp parses."""
    flags = []
    for e in events:
        missing = [f for f in REQUIRED_FIELDS if f not in e or e[f] in (None, "")]
        if missing:
            flags.append((e, "R2-schema", f"missing field(s): {', '.join(missing)}"))
            continue
        if e["event_type"] not in ALLOWED_EVENTS:
            flags.append((e, "R2-schema", f"invalid event_type '{e['event_type']}'"))
            continue
        try:
            parse_ts(e["timestamp"])
        except (ValueError, TypeError):
            flags.append((e, "R2-schema", "unparseable timestamp"))
    return flags


def _valid(events):
    bad = {id(f[0]) for f in rule_schema(events)}
    return [e for e in events if id(e) not in bad]


def rule_travel(events, threshold_min=TRAVEL_THRESHOLD_MIN, mode="distance",
                speed_kmh=MAX_SPEED_KMH):
    """R1: per subscriber, sort by time; flag consecutive events whose country
    changes faster than the minimum plausible travel time.
      mode="flat"     : one fixed threshold_min for every country pair
      mode="border"   : flat threshold, but BORDER_THRESHOLD_MIN for neighbours
      mode="distance" : per-pair limit = great-circle distance / speed_kmh
                        + airport overhead (neighbours: BORDER_THRESHOLD_MIN)"""
    flags = []
    by_sub = defaultdict(list)
    for e in _valid(events):
        by_sub[e["subscriber_id"]].append(e)
    for sub, evs in by_sub.items():
        evs.sort(key=lambda e: e["timestamp"])
        for prev, cur in zip(evs, evs[1:]):
            if prev["country"] != cur["country"]:
                gap = (parse_ts(cur["timestamp"]) - parse_ts(prev["timestamp"])).total_seconds() / 60
                a, b = prev["country"], cur["country"]
                if mode == "distance" and a in COORDS and b in COORDS:
                    limit = round(min_travel_minutes(a, b, speed_kmh))
                elif mode in ("border", "distance") and frozenset((a, b)) in ADJACENT:
                    limit = BORDER_THRESHOLD_MIN
                else:
                    limit = threshold_min
                if gap < limit:
                    flags.append((cur, "R1-travel",
                                  f"{prev['country']}->{cur['country']} in {gap:.0f} min "
                                  f"(< {limit} min)"))
    return flags


def rule_auth_rate(events, max_count=AUTH_RATE_MAX, window_s=AUTH_RATE_WINDOW_S):
    """R3 (Lab Task 2): more than max_count auth_request in any window_s window."""
    flags = []
    by_sub = defaultdict(list)
    for e in _valid(events):
        if e["event_type"] == "auth_request":
            by_sub[e["subscriber_id"]].append(e)
    for sub, evs in by_sub.items():
        evs.sort(key=lambda e: e["timestamp"])
        times = [parse_ts(e["timestamp"]) for e in evs]
        left = 0
        for right in range(len(evs)):
            while (times[right] - times[left]).total_seconds() > window_s:
                left += 1
            count = right - left + 1
            if count > max_count:
                flags.append((evs[right], "R3-auth-rate",
                              f"{count} auth_request in {window_s}s (> {max_count})"))
    return flags


def rule_non_monotonic(events):
    """R4 (Lab Task 6): in ARRIVAL order, a subscriber's timestamp goes backwards."""
    flags = []
    last = {}
    for e in _valid(events):
        t = parse_ts(e["timestamp"])
        sub = e["subscriber_id"]
        if sub in last and t < last[sub]:
            back = (last[sub] - t).total_seconds() / 60
            flags.append((e, "R4-time-order", f"time went back {back:.0f} min"))
        last[sub] = max(t, last.get(sub, t))
    return flags


def detect(events, travel_mode="distance"):
    return (rule_schema(events) + rule_travel(events, mode=travel_mode)
            + rule_auth_rate(events) + rule_non_monotonic(events))


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
def fmt(e):
    """Compact one-line view of an event: id, MM-DD HH:MM, IMSI tail, type, country."""
    ts = str(e.get("timestamp", ""))
    return (f"#{e.get('event_id', '?'):<4} {ts[5:10]} {ts[11:16]} ..{str(e.get('subscriber_id'))[-6:]} "
            f"{str(e.get('event_type')):<15} {e.get('country', '--')}")


def summarise(flags, truth):
    flagged_ids = {f[0].get("event_id") for f in flags}
    print("\nInjected anomaly                 injected  detected")
    print("-" * 54)
    for kind in ("implausible_travel", "malformed", "auth_burst", "non_monotonic"):
        ids = truth.get(kind, [])
        hit = sum(1 for i in ids if i in flagged_ids)
        note = ""
        if kind == "auth_burst" and ids:
            note = f"  (first {AUTH_RATE_MAX} of the burst are below the rate limit)"
        print(f"{kind:<32} {len(ids):>8}  {hit:>8}{note}")
    border = truth.get("legit_border", [])
    fp = sum(1 for i in border if i in flagged_ids)
    print(f"{'legit_border (should NOT flag)':<32} {len(border):>8}  {fp:>8}  <- false positive(s)")
    all_injected = set(i for k, v in truth.items() if k not in ("legit_border", "legit_roaming") for i in v)
    other = [f for f in flags if f[0].get("event_id") not in all_injected | set(border)]
    print(f"{'ordinary events flagged':<32} {'':>8}  {len(other):>8}")


def threshold_sweep(seed=2026):
    """Lab Task 5: larger log, many legit flights/border crossings and many
    implausible jumps; sweep the R1 threshold."""
    events, truth = generate_signaling_log(
        5000, n_subscribers=600, seed=seed, n_far_jumps=40, n_border=25,
        n_flights=80, n_bursts=3, n_malformed=6, n_backwards=3)
    bad = set(truth["implausible_travel"])
    rows = []
    print(f"\nLarge log: {len(events)} events, {len(bad)} implausible jumps, "
          f"{len(truth['legit_border'])} fast border crossings, "
          f"{len(truth['legit_roaming'])} legit flights")
    def score(flagged):
        tp, fp, fn = len(flagged & bad), len(flagged - bad), len(bad - flagged)
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 1.0
        return tp, fp, fn, prec, rec

    for mode, label in (("flat", "flat-threshold R1"), ("border", "border-aware R1")):
        print(f"\n  {label}")
        print(f"{'threshold(min)':>14} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}")
        for th in (10, 20, 30, 45, 60, 90, 120, 180, 240, 360):
            flagged = {f[0]["event_id"] for f in rule_travel(events, th, mode=mode)}
            tp, fp, fn, prec, rec = score(flagged)
            rows.append({"rule": label, "parameter": f"{th} min", "TP": tp, "FP": fp,
                         "FN": fn, "precision": round(prec, 3), "recall": round(rec, 3)})
            print(f"{th:>14} {tp:>4} {fp:>4} {fn:>4} {prec:>10.3f} {rec:>8.3f}")

    label = "distance-aware R1"
    print(f"\n  {label} (per-pair limit = distance / speed + {AIRPORT_OVERHEAD_MIN} min)")
    print(f"{'speed(km/h)':>14} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8}")
    for v in (300, 600, 900, 1500, 3000):
        flagged = {f[0]["event_id"] for f in rule_travel(events, mode="distance", speed_kmh=v)}
        tp, fp, fn, prec, rec = score(flagged)
        rows.append({"rule": label, "parameter": f"{v} km/h", "TP": tp, "FP": fp,
                     "FN": fn, "precision": round(prec, 3), "recall": round(rec, 3)})
        print(f"{v:>14} {tp:>4} {fp:>4} {fn:>4} {prec:>10.3f} {rec:>8.3f}")
    return rows


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("=" * 72)
    print("MINI PROJECT 5.1 - PART B: SIGNALING-PLANE ANOMALY DETECTION")
    print("=" * 72)

    events, truth = generate_signaling_log(300)
    print(f"Synthetic log: {len(events)} events, "
          f"{len({e['subscriber_id'] for e in events})} subscribers")
    print("Injected:", {k: len(v) for k, v in truth.items()})
    with open(os.path.join(OUT_DIR, "signaling_log_sample.json"), "w") as f:
        json.dump({"events": events, "ground_truth": truth}, f, indent=1)

    print("\nSample of normal events (full log saved as JSON):")
    for e in events[:4]:
        print("   " + fmt(e))

    runs = (("flat", f"Run 1 - basic detector: flat R1 threshold = {TRAVEL_THRESHOLD_MIN} min"),
            ("distance", f"Run 2 - tuned detector: distance-aware R1 "
                         f"({MAX_SPEED_KMH} km/h + {AIRPORT_OVERHEAD_MIN} min, "
                         f"neighbours {BORDER_THRESHOLD_MIN} min)"))
    for mode, title in runs:
        flags = detect(events, travel_mode=mode)
        print("\n" + "-" * 72)
        print(title)
        print("-" * 72)
        print(f"FLAGGED ENTRIES ({len(flags)}):")
        shown_burst = 0
        for e, rule, why in flags:
            if rule == "R3-auth-rate":
                shown_burst += 1
                if shown_burst > 3:
                    continue
            print(f"  [{rule:<13}] {fmt(e)} | {why}")
        if shown_burst > 3:
            print(f"  [R3-auth-rate ] ... {shown_burst - 3} more events from the same burst")
        summarise(flags, truth)

    print("\n--- Lab Task 5: tuning the implausible-travel threshold ---")
    rows = threshold_sweep()
    with open(os.path.join(OUT_DIR, "threshold_sweep.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("\nSaved: outputs/signaling_log_sample.json, outputs/threshold_sweep.csv")
    print("Done.")


if __name__ == "__main__":
    main()
