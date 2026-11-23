"""
Mini Project 5.3 - Privacy-Compliance Checklist Tool for a Hypothetical Mobile App

Reads the declared data practices in app_profile.json and checks each practice
against a small, explicit rule set for four frameworks:
    GDPR (EU), CCPA/CPRA (California), LGPD (Brazil), DPDP Act 2023 (India)

Every rule returns one of: COMPLIANT, GAP, N/A - with a short reason.
A practice is a GAP for a framework if any rule of that framework says GAP.

Outputs (in ../outputs/):
    privacy_checklist_matrix.csv  - one row per practice, one column per framework
    privacy_gap_report.csv        - every gap with priority and recommended fix
Console: per-framework gap report + app-level checks + prioritised remediation.

This is a teaching tool built from course Section 5.7, not legal advice.
Python 3 standard library only.  Run:  python privacy_checklist.py [profile.json]
"""

import csv
import json
import os
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "..", "outputs")

OK, GAP, NA = "COMPLIANT", "GAP", "N/A"
SPECIAL = {"health", "biometric"}                 # GDPR Art. 9 / LGPD Art. 11 style
CPRA_SPI = {"health", "biometric", "precise_location"}
AD_WORDS = ("advertis", "insur")                  # purposes beyond the core service


def sells_or_shares(p):
    return any(s["type"] == "sale_or_share" for s in p["shared_with"])


def beyond_core(p):
    return sells_or_shares(p) or any(w in p["purpose"].lower() for w in AD_WORDS)


def is_ads(p):
    return "advertis" in p["purpose"].lower()


# ---------------------------------------------------------------------------
# GDPR - affirmative lawful basis, opt-in consent, sensitive data, storage limit
# ---------------------------------------------------------------------------
def gdpr_rules(p, app):
    r = []
    b, m = p["lawful_basis"], p["consent_mechanism"]
    # G1 lawful basis (Art. 6) and valid consent (Art. 4(11), Art. 7)
    if b == "consent":
        r.append(("G1", OK, "freely given, specific opt-in consent") if m == "opt_in" else
                 ("G1", GAP, f"'{m}' is not valid consent - GDPR needs an affirmative, "
                             "unbundled opt-in"))
    elif b == "legitimate_interest":
        if p["sensitive_type"] in SPECIAL:
            r.append(("G1", GAP, "legitimate interest cannot cover special-category data"))
        elif p["lia_documented"] and m == "opt_out":
            r.append(("G1", OK, "legitimate interest with documented balancing test "
                                "and right to object"))
        else:
            r.append(("G1", GAP, "legitimate interest not documented / no right to object"))
    elif b == "contract":
        r.append(("G1", OK, "necessary for the contract with the user"))
    else:
        r.append(("G1", GAP, f"no recognised lawful basis ('{b}')"))
    # G2 sensitive data: explicit opt-in before collection (location treated as sensitive)
    if p["sensitive_type"]:
        r.append(("G2", OK, f"explicit opt-in obtained for {p['sensitive_type']}")
                 if m == "opt_in" else
                 ("G2", GAP, f"{p['sensitive_type']} collected without explicit opt-in consent"))
    else:
        r.append(("G2", NA, "not sensitive data"))
    # G3 storage limitation (Art. 5(1)(e))
    r.append(("G3", OK, f"finite retention ({p['retention']})") if p["retention_days"] is not None
             else ("G3", GAP, "indefinite retention breaks storage limitation"))
    # G4 sharing: third-party disclosure needs its own consent; processors need Art. 28 contract
    if not p["shared_with"]:
        r.append(("G4", NA, "no third-party sharing"))
    elif sells_or_shares(p):
        r.append(("G4", OK, "sharing covered by opt-in consent") if m == "opt_in" else
                 ("G4", GAP, "data passed to other controllers without specific opt-in consent"))
    else:
        r.append(("G4", OK, "processor bound by an Art. 28 contract"))
    return r


# ---------------------------------------------------------------------------
# CCPA / CPRA - notice at collection, opt-out of sale/sharing, SPI, retention
# ---------------------------------------------------------------------------
def ccpa_rules(p, app):
    r = []
    r.append(("C1", OK, "covered by notice at collection") if app["notice_lists_each_category_and_purpose"]
             else ("C1", GAP, "no notice at collection"))
    if sells_or_shares(p):
        if not app["do_not_sell_or_share_link"]:
            r.append(("C2", GAP, "sold/shared without a 'Do Not Sell or Share My Personal "
                                 "Information' opt-out"))
        else:
            r.append(("C2", OK, "opt-out link provided"))
        if app["minimum_user_age"] < 16 and p["consent_mechanism"] != "opt_in":
            r.append(("C2b", GAP, "users aged 13-15 need opt-in before sale/sharing"))
    else:
        r.append(("C2", NA, "not sold or shared"))
    if p["sensitive_type"] in CPRA_SPI:
        if beyond_core(p) and not app["limit_sensitive_pi_link"]:
            r.append(("C3", GAP, f"sensitive PI ({p['sensitive_type']}) used beyond the "
                                 "requested service with no 'Limit the Use of My Sensitive "
                                 "Personal Information' link"))
        else:
            r.append(("C3", OK, "sensitive PI used only to provide the requested service"))
    else:
        r.append(("C3", NA, "not sensitive personal information"))
    r.append(("C4", OK, "retention period disclosed") if p["retention_days"] is not None
             else ("C4", GAP, "retention period not disclosed ('indefinite')"))
    return r


# ---------------------------------------------------------------------------
# LGPD - legal basis (Art. 7), sensitive data (Art. 11), sharing, termination
# ---------------------------------------------------------------------------
def lgpd_rules(p, app):
    r = []
    b, m = p["lawful_basis"], p["consent_mechanism"]
    if b == "consent":
        r.append(("L1", OK, "free, informed, unambiguous consent") if m == "opt_in" else
                 ("L1", GAP, f"'{m}' consent is a generic authorisation - void under LGPD"))
    elif b == "legitimate_interest":
        r.append(("L1", OK, "legitimate interest (Art. 7 IX) with documented assessment")
                 if p["lia_documented"] and p["sensitive_type"] not in SPECIAL else
                 ("L1", GAP, "legitimate interest not usable / not documented"))
    else:
        r.append(("L1", OK, "performance of contract (Art. 7 V)"))
    if p["sensitive_type"] in SPECIAL:
        if m != "opt_in":
            r.append(("L2", GAP, f"sensitive data ({p['sensitive_type']}) needs specific, "
                                 "highlighted consent"))
        else:
            r.append(("L2", OK, "specific, highlighted consent"))
        if p["sensitive_type"] == "health" and sells_or_shares(p):
            r.append(("L2b", GAP, "health data shared with an insurer for economic advantage "
                                  "(restricted by Art. 11)"))
    else:
        r.append(("L2", NA, "not sensitive personal data under LGPD"))
    if sells_or_shares(p):
        r.append(("L3", OK, "specific consent for sharing") if m == "opt_in" else
                 ("L3", GAP, "sharing with another controller lacks specific consent"))
    else:
        r.append(("L3", NA if not p["shared_with"] else OK,
                  "no sharing" if not p["shared_with"] else "operator (processor) under contract"))
    r.append(("L4", OK, "data eliminated when processing ends") if p["retention_days"] is not None
             else ("L4", GAP, "no end of processing - data never eliminated"))
    return r


# ---------------------------------------------------------------------------
# DPDP Act 2023 - Data Fiduciary obligations towards the Data Principal
# ---------------------------------------------------------------------------
def dpdp_rules(p, app):
    r = []
    b, m = p["lawful_basis"], p["consent_mechanism"]
    if b == "consent":
        r.append(("D1", OK, "clear affirmative consent from the Data Principal") if m == "opt_in"
                 else ("D1", GAP, f"'{m}' is not free, specific, unconditional consent by "
                                  "clear affirmative action"))
    elif b == "legitimate_interest":
        r.append(("D1", GAP, "DPDP has no legitimate-interest ground; needs consent or "
                             "a listed legitimate use"))
    else:
        r.append(("D1", OK, "legitimate use: data voluntarily provided for a specified purpose"))
    r.append(("D2", OK, "itemised notice of data and purpose")
             if app["notice_lists_each_category_and_purpose"] else ("D2", GAP, "no notice"))
    r.append(("D3", OK, "erased once the purpose is served") if p["retention_days"] is not None
             else ("D3", GAP, "Data Fiduciary keeps data after the purpose is served"))
    if app["minimum_user_age"] < 18 and is_ads(p):
        r.append(("D4", GAP, "targeted advertising / tracking of Data Principals under 18 "
                             "is prohibited"))
    else:
        r.append(("D4", NA, "no child-directed tracking"))
    return r


FRAMEWORKS = {"GDPR": gdpr_rules, "CCPA/CPRA": ccpa_rules,
              "LGPD": lgpd_rules, "DPDP Act": dpdp_rules}

# Recommended change for each rule code that can raise a gap
REMEDY = {
    "G1": "Replace bundled/opt-out consent with a separate, unticked opt-in screen per purpose; "
          "allow withdrawal as easily as giving consent.",
    "G2": "Ask for explicit opt-in (separate dialog) BEFORE collecting the sensitive data; "
          "default to off.",
    "G3": "Set and publish a finite retention period; auto-delete when it expires.",
    "G4": "Stop sharing until users give a specific opt-in for each recipient; list recipients.",
    "C1": "Publish a notice at collection listing categories and purposes.",
    "C2": "Add a 'Do Not Sell or Share My Personal Information' link and honour Global "
          "Privacy Control signals.",
    "C2b": "Require opt-in before selling/sharing data of users aged 13-15 (parental consent "
           "under 13) or raise the minimum age.",
    "C3": "Add a 'Limit the Use of My Sensitive Personal Information' link, or stop using SPI "
          "beyond the requested service.",
    "C4": "Disclose a concrete retention period for this category.",
    "L1": "Collect specific, highlighted consent (no generic authorisation in terms of use).",
    "L2": "Separate, highlighted consent for sensitive data, for a stated purpose only.",
    "L2b": "End the health-data feed to the insurer.",
    "L3": "Obtain specific consent naming the third party before any sharing.",
    "L4": "Define the end of processing and delete or anonymise data at that point.",
    "D1": "Use clear affirmative consent (or a listed legitimate use) for this purpose; "
          "provide a consent-withdrawal option.",
    "D2": "Provide itemised notice in English or any Eighth Schedule language.",
    "D3": "Erase data when the purpose is served or consent is withdrawn.",
    "D4": "Disable targeted ads and tracking for users under 18; add verifiable parental consent.",
}


THEMES = {"consent": ("G1", "G2", "L1", "L2", "D1"), "sharing": ("G4", "L3", "C2"),
          "children": ("C2b", "D4"), "spi": ("C3",), "retention": ("G3", "C4", "L4", "D3"),
          "insurer": ("L2b",)}


def themes_of(gs):
    out = {}
    for theme, codes in THEMES.items():
        hit = [g["rule"] for g in gs if g["rule"] in codes]
        if hit:
            out[theme] = list(dict.fromkeys(hit))
    return out


def theme_remedy(theme, p, codes):
    """One concrete change per theme, merged so a single fix satisfies every framework."""
    parties = ", ".join(s["party"] for s in p["shared_with"] if s["type"] == "sale_or_share")
    if theme == "consent":
        if codes == ["D1"] and p["lawful_basis"] == "legitimate_interest":
            return ("For Indian users, switch this processing from opt-out to an opt-in "
                    "consent toggle (DPDP has no legitimate-interest ground); keep the "
                    "documented legitimate-interest basis for GDPR and LGPD.")
        extra = " explicit," if p["sensitive_type"] else ""
        return (f"Replace the '{p['consent_mechanism']}' mechanism with a separate,{extra} "
                "unticked opt-in screen for this one purpose, shown BEFORE collection, with "
                "withdrawal as easy as giving consent.")
    if theme == "sharing":
        return (f"Suspend the feed to {parties} until the user opts in for that named "
                "recipient; add a 'Do Not Sell or Share My Personal Information' link that "
                "also honours the Global Privacy Control signal.")
    if theme == "children":
        return ("Turn off targeted advertising and tracking for every account under 18 "
                "(DPDP) and require opt-in before any sale/sharing for ages 13-15 (CCPA), "
                "or raise the minimum age to 18 with an age gate.")
    if theme == "spi":
        return (f"Add a 'Limit the Use of My Sensitive Personal Information' link, or stop "
                f"using {p['sensitive_type'].replace('_', ' ')} for anything beyond the "
                "service the user asked for.")
    if theme == "retention":
        return ("Replace 'indefinite' with a published, finite retention period (e.g. 12 "
                "months after last use) and automatic deletion or anonymisation.")
    return "End the transfer of health data to the insurer completely."


def evaluate(profile):
    app = profile["app_level"]
    results = {}          # (practice_id, framework) -> (status, [rule results])
    for p in profile["practices"]:
        for fw, fn in FRAMEWORKS.items():
            rules = fn(p, app)
            statuses = [s for _, s, _ in rules]
            status = GAP if GAP in statuses else OK if OK in statuses else NA
            results[(p["id"], fw)] = (status, rules)
    return results


def app_level_checks(app):
    """Obligations that attach to the app/organisation rather than one practice."""
    checks = [
        ("GDPR", "DPO for large-scale health-data processing (Art. 37)",
         app["gdpr_dpo_appointed"], "Appoint a Data Protection Officer."),
        ("GDPR", "Parental consent for under-16 users where consent is the basis (Art. 8)",
         app["minimum_user_age"] >= 16, "Add age gate and parental consent for users under 16."),
        ("CCPA/CPRA", "'Do Not Sell or Share' link", app["do_not_sell_or_share_link"],
         "Add the opt-out link in app settings and on the website."),
        ("CCPA/CPRA", "'Limit the Use of My Sensitive PI' link", app["limit_sensitive_pi_link"],
         "Add the limit-use link."),
        ("LGPD", "Encarregado (data protection officer) appointed (Art. 41)",
         app["lgpd_encarregado_appointed"], "Appoint and publish the encarregado's contact."),
        ("DPDP Act", "Grievance redressal for Data Principals", app["dpdp_grievance_officer"],
         "Name a grievance officer and response process; mention the Data Protection Board."),
        ("DPDP Act", "Verifiable parental consent for users under 18",
         app["minimum_user_age"] >= 18, "Add verifiable parental consent for under-18 users."),
        ("All", "Data-rights requests (access / delete / correct) in app",
         app["data_rights_request_in_app"], "Add an in-app rights request form."),
    ]
    return checks


def priority(p, code):
    if p["sensitive_type"] or sells_or_shares(p) or code in ("D4", "C2b", "L2b"):
        return "HIGH"
    if code in ("G1", "L1", "D1", "G4", "L3", "C2"):
        return "MEDIUM"
    return "LOW"


def main(path):
    with open(path, encoding="utf-8") as f:
        profile = json.load(f)
    os.makedirs(OUT_DIR, exist_ok=True)
    practices = {p["id"]: p for p in profile["practices"]}
    results = evaluate(profile)

    print("=" * 78)
    print("MINI PROJECT 5.3 - PRIVACY-COMPLIANCE CHECKLIST")
    print(f"App: {profile['app_name']}")
    print("=" * 78)

    # Checklist matrix
    fws = list(FRAMEWORKS)
    print(f"\n{'ID':<4}{'Data practice':<44}" + "".join(f"{fw:<11}" for fw in fws))
    print("-" * 92)
    rows = []
    for pid, p in practices.items():
        cells = [results[(pid, fw)][0] for fw in fws]
        print(f"{pid:<4}{p['data_category'][:42]:<44}" + "".join(f"{c:<11}" for c in cells))
        rows.append({"id": pid, "data_practice": p["data_category"], "purpose": p["purpose"],
                     "consent_mechanism": p["consent_mechanism"], "retention": p["retention"],
                     **{fw: c for fw, c in zip(fws, cells)}})
    with open(os.path.join(OUT_DIR, "privacy_checklist_matrix.csv"), "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # Per-framework gap report
    gaps = []
    for fw in fws:
        print(f"\n--- {fw}: gap report ---")
        n = 0
        for pid, p in practices.items():
            for code, status, reason in results[(pid, fw)][1]:
                if status == GAP:
                    n += 1
                    pr = priority(p, code)
                    print(f"  [{pr:<6}] {pid} {code:<4} {reason}")
                    gaps.append({"framework": fw, "practice": pid,
                                 "data_category": p["data_category"], "rule": code,
                                 "finding": reason, "priority": pr,
                                 "recommendation": REMEDY[code]})
        print(f"  -> {n} gap(s)")

    print("\n--- App-level checks ---")
    for fw, item, ok, fix in app_level_checks(profile["app_level"]):
        print(f"  {fw:<10} {'OK ' if ok else 'GAP'}  {item}")
        if not ok:
            gaps.append({"framework": fw, "practice": "APP", "data_category": "Whole app",
                         "rule": "APP", "finding": item + " - missing", "priority": "MEDIUM",
                         "recommendation": fix})

    with open(os.path.join(OUT_DIR, "privacy_gap_report.csv"), "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(gaps[0].keys()))
        w.writeheader()
        w.writerows(gaps)

    # Prioritised remediation: per practice, one merged action per theme
    print("\n--- Prioritised remediation (merged across frameworks) ---")
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    by_practice = {}
    for g in gaps:
        if g["practice"] != "APP":
            by_practice.setdefault(g["practice"], []).append(g)
    ranked = sorted(by_practice.items(),
                    key=lambda kv: (min(order[g["priority"]] for g in kv[1]), kv[0]))
    plan = []
    for pid, gs in ranked:
        p = practices[pid]
        pr = min((g["priority"] for g in gs), key=order.get)
        print(f"\n  [{pr}] {pid} {p['data_category']}")
        for theme, codes in themes_of(gs).items():
            text = theme_remedy(theme, p, codes)
            plan.append({"priority": pr, "practice": pid, "data_category": p["data_category"],
                         "theme": theme, "rules": " ".join(codes), "action": text})
            print(textwrap.fill(f"{text} [{' '.join(codes)}]", 74,
                                initial_indent="     - ", subsequent_indent="       "))
    with open(os.path.join(OUT_DIR, "privacy_remediation_plan.csv"), "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(plan[0].keys()))
        w.writeheader()
        w.writerows(plan)

    total = len(gaps)
    print(f"\nTotal gaps: {total}  "
          f"(HIGH {sum(g['priority'] == 'HIGH' for g in gaps)}, "
          f"MEDIUM {sum(g['priority'] == 'MEDIUM' for g in gaps)}, "
          f"LOW {sum(g['priority'] == 'LOW' for g in gaps)})")
    print("Saved: outputs/privacy_checklist_matrix.csv, outputs/privacy_gap_report.csv, "
          "outputs/privacy_remediation_plan.csv")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "app_profile.json"))
