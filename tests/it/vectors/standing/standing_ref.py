"""Integer-only reference for the cmtymeet standing v5 state transitions and derived tables.

This is the oracle for src/standing.rs and for the Noir circuits. Nothing here uses floats.
Run `python3 standing_ref.py` to regenerate golden.json; `python3 standing_ref.py --check-model
PATH_TO_model.py` additionally compares the derived tables with the float reference model
(allowed difference: one unit in the last place).

Decided constants (not tunable): punishment given and received weigh 1 each (gamma = 1,
w_out = w_in = 1); every punishment counts fully.
"""
import json
import sys

Q = 1 << 16
HALF = Q >> 1
ONE = 1 << 60
LN2 = 799144290325165979  # round(ln 2 * 2^60)
TRUST_ENTRIES = 65
TABLE_PAD = 64

DEFAULTS = dict(
    c0=3, h_A=14, h_G=14, n_half=25, n_c=60,
    e_q=Q // 4, r_max=40, r_age=2, c_max_q=int(0.8 * Q), c_vet=30, age_vet=60,
    boost_q=Q, boost_days=30, slope_q=4 * Q, mid_q=int(0.75 * Q),
    kappa_q=2 * Q, loan_use_q=0,
)
# Safe ranges (inclusive) enforced by the policy validator.
RANGES = dict(
    c0=(1, 16), h_A=(1, 64), h_G=(1, 64), n_half=(5, 200), n_c=(10, 200),
    e_q=(0, Q), r_max=(1, 200), r_age=(0, 16), c_max_q=(0, int(0.9 * Q)),
    c_vet=(1, 200), age_vet=(1, 365), boost_q=(0, 2 * Q), boost_days=(0, 90),
    slope_q=(Q, 8 * Q), mid_q=(Q // 4, 3 * Q), kappa_q=(Q // 2, 6 * Q),
    loan_use_q=(1, Q),
)


def exp_neg(x):
    """e^(-x) for x >= 0 in Q60 (x and result are Q60 integers)."""
    n, r = divmod(x, LN2)
    if n >= 100:
        return 0
    s = t = ONE
    for k in range(1, 41):
        t = ((t * r) >> 60) // k
        s = s - t if k & 1 else s + t
    return s >> n


def clean_factor(n_half):
    return exp_neg(LN2 // n_half) >> 44  # floor(Q * 2^(-1/n))


def decay_table(h):
    out = [(exp_neg(LN2 * r // h) + (1 << 43)) >> 44 for r in range(h)]
    return out + [0] * (TABLE_PAD - h)


def trust_table(slope_q, mid_q):
    def logistic(t_q60):  # 1 / (1 + e^(-t))
        if t_q60 >= 0:
            return (ONE << 60) // (ONE + exp_neg(t_q60))
        e = exp_neg(-t_q60)
        return (e << 60) // (ONE + e)

    f0 = logistic(-(slope_q * mid_q) << 28)
    den = ONE - f0
    out = []
    for i in range(TRUST_ENTRIES):
        t = (slope_q * (i * (Q // 8) - mid_q)) << 28
        num = ONE - logistic(t)
        v = (num * Q * 2 + den) // (2 * den)
        out.append(max(0, min(Q, v)))
    out[0] = Q
    return out


def validate(p):
    for k, (lo, hi) in RANGES.items():
        if not lo <= p[k] <= hi:
            raise ValueError(k)


class Policy:
    def __init__(self, **over):
        p = dict(DEFAULTS)
        p.update(over)
        if p["loan_use_q"] == 0:
            p["loan_use_q"] = Q // 4
        validate(p)
        self.p = p
        self.factor = clean_factor(p["n_half"])
        self.g_table = decay_table(p["h_G"])
        self.a_table = decay_table(p["h_A"])
        self.trust = trust_table(p["slope_q"], p["mid_q"])

    def fields(self):
        """Canonical field list hashed (with a domain) into the policy digest."""
        p = self.p
        keys = ["c0", "h_A", "h_G", "n_half", "n_c", "e_q", "r_max", "r_age", "c_max_q", "c_vet",
                "age_vet", "boost_q", "boost_days", "slope_q", "mid_q", "kappa_q", "loan_use_q"]
        return [p[k] for k in keys] + [self.factor] + self.trust + self.g_table + self.a_table


def decay(x, days, h, table):
    if days <= 0 or x == 0:
        return x
    qd, r = divmod(days, h)
    if qd >= 31:
        return 0
    return ((x >> qd) * table[r]) >> 16


class State:
    FIELDS = ("G", "A", "C", "Pr", "Pg", "Lc", "day", "joined")

    def __init__(self, day, a0_q):
        self.G = self.C = self.Pr = self.Pg = self.Lc = 0
        self.A = a0_q
        self.day = self.joined = day

    def dump(self):
        return {k: getattr(self, k) for k in self.FIELDS}


def advance(st, day, P):
    d = day - st.day
    if d > 0:
        st.G = decay(st.G, d, P.p["h_G"], P.g_table)
        st.A = decay(st.A, d, P.p["h_A"], P.a_table)
        st.day = day


def mul_up(x, f):
    return 0 if x == 0 else -((-x * f) >> 16)


def clean(st, P):
    st.Pr = mul_up(st.Pr, P.factor)
    st.Pg = mul_up(st.Pg, P.factor)
    st.C = st.C - st.C // P.p["n_c"] + Q


def answer_received(st, P):
    st.G += Q
    if P.p["boost_q"] and st.day - st.joined < P.p["boost_days"]:
        st.G += P.p["boost_q"]
    clean(st, P)


def answer_given(st, P):
    st.G += P.p["e_q"]
    clean(st, P)


def unanswered(st, P):
    d = P.p["loan_use_q"]
    st.A = st.A - d if st.A > d else 0


def group_credit(st, credit_q):
    st.G += credit_q


def punished(st, established):
    st.Pr += Q
    st.Lc += 1
    if established and st.C >= Q:
        st.C -= Q


def punish_given(st):
    st.Pg += Q
    st.Lc += 1


def veteran(st, P):
    p = P.p
    f = min(Q, st.C // p["c_vet"], ((st.day - st.joined) << 16) // p["age_vet"])
    return (p["c_max_q"] * f) >> 16


def trust(st, P):
    ex = st.Pr + st.Pg - veteran(st, P)
    if ex <= 0:
        return Q
    i = (ex * 8 + HALF) >> 16
    return P.trust[min(i, 64)]


def reach(st, P):
    p = P.p
    r = ((p["kappa_q"] * st.G) >> 16) + st.A
    ceiling = (p["c0"] - 1 + p["r_age"] * (st.day - st.joined)) << 16
    return min(r, p["r_max"] << 16, ceiling)


def cap(st, P):
    return 1 + ((trust(st, P) * reach(st, P) + (1 << 31)) >> 32)


def run(P, a0_q, script):
    """script: list of (op, arg). Returns list of (state, cap) after each step."""
    st = State(0, a0_q)
    out = []
    for op, arg in script:
        if op == "day":
            advance(st, arg, P)
        elif op == "recv":
            answer_received(st, P)
        elif op == "give":
            answer_given(st, P)
        elif op == "miss":
            unanswered(st, P)
        elif op == "credit":
            group_credit(st, arg)
        elif op == "punished":
            punished(st, bool(arg))
        elif op == "punish_given":
            punish_given(st)
        else:
            raise ValueError(op)
        out.append({"step": [op, arg], "state": st.dump(), "cap": cap(st, P)})
    return out


SCRIPTS = {
    "newcomer_spam": [["miss", 0]] * 6 + [["day", 3], ["miss", 0]],
    "sociable": [["recv", 0], ["give", 0]] * 12 + [["day", 20], ["punish_given", 0], ["recv", 0]],
    "violator_veteran": [["recv", 0]] * 20 + [["day", 70], ["punished", 1], ["punished", 0],
                                              ["punished", 0], ["recv", 0], ["day", 140]],
    "established": [["day", 0], ["recv", 0], ["punished", 1], ["punished", 1], ["punished", 0],
                    ["credit", 32768]],
    "absent_returns": [["punished", 0], ["punished", 0], ["day", 730], ["recv", 0]],
}
PARAM_SETS = {
    "default": {},
    "fast": dict(n_half=10, h_G=7, h_A=7, slope_q=2 * Q, mid_q=Q, kappa_q=3 * Q),
    "noboost": dict(boost_q=0),
    "slow": dict(n_half=50, h_G=28, h_A=28, c_max_q=0, loan_use_q=Q // 8),
}


def vectors():
    out = {"Q": Q, "ranges": RANGES, "defaults": DEFAULTS, "defaults_resolved": Policy().p, "sets": {}}
    for name, over in PARAM_SETS.items():
        P = Policy(**over)
        a0 = (P.p["c0"] - 1) * Q
        out["sets"][name] = {
            "params": P.p, "factor": P.factor, "trust": P.trust,
            "g_table": P.g_table, "a_table": P.a_table, "a0_q": a0,
            "fields_len": len(P.fields()),
            "scripts": {k: run(P, a0, s) for k, s in SCRIPTS.items()},
        }
    return out


def check_model(path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("m", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    worst = 0
    for name, over in PARAM_SETS.items():
        P = Policy(**over)
        mp = m.Params(N_half=P.p["n_half"], h_G=P.p["h_G"], h_A=P.p["h_A"], s=P.p["slope_q"] / Q,
                      L50=P.p["mid_q"] / Q)
        for a, b in zip(P.trust, mp.T_TABLE):
            worst = max(worst, abs(a - b))
        worst = max(worst, abs(P.factor - m.clean_factor_q(mp, 0)))
        for a, b in zip(P.g_table[:P.p["h_G"]], m.decay_table(P.p["h_G"])):
            worst = max(worst, abs(a - b))
    print("max difference vs model.py (ulp):", worst)
    assert worst <= 1


if __name__ == "__main__":
    here = __file__.rsplit("/", 1)[0] if "/" in __file__ else "."
    if "--check-model" in sys.argv:
        check_model(sys.argv[sys.argv.index("--check-model") + 1])
    with open(here + "/golden.json", "w") as f:
        json.dump(vectors(), f, indent=1, sort_keys=True)
        f.write("\n")
