"""
Password strength lab
=====================
Helps a learner understand what makes a password weak, entirely offline.

Two things it does:

  analyze(password, personal_info)
      Scores a password and explains every weakness in plain language:
      length, character variety, an entropy estimate, whether it is a known
      leaked password, and - importantly - whether it is built from the user's
      own personal details (name, date of birth, pet, etc.). Weak, guessable
      passwords are the reason attackers succeed, so seeing *why* a password is
      weak is the whole lesson.

  generate(...)
      Produces strong passwords: a random-character one and a "passphrase"
      built from the EFF diceware word list.

Everything runs locally. No password is stored, logged or sent anywhere.
"""

import math
import re
import secrets
from datetime import date
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"

# Size of each character pool, used for the entropy estimate.
POOLS = {"lower": 26, "upper": 26, "digit": 10, "symbol": 33}

# Common keyboard walks and sequences that attackers try first.
SEQUENCES = ["qwerty", "asdf", "zxcv", "qwertyuiop", "abcdefghijklmnopqrstuvwxyz",
             "0123456789", "password", "letmein", "admin", "welcome"]

# How many guesses per second different attackers can make. Used to turn an
# entropy estimate into a "time to crack" people can relate to.
ATTACK_SPEEDS = [
    ("Online, rate-limited (10/s)", 10),
    ("Online, no rate limit (1k/s)", 1_000),
    ("Stolen hashes, slow hash e.g. bcrypt (10k/s)", 10_000),
    ("Stolen hashes, fast GPU on a fast hash e.g. MD5 (100 billion/s)", 100_000_000_000),
]

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                      "7": "t", "8": "b", "@": "a", "$": "s", "!": "i"})


def _load_lines(name):
    try:
        return Path(DATA / name).read_text(encoding="utf-8", errors="ignore").splitlines()
    except FileNotFoundError:
        return []


class _Lists:
    """Lazily loaded word lists (loaded once, on first use)."""
    def __init__(self):
        self._common = None
        self._diceware = None

    @property
    def common(self):
        if self._common is None:
            self._common = {p.strip().lower() for p in _load_lines("common_passwords.txt") if p.strip()}
        return self._common

    @property
    def diceware(self):
        if self._diceware is None:
            words = []
            for line in _load_lines("eff_large_wordlist.txt"):
                parts = line.split()
                words.append(parts[-1] if parts else line.strip())
            # sensible fallback if the file is missing
            self._diceware = [w for w in words if w] or [
                "correct", "horse", "battery", "staple", "orange", "planet",
                "river", "silver", "cactus", "nebula", "anchor", "velvet"]
        return self._diceware


_lists = _Lists()


# ----------------------------------------------------------------------------
# Personal-info matching
# ----------------------------------------------------------------------------
def _personal_tokens(info):
    """Turn the user's details into the words an attacker would try first.

    Reusing your name, birth year or pet's name is the single most common
    reason a password is guessable, so we build the same candidate list a
    targeted guess would and check the password against it.
    """
    tokens = set()

    def add(value):
        v = str(value or "").strip().lower()
        if len(v) >= 2:
            tokens.add(v)
            tokens.update(re.split(r"[\s\-_.@]+", v))   # split "John Smith" etc.

    for key in ("name", "nickname", "partner", "child", "pet", "employer",
                "city", "favorite_team", "username", "email"):
        add(info.get(key))

    # Dates: pull out day / month / year and common 2- and 4-digit forms.
    for key in ("dob", "anniversary"):
        raw = str(info.get(key) or "")
        for num in re.findall(r"\d+", raw):
            tokens.add(num)
            if len(num) == 4:            # a year -> also its last two digits
                tokens.add(num[2:])
    # A plausible range of birth years, so "Anna1990" is caught even without a DOB.
    for extra in info.get("extra_words", []):
        add(extra)

    return {t for t in tokens if len(t) >= 2}


def _find_personal_matches(password, info):
    pw = password.lower()
    pw_deleet = pw.translate(LEET)
    matches = []
    for token in _personal_tokens(info):
        if token in pw or (token.isalpha() and token in pw_deleet):
            matches.append(token)
    return sorted(set(matches), key=len, reverse=True)


# ----------------------------------------------------------------------------
# Entropy
# ----------------------------------------------------------------------------
def _char_classes(password):
    classes = set()
    if re.search(r"[a-z]", password): classes.add("lower")
    if re.search(r"[A-Z]", password): classes.add("upper")
    if re.search(r"\d", password): classes.add("digit")
    if re.search(r"[^A-Za-z0-9]", password): classes.add("symbol")
    return classes


def _entropy_bits(password):
    """A deliberately simple 'ideal' entropy: log2(poolsize) per character.

    This is the best case (a truly random password from that pool). Pattern
    penalties below reflect that real passwords are far from random.
    """
    if not password:
        return 0.0
    pool = sum(POOLS[c] for c in _char_classes(password)) or 1
    return len(password) * math.log2(pool)


def _humanize_seconds(seconds):
    if seconds < 1:
        return "instantly"
    units = [("years", 31_536_000), ("days", 86_400), ("hours", 3_600),
             ("minutes", 60), ("seconds", 1)]
    if seconds > 31_536_000 * 1e6:
        exp = int(math.log10(seconds / 31_536_000))
        return f"~10^{exp} years (effectively forever)"
    for name, size in units:
        if seconds >= size:
            return f"{seconds / size:.1f} {name}"
    return "instantly"


def _crack_times(effective_bits):
    guesses = 2 ** effective_bits / 2       # expected guesses = half the space
    out = []
    for label, rate in ATTACK_SPEEDS:
        out.append({"attacker": label, "time": _humanize_seconds(guesses / rate)})
    return out


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------
def analyze(password, personal_info=None):
    info = personal_info or {}
    if not isinstance(password, str) or not password:
        return {"error": "Provide a password to analyze."}
    if len(password) > 256:
        return {"error": "Password too long to analyze (max 256 characters)."}

    classes = _char_classes(password)
    ideal_bits = _entropy_bits(password)
    lower = password.lower()

    findings = []      # {level: good|warn|bad, text}
    penalty = 0.0      # bits removed from the ideal estimate

    def add(level, text):
        findings.append({"level": level, "text": text})

    # length
    n = len(password)
    if n < 8:
        add("bad", f"Only {n} characters. Aim for at least 12-16.")
    elif n < 12:
        add("warn", f"{n} characters. 12 or more is much safer.")
    else:
        add("good", f"{n} characters - good length.")

    # variety
    missing = [c for c in ("lower", "upper", "digit", "symbol") if c not in classes]
    names = {"lower": "lowercase", "upper": "uppercase", "digit": "digits", "symbol": "symbols"}
    if missing:
        add("warn", "Missing " + ", ".join(names[m] for m in missing) + ".")
    else:
        add("good", "Uses lowercase, uppercase, digits and symbols.")

    # known leaked password
    if lower in _lists.common:
        add("bad", "This is one of the most common leaked passwords. "
                   "It would be tried in the first second of any attack.")
        penalty += ideal_bits * 0.95
    elif lower.translate(LEET) in _lists.common:
        add("bad", "This is a common password with simple letter-to-symbol swaps "
                   "(like a->@). Attackers apply those swaps automatically.")
        penalty += ideal_bits * 0.85

    # personal info. A targeted attacker builds a wordlist from these facts and
    # tries them (with years and symbols) first, so the more of the password
    # they cover, the less its length actually protects it.
    personal = _find_personal_matches(password, info)
    coverage = min(sum(len(p) for p in personal) / n, 1.0) if personal else 0.0
    if personal:
        add("bad", "Contains personal details anyone could find or guess: "
                   + ", ".join(f'"{p}"' for p in personal[:6])
                   + ". A targeted guess tries these combined with years and symbols first.")
        penalty += ideal_bits * min(0.4 + coverage * 0.55, 0.9)

    # sequences / repeats / dates
    if any(s in lower or s[::-1] in lower for s in SEQUENCES):
        add("warn", "Contains a keyboard pattern or dictionary run (e.g. 'qwerty', '1234').")
        penalty += 12
    if re.search(r"(.)\1\1", password):
        add("warn", "Has a character repeated 3+ times in a row.")
        penalty += 6
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[!@#$]?", password):
        add("warn", "Follows the very common 'Word + numbers + symbol' pattern "
                    "that cracking tools generate automatically.")
        penalty += 10
    if re.search(r"(19|20)\d{2}", password):
        add("warn", "Contains a 4-digit year - a small, predictable range.")
        penalty += 4

    effective_bits = max(ideal_bits - penalty, 0.0)

    # score 0-100 from effective entropy (~60 bits considered strong)
    score = max(0, min(100, round(effective_bits / 70 * 100)))
    if lower in _lists.common:
        score = min(score, 15)
    elif personal and max((len(p) for p in personal), default=0) >= 4:
        # a name, year or word from your own details is in here - guessable
        score = min(score, 30)
    verdict = ("Very weak" if score < 20 else "Weak" if score < 40 else
               "Fair" if score < 60 else "Strong" if score < 80 else "Very strong")

    return {
        "length": n,
        "classes": sorted(classes),
        "ideal_entropy_bits": round(ideal_bits, 1),
        "effective_entropy_bits": round(effective_bits, 1),
        "score": score,
        "verdict": verdict,
        "is_common": lower in _lists.common,
        "personal_matches": personal,
        "findings": findings,
        "crack_times": _crack_times(effective_bits),
    }


def generate(mode="passphrase", words=5, length=20, separator="-",
             capitalize=True, add_number=True):
    """Return a strong password plus its entropy estimate."""
    if mode == "passphrase":
        words = max(3, min(int(words), 10))
        pool = _lists.diceware
        chosen = [secrets.choice(pool) for _ in range(words)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]
        pw = (separator or "").join(chosen)
        if add_number:
            pw += (separator or "") + str(secrets.randbelow(90) + 10)
        # entropy = words * log2(listsize); the number adds ~6.5 bits
        bits = words * math.log2(len(pool)) + (add_number * math.log2(90))
    else:  # random characters
        length = max(8, min(int(length), 128))
        alphabet = ("abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789"
                    "!@#$%^&*()-_=+[]{};:,.?")
        # guarantee at least one of each class
        while True:
            pw = "".join(secrets.choice(alphabet) for _ in range(length))
            if _char_classes(pw) == {"lower", "upper", "digit", "symbol"}:
                break
        bits = length * math.log2(len(alphabet))

    return {"password": pw, "entropy_bits": round(bits, 1),
            "crack_times": _crack_times(bits)}
