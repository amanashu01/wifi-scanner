from netguard import password


def test_common_password_is_very_weak():
    r = password.analyze("password")
    assert r["is_common"] and r["score"] <= 15
    assert any(f["level"] == "bad" for f in r["findings"])


def test_personal_info_is_detected():
    r = password.analyze("Ashutosh1998!", {"name": "Ashutosh Singh", "dob": "1998-05-10"})
    assert "ashutosh" in r["personal_matches"]
    assert "1998" in r["personal_matches"]
    assert r["score"] <= 40


def test_leet_personal_info_detected():
    r = password.analyze("4shut0sh", {"name": "ashutosh"})
    assert "ashutosh" in r["personal_matches"]


def test_strong_password_scores_high():
    r = password.analyze("Tr0ub4dour&3xplos!on-Quokka")
    assert r["score"] >= 70 and r["verdict"] in ("Strong", "Very strong")
    assert not r["personal_matches"]


def test_crack_times_present_and_ordered():
    r = password.analyze("abc")
    assert len(r["crack_times"]) == 4
    assert r["crack_times"][-1]["time"] == "instantly"   # fast GPU cracks "abc" instantly


def test_empty_password_errors():
    assert "error" in password.analyze("")


def test_generate_passphrase():
    g = password.generate("passphrase", words=4, add_number=True)
    assert g["password"].count("-") == 4          # 4 words + number
    assert g["entropy_bits"] > 40


def test_generate_random_has_all_classes():
    g = password.generate("random", length=16)
    pw = g["password"]
    assert len(pw) == 16
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)
