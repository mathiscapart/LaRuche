"""Tests du classifieur comportemental + matrice de confusion (US-30).

Validation sur un jeu de sessions étiquetées représentatives (Hydra, Nikto,
bot, humain). La validation > 85% sur logs réels se fera en J2 ; ici on vérifie
la cohérence des seuils et le calcul de la matrice.
"""

from datetime import UTC, datetime, timedelta

from analyzer.classifier import (
    BehaviorClassifier,
    confusion_matrix,
    matrix_metrics,
    session_features,
)

_BASE = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _ev(offset_s, event_type="request", path=None, is_scanner=False):
    ts = (_BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    payload: dict = {}
    if path:
        payload["path"] = path
    if is_scanner:
        payload["is_scanner"] = True
    return {"timestamp": ts, "event_type": event_type, "src_ip": "45.33.32.156", "payload": payload}


def _bruteforcer(n=20):
    return [_ev(i * 0.2, "credential_attempt", "/wp-login.php") for i in range(n)]


def _scanner(n=30):
    return [_ev(i * 0.3, "request", f"/path{i}", is_scanner=True) for i in range(n)]


def _bot(n=40):
    return [_ev(i * 0.4, "request", "/xmlrpc.php") for i in range(n)]


def _human():
    offsets_paths = [(0, "/"), (3, "/wp-login.php"), (12, "/"), (16, "/about"), (35, "/contact")]
    return [_ev(o, "request", p) for o, p in offsets_paths]


def test_each_profile_classified() -> None:
    clf = BehaviorClassifier()
    assert clf.classify_session(_bruteforcer()) == "bruteforcer"
    assert clf.classify_session(_scanner()) == "scanner"
    assert clf.classify_session(_bot()) == "bot"
    assert clf.classify_session(_human()) == "human"


def test_features_are_chiffres() -> None:
    f = session_features(_bruteforcer())
    assert f["n_auth"] == 20
    assert f["auth_ratio"] == 1.0
    assert f["timing_cv"] < 0.35  # cadence régulière


def test_confusion_matrix_precision_above_85() -> None:
    clf = BehaviorClassifier()
    dataset = [
        ("bruteforcer", _bruteforcer(20)),
        ("bruteforcer", _bruteforcer(12)),
        ("scanner", _scanner(30)),
        ("scanner", _scanner(15)),
        ("bot", _bot(40)),
        ("bot", _bot(60)),
        ("human", _human()),
        ("human", _human()),
    ]
    labeled = [(label, clf.classify_session(events)) for label, events in dataset]
    matrix = confusion_matrix(labeled)
    metrics = matrix_metrics(matrix)
    assert metrics["accuracy"] >= 0.85
    # chaque profil a une précision exploitable
    for profile in ("bruteforcer", "scanner", "bot", "human"):
        assert metrics["per_profile"][profile]["f1"] >= 0.85
