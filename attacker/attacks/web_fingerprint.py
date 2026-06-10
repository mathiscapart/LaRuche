"""Web technology / CMS fingerprinting for the HTTP scan pipeline.

The goal is to answer one question before any attack: *what is running here?*
We inspect the homepage (headers, cookies, body, ``<meta generator>``) and, for
the strongest candidate, confirm with a couple of marker requests and try to
read a version. The result drives whether ``http_scan`` runs a CMS-aware attack
(WordPress, Joomla, ...) or a generic discovery sweep.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from attacker.attacks.common import HttpResponse, http_request

logger = logging.getLogger(__name__)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CmsSignature:
    """Declarative detection rules for a single CMS / platform."""

    name: str
    # Confidence weight added when *any* of the home-page rules below match.
    header_patterns: tuple[tuple[str, str], ...] = ()  # (header, regex)
    cookie_patterns: tuple[str, ...] = ()  # regex against the Set-Cookie blob
    body_patterns: tuple[str, ...] = ()  # regex against the homepage body
    generator_patterns: tuple[str, ...] = ()  # regex against <meta generator>
    # Confirmation: a request to ``path`` whose body matches ``regex`` (empty
    # regex => any non-404 answer counts). Strong evidence (+40).
    marker_paths: tuple[tuple[str, str], ...] = ()
    # Version disclosure: first capture group of ``regex`` on ``path``'s body.
    version_paths: tuple[tuple[str, str], ...] = ()
    # True for hosted platforms we can detect but should not brute-force.
    hosted: bool = False


@dataclass
class Fingerprint:
    cms: str = ""
    cms_confidence: int = 0
    cms_version: str = ""
    hosted: bool = False
    server: str = ""
    powered_by: str = ""
    title: str = ""
    technologies: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def is_cms(self) -> bool:
        return bool(self.cms)

    @property
    def attackable_cms(self) -> bool:
        return self.is_cms and not self.hosted


# --- CMS signature database ------------------------------------------------
CMS_SIGNATURES: tuple[CmsSignature, ...] = (
    CmsSignature(
        name="WordPress",
        header_patterns=(("link", r"api\.w\.org"), ("x-pingback", r"xmlrpc\.php")),
        cookie_patterns=(r"wordpress_", r"wp-settings"),
        body_patterns=(r"/wp-content/", r"/wp-includes/", r"wp-embed\.min\.js"),
        generator_patterns=(r"WordPress\s*([\d.]+)?",),
        marker_paths=(
            ("/wp-login.php", r"user_login|loginform|wordpress"),
            ("/wp-json/", r'"namespaces"|wp/v2'),
        ),
        version_paths=(
            ("/readme.html", r"Version\s+([\d.]+)"),
            ("/feed/", r"wordpress\.org/\?v=([\d.]+)"),
        ),
    ),
    CmsSignature(
        name="Joomla",
        header_patterns=(),
        cookie_patterns=(r"[0-9a-f]{32}=",),
        body_patterns=(r"/media/system/js/", r"/media/jui/", r"option=com_", r"Joomla"),
        generator_patterns=(r"Joomla!?\s*([\d.]+)?",),
        marker_paths=(
            ("/administrator/", r"joomla|mod-login|com_login|Administration Login"),
            ("/language/en-GB/en-GB.xml", r"<extension|<name>English"),
        ),
        version_paths=(
            (
                "/administrator/manifests/files/joomla.xml",
                r"<version>([\d.]+)</version>",
            ),
            ("/language/en-GB/en-GB.xml", r'version="([\d.]+)"'),
        ),
    ),
    CmsSignature(
        name="Drupal",
        header_patterns=(("x-generator", r"Drupal"), ("x-drupal-cache", r".")),
        cookie_patterns=(r"SESS[0-9a-f]{32}", r"Drupal"),
        body_patterns=(r"/sites/default/files", r"Drupal\.settings", r"drupal\.js"),
        generator_patterns=(r"Drupal\s*([\d.]+)?",),
        marker_paths=(
            ("/user/login", r"user-login|name=.edit-name|Drupal"),
            ("/core/install.php", r"Drupal"),
        ),
        version_paths=(
            ("/CHANGELOG.txt", r"Drupal ([\d.]+),"),
            ("/core/CHANGELOG.txt", r"Drupal ([\d.]+),"),
        ),
    ),
    CmsSignature(
        name="Magento",
        cookie_patterns=(r"frontend=", r"X-Magento", r"mage-"),
        body_patterns=(
            r"/skin/frontend/",
            r"Mage\.Cookies",
            r"/static/version",
            r"Magento",
        ),
        marker_paths=(
            ("/downloader/", r"Magento|Connect Manager"),
            ("/admin/", r"login|Magento"),
        ),
        version_paths=(
            ("/magento_version", r"Magento/([\d.]+)"),
            ("/RELEASE_NOTES.txt", r"([\d]+\.[\d]+\.[\d.]+)"),
        ),
    ),
    CmsSignature(
        name="PrestaShop",
        header_patterns=(("powered-by", r"PrestaShop"),),
        cookie_patterns=(r"PrestaShop-", r"PrestaShop="),
        body_patterns=(r"/themes/", r"prestashop", r"var prestashop"),
        generator_patterns=(r"PrestaShop\s*([\d.]+)?",),
        marker_paths=(("/admin/", r"login|Employee"),),
        version_paths=(("/docs/CHANGELOG.txt", r"v([\d.]+)"),),
    ),
    CmsSignature(
        name="TYPO3",
        cookie_patterns=(r"fe_typo_user", r"be_typo_user"),
        body_patterns=(
            r"/typo3temp/",
            r"/typo3conf/",
            r"This website is powered by TYPO3",
        ),
        generator_patterns=(r"TYPO3\s*([\d.]+)?",),
        marker_paths=(("/typo3/", r"TYPO3|backend|login"),),
    ),
    CmsSignature(
        name="Shopify",
        header_patterns=(("x-shopid", r"."), ("x-shopify-stage", r".")),
        body_patterns=(r"cdn\.shopify\.com", r"Shopify\.theme"),
        hosted=True,
    ),
)

# --- Generic technology fingerprints (informational) -----------------------
_TECH_HEADER_RULES: tuple[tuple[str, str, str], ...] = (
    ("server", r"apache", "Apache"),
    ("server", r"nginx", "nginx"),
    ("server", r"microsoft-iis", "IIS"),
    ("server", r"litespeed", "LiteSpeed"),
    ("server", r"caddy", "Caddy"),
    ("server", r"cloudflare", "Cloudflare"),
    ("x-powered-by", r"php", "PHP"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express/Node.js"),
    ("x-aspnet-version", r".", "ASP.NET"),
    ("x-powered-by", r"servlet|jsp", "Java/Servlet"),
)
_TECH_COOKIE_RULES: tuple[tuple[str, str], ...] = (
    (r"laravel_session", "Laravel"),
    (r"csrftoken|django", "Django"),
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java/Servlet"),
    (r"connect\.sid", "Express/Node.js"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
)
_TECH_BODY_RULES: tuple[tuple[str, str], ...] = (
    (r"jquery", "jQuery"),
    (r"bootstrap(\.min)?\.(css|js)", "Bootstrap"),
    (r"react(\.production)?\.min\.js|__NEXT_DATA__", "React/Next.js"),
    (r"ng-version|angular", "Angular"),
    (r"wp-content", "PHP"),
)


def _search(text: str, pattern: str) -> re.Match[str] | None:
    return re.search(pattern, text or "", re.IGNORECASE)


def _score_homepage(sig: CmsSignature, home: HttpResponse) -> tuple[int, list[str]]:
    score = 0
    evidence: list[str] = []
    cookies = home.header("set-cookie")

    for header, pattern in sig.header_patterns:
        if _search(home.header(header), pattern):
            score += 25
            evidence.append(f"{sig.name}: header {header} ~ /{pattern}/")

    for pattern in sig.cookie_patterns:
        if _search(cookies, pattern):
            score += 25
            evidence.append(f"{sig.name}: cookie ~ /{pattern}/")

    for pattern in sig.body_patterns:
        if _search(home.body, pattern):
            score += 15
            evidence.append(f"{sig.name}: body ~ /{pattern}/")

    generator = _GENERATOR_RE.search(home.body) or [None, ""]
    generator_value = (
        generator[1] if isinstance(generator, list) else generator.group(1)
    )

    for pattern in sig.generator_patterns:
        if _search(generator_value, pattern):
            score += 35
            evidence.append(f"{sig.name}: <meta generator> ~ /{pattern}/")

    return score, evidence


def _confirm_markers(
    sig: CmsSignature,
    base_url: str,
    *,
    timeout: float,
    pause: float,
) -> tuple[int, list[str], list[HttpResponse]]:
    score = 0
    evidence: list[str] = []
    responses: list[HttpResponse] = []
    for path, pattern in sig.marker_paths:
        response = http_request(base_url, path, timeout=timeout, capture_body=True)
        responses.append(response)
        time.sleep(pause)

        if response.status is None or response.status == 404:
            continue

        if not pattern or _search(response.body, pattern):
            score += 40
            evidence.append(f"{sig.name}: {path} -> {response.status} (marker matched)")

    return score, evidence, responses


def _detect_version(
    sig: CmsSignature,
    base_url: str,
    home: HttpResponse,
    *,
    timeout: float,
    pause: float,
) -> str:
    generator = _GENERATOR_RE.search(home.body)
    if generator:
        inline = re.search(r"([\d]+\.[\d.]+)", generator.group(1))
        if inline:
            return inline.group(1)

    for path, pattern in sig.version_paths:
        response = http_request(base_url, path, timeout=timeout, capture_body=True)
        time.sleep(pause)
        if response.status == 200:
            match = _search(response.body, pattern)
            if match:
                return match.group(1)

    return ""


def _detect_technologies(home: HttpResponse) -> list[str]:
    techs: list[str] = []
    cookies = home.header("set-cookie")
    for header, pattern, label in _TECH_HEADER_RULES:
        if _search(home.header(header), pattern) and label not in techs:
            techs.append(label)

    for pattern, label in _TECH_COOKIE_RULES:
        if _search(cookies, pattern) and label not in techs:
            techs.append(label)

    for pattern, label in _TECH_BODY_RULES:
        if _search(home.body, pattern) and label not in techs:
            techs.append(label)

    return techs


def fingerprint(
    base_url: str,
    *,
    request_timeout: float = 10.0,
    pause: float = 0.2,
    home: HttpResponse | None = None,
) -> Fingerprint:
    """Identify the platform behind ``base_url`` (CMS, server, version, stack)."""
    if home is None:
        home = http_request(base_url, "/", timeout=request_timeout, capture_body=True)

    result = Fingerprint(
        server=home.header("server"),
        powered_by=home.header("x-powered-by"),
    )
    title_match = _TITLE_RE.search(home.body)
    if title_match:
        result.title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120]

    # Score every signature on the homepage first (cheap, no extra requests).
    scored: list[tuple[int, list[str], CmsSignature]] = []
    for sig in CMS_SIGNATURES:
        score, evidence = _score_homepage(sig, home)
        if score > 0:
            scored.append((score, evidence, sig))
    scored.sort(key=lambda item: item[0], reverse=True)

    # Confirm the two strongest candidates with marker requests.
    best: tuple[int, CmsSignature] | None = None
    all_evidence: list[str] = []
    for score, evidence, sig in scored[:2]:
        all_evidence.extend(evidence)
        if not sig.hosted:
            confirm_score, confirm_evidence, _ = _confirm_markers(
                sig, base_url, timeout=request_timeout, pause=pause
            )
            score += confirm_score
            all_evidence.extend(confirm_evidence)

        if best is None or score > best[0]:
            best = (score, sig)

    if best is not None and best[0] >= 35:
        score, sig = best
        result.cms = sig.name
        result.cms_confidence = min(score, 100)
        result.hosted = sig.hosted
        if not sig.hosted:
            result.cms_version = _detect_version(
                sig,
                base_url,
                home,
                timeout=request_timeout,
                pause=pause,
            )

    result.evidence = all_evidence
    result.technologies = _detect_technologies(home)
    logger.info(
        "Fingerprint: cms=%s (%d%%) version=%s server=%s tech=%s",
        result.cms or "unknown",
        result.cms_confidence,
        result.cms_version or "?",
        result.server or "?",
        ", ".join(result.technologies) or "-",
    )

    return result
