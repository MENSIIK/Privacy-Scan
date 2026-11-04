"""Core logic for Privacy Scan.

Public website/privacy policy analysis + VirusTotal Public API v3.
This is an educational tool, not a guarantee of website safety.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import re
import socket
import ssl

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup


# ==========================================
# BASIC SETTINGS
# ==========================================

MAX_HTML_BYTES = 1_000_000
MAX_REDIRECTS = 4
REQUEST_TIMEOUT_SECONDS = 7

USER_AGENT = "SchoolPrivacyInfoChecker/2.2"

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_TIMEOUT_SECONDS = 20


# ==========================================
# PRIVACY POLICY SETTINGS
# ==========================================

POLICY_TERMS = (
    "개인정보처리방침",
    "개인정보 처리방침",
    "개인정보 보호정책",
    "privacy policy",
    "privacy notice",
    "privacy statement",
)


TOPIC_PATTERNS = {

    "개인정보 수집 항목": [
        r"개인정보.{0,12}수집.{0,8}항목",
        r"수집하는 개인정보 항목",
        r"수집 항목",
        r"information we collect",
        r"personal information collected",
        r"categories of personal data",
    ],

    "수집 목적": [
        r"수집.{0,20}목적",
        r"수집.{0,15}이용 목적",
        r"처리 목적",
        r"purpose(?:s)? of (?:data )?collection",
        r"purpose(?:s)? of processing",
    ],

    "보관 기간": [
        r"보유.{0,15}기간",
        r"보관.{0,15}기간",
        r"보유.{0,15}이용 기간",
        r"retention period",
        r"retain.{0,40}as long",
    ],

    "제3자 제공": [
        r"제3자.{0,15}제공",
        r"제공받는 자",
        r"third parties",
        r"third.party sharing",
    ],

    "개인정보 처리 위탁": [
        r"개인정보.{0,15}처리.{0,10}위탁",
        r"처리업무.{0,10}위탁",
        r"위탁.{0,15}(?:업체|수탁자|업무|내용)",
        r"data processors",
        r"processing by (?:a )?third.party",
    ],

    "삭제·파기 방법": [
        r"파기.{0,15}(?:절차|방법|합니다|한다)",
        r"삭제.{0,15}(?:방법|절차|합니다|한다)",
        r"deletion",
        r"destroy.{0,30}personal data",
    ],

    "정보주체 권리 및 행사 방법": [
        r"정보주체.{0,25}권리",
        r"권리.{0,15}행사",
        r"열람.{0,20}정정.{0,20}삭제",
        r"data subject rights",
        r"right to access",
        r"exercise.{0,20}rights",
    ],

    "개인정보 보호책임자·문의처": [
        r"개인정보\s*보호책임자",
        r"개인정보보호\s*책임자",
        r"개인정보.{0,10}보호.{0,10}담당자",
        r"privacy officer",
        r"data protection officer",
        r"privacy contact",
    ],

    "국외 이전": [
        r"국외.{0,15}이전",
        r"국외로.{0,10}이전",
        r"international data transfers?",
        r"cross.border data transfer",
        r"transfer.{0,25}(?:overseas|outside the country)",
    ],

    "쿠키·자동 수집 정보": [
        r"쿠키",
        r"자동 수집.{0,20}(?:장치|정보|항목)",
        r"행태정보",
        r"cookies?",
        r"tracking technologies",
        r"web beacons?",
    ],

    "안전성 확보 조치": [
        r"안전성 확보.{0,10}조치",
        r"관리적.{0,20}기술적.{0,20}(?:조치|보호조치)",
        r"기술적.{0,20}관리적.{0,20}(?:조치|보호조치)",
        r"technical and organizational measures",
        r"security measures",
    ],
}


# ==========================================
# EXCEPTIONS AND DATA CLASSES
# ==========================================

class ScanError(Exception):
    """Website scanning error."""


class VirusTotalError(Exception):
    """Safe, user-facing VirusTotal API error."""


class VirusTotalNotFoundError(VirusTotalError):
    """VirusTotal does not have a report for this URL yet."""


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    content_type: str
    html: str


@dataclass
class TopicResult:
    topic: str
    found: bool
    evidence: str = ""
    matched_phrase: str = ""


# ==========================================
# URL VALIDATION
# ==========================================

def normalize_url(raw_url: str) -> str:
    """Normalize URL and reject unsafe URL syntax."""

    value = (raw_url or "").strip()

    if not value:
        raise ScanError("웹사이트 주소를 입력해 주세요.")

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        port = parsed.port

    except ValueError as exc:
        raise ScanError(
            "주소의 포트 형식이 올바르지 않습니다."
        ) from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScanError(
            "http 또는 https 주소만 분석할 수 있습니다."
        )

    if not parsed.hostname:
        raise ScanError(
            "올바른 웹사이트 주소를 입력해 주세요."
        )

    if parsed.username is not None or parsed.password is not None:
        raise ScanError(
            "사용자 이름이나 비밀번호가 포함된 주소는 허용하지 않습니다."
        )

    if parsed.fragment:
        parsed = parsed._replace(fragment="")

    host = parsed.hostname.rstrip(".").lower()

    if (
        host in {"localhost", "localhost.localdomain"}
        or host.endswith(
            (".localhost", ".local", ".internal")
        )
    ):
        raise ScanError(
            "로컬 네트워크 주소는 분석할 수 없습니다."
        )

    # Reject private, loopback and reserved IP literals.
    try:
        literal_ip = ipaddress.ip_address(host)

    except ValueError:
        literal_ip = None

    if literal_ip is not None and not literal_ip.is_global:
        raise ScanError(
            "공개 인터넷 IP 주소만 분석할 수 있습니다."
        )

    default_port = (
        443 if parsed.scheme.lower() == "https" else 80
    )

    if port is not None and port != default_port:
        raise ScanError(
            "HTTP 80 또는 HTTPS 443 포트만 분석할 수 있습니다."
        )

    is_ipv6 = ":" in host
    authority_host = f"[{host}]" if is_ipv6 else host

    path = parsed.path or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            authority_host,
            path,
            parsed.query,
            "",
        )
    )


# ==========================================
# PUBLIC IP VALIDATION
# ==========================================

def _resolve_public_addresses(
    host: str,
    port: int,
) -> list[str]:

    try:
        literal_ip = ipaddress.ip_address(host)
        addresses = [str(literal_ip)]

    except ValueError:
        try:
            infos = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
            )

        except socket.gaierror as exc:
            raise ScanError(
                "도메인 주소를 확인할 수 없습니다. "
                "주소를 다시 확인해 주세요."
            ) from exc

        addresses = list(
            dict.fromkeys(
                info[4][0] for info in infos
            )
        )

    if not addresses:
        raise ScanError(
            "도메인 주소를 확인할 수 없습니다."
        )

    for address in addresses:
        try:
            parsed_ip = ipaddress.ip_address(address)

        except ValueError as exc:
            raise ScanError(
                "도메인 주소를 안전하게 확인할 수 없습니다."
            ) from exc

        if not parsed_ip.is_global:
            raise ScanError(
                "공개 인터넷에서 접근할 수 있는 "
                "웹사이트 주소만 분석할 수 있습니다."
            )

    return addresses


# ==========================================
# SAFE HTTP CONNECTION
# ==========================================

class _PinnedHTTPConnection(
    http.client.HTTPConnection
):

    def __init__(
        self,
        host: str,
        port: int,
        connect_ip: str,
        timeout: float,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
        )

        self._connect_ip = connect_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._connect_ip, self.port),
            self.timeout,
        )


class _PinnedHTTPSConnection(
    http.client.HTTPSConnection
):

    def __init__(
        self,
        host: str,
        port: int,
        connect_ip: str,
        timeout: float,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )

        self._connect_ip = connect_ip

    def connect(self):
        raw_sock = socket.create_connection(
            (self._connect_ip, self.port),
            self.timeout,
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_sock,
                server_hostname=self.host,
            )

        except Exception:
            raw_sock.close()
            raise


def _host_header(
    host: str,
    port: int,
    scheme: str,
) -> str:

    safe_host = f"[{host}]" if ":" in host else host

    default_port = (
        443 if scheme == "https" else 80
    )

    return (
        safe_host
        if port == default_port
        else f"{safe_host}:{port}"
    )


# ==========================================
# FETCH PUBLIC HTML
# ==========================================

def fetch_public_html(raw_url: str) -> FetchResult:
    """Fetch public HTML with redirect and network safety checks."""

    original = normalize_url(raw_url)
    current = original

    for redirect_count in range(MAX_REDIRECTS + 1):

        current = normalize_url(current)
        parsed = urlsplit(current)

        host = parsed.hostname or ""
        scheme = parsed.scheme

        port = parsed.port or (
            443 if scheme == "https" else 80
        )

        addresses = _resolve_public_addresses(
            host,
            port,
        )

        connect_ip = addresses[0]

        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        if scheme == "https":
            connection = _PinnedHTTPSConnection(
                host,
                port,
                connect_ip,
                REQUEST_TIMEOUT_SECONDS,
            )

        else:
            connection = _PinnedHTTPConnection(
                host,
                port,
                connect_ip,
                REQUEST_TIMEOUT_SECONDS,
            )

        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": _host_header(
                        host,
                        port,
                        scheme,
                    ),
                    "User-Agent": USER_AGENT,
                    "Accept": (
                        "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"
                    ),
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )

            response = connection.getresponse()

            status = response.status
            location = response.getheader("Location")

            content_type = (
                response.getheader("Content-Type") or ""
            ).lower()

            # Redirect
            if status in {301, 302, 303, 307, 308}:

                response.read(1024)

                if not location:
                    raise ScanError(
                        "웹사이트가 리디렉션했지만 "
                        "이동 주소를 제공하지 않았습니다."
                    )

                if redirect_count >= MAX_REDIRECTS:
                    raise ScanError(
                        "웹사이트 이동 횟수가 너무 많습니다."
                    )

                current = urljoin(current, location)
                continue

            if status < 200 or status >= 400:
                raise ScanError(
                    f"웹사이트가 HTTP {status} 응답을 반환했습니다. "
                    "접근이 제한되었을 수 있습니다."
                )

            body = response.read(
                MAX_HTML_BYTES + 1
            )

            if len(body) > MAX_HTML_BYTES:
                raise ScanError(
                    "페이지 크기가 너무 커서 분석을 중단했습니다. "
                    "(최대 1MB)"
                )

            content_type_main = (
                content_type.split(";", 1)[0].strip()
            )

            looks_like_html = (
                b"<html" in body[:4096].lower()
                or b"<!doctype html" in body[:4096].lower()
            )

            if (
                content_type_main
                not in {
                    "text/html",
                    "application/xhtml+xml",
                }
                and not (
                    not content_type_main
                    and looks_like_html
                )
            ):
                raise ScanError(
                    "HTML 웹페이지가 아닌 응답이라 분석할 수 없습니다."
                )

            charset = (
                response.msg.get_content_charset()
                if response.msg
                else None
            )

            try:
                html = body.decode(
                    charset or "utf-8",
                    errors="replace",
                )

            except LookupError:
                html = body.decode(
                    "utf-8",
                    errors="replace",
                )

            return FetchResult(
                requested_url=original,
                final_url=current,
                status=status,
                content_type=(
                    content_type or "(응답 헤더에 없음)"
                ),
                html=html,
            )

        except ScanError:
            raise

        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
            TimeoutError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise ScanError(
                "사이트에 접속하지 못했습니다. "
                "주소, 연결 상태 또는 사이트의 자동 접속 제한을 "
                "확인해 주세요."
            ) from exc

        finally:
            connection.close()

    raise ScanError(
        "웹사이트에 접속하지 못했습니다."
    )


# ==========================================
# PRIVACY POLICY LINK DETECTION
# ==========================================

def find_privacy_policy_links(
    html: str,
    page_url: str,
) -> list[dict[str, str]]:

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    base_host = (
        urlsplit(page_url).hostname or ""
    ).lower()

    found = []
    seen = set()

    for anchor in soup.find_all(
        "a",
        href=True,
    ):

        href = (
            anchor.get("href") or ""
        ).strip()

        if not href or href.startswith(
            ("#", "mailto:", "tel:", "javascript:")
        ):
            continue

        visible = anchor.get_text(
            " ",
            strip=True,
        )

        aria = str(
            anchor.get("aria-label") or ""
        )

        title = str(
            anchor.get("title") or ""
        )

        combined = (
            f"{visible} {aria} {title} {href}"
        ).lower()

        normalized_combined = re.sub(
            r"[-_]+",
            " ",
            combined,
        )

        if not any(
            term.lower() in combined
            or term.lower() in normalized_combined
            for term in POLICY_TERMS
        ):
            continue

        absolute = urljoin(
            page_url,
            href,
        )

        try:
            normalized = normalize_url(
                absolute
            )

        except ScanError:
            continue

        host = (
            urlsplit(normalized).hostname or ""
        ).lower()

        if normalized in seen:
            continue

        seen.add(normalized)

        found.append({
            "url": normalized,
            "label": (
                visible
                or aria
                or title
                or "개인정보 처리방침 관련 링크"
            ),
            "same_host": (
                "true" if host == base_host else "false"
            ),
        })

    return found


# ==========================================
# EVIDENCE EXTRACTION
# ==========================================

def _evidence_context(
    text: str,
    start: int,
    end: int,
    radius: int = 95,
) -> str:

    left = max(
        0,
        start - radius,
    )

    right = min(
        len(text),
        end + radius,
    )

    excerpt = text[left:right].strip()

    if left > 0:
        excerpt = "…" + excerpt

    if right < len(text):
        excerpt += "…"

    return excerpt


# ==========================================
# ANALYZE 11 PRIVACY TOPICS
# ==========================================

def analyze_policy_text(
    html: str,
) -> list[TopicResult]:

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    for tag in soup(
        ["script", "style", "noscript", "svg"]
    ):
        tag.decompose()

    text = re.sub(
        r"\s+",
        " ",
        soup.get_text(" ", strip=True),
    ).strip()

    results = []

    for topic, patterns in TOPIC_PATTERNS.items():

        evidence = ""
        matched_phrase = ""

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            )

            if match:
                matched_phrase = (
                    match.group(0).strip()
                )

                evidence = _evidence_context(
                    text,
                    match.start(),
                    match.end(),
                )

                break

        results.append(
            TopicResult(
                topic=topic,
                found=bool(matched_phrase),
                evidence=evidence,
                matched_phrase=matched_phrase,
            )
        )

    return results


# ==========================================
# COMPLETE WEBSITE ANALYSIS
# ==========================================

def analyze_website(raw_url: str) -> dict:

    homepage = fetch_public_html(raw_url)

    homepage_parsed = urlsplit(
        homepage.final_url
    )

    homepage_host = (
        homepage_parsed.hostname or ""
    ).lower()

    is_https = (
        homepage_parsed.scheme == "https"
    )

    normalized_path = (
        homepage_parsed.path.lower()
        .replace("-", "")
        .replace("_", "")
    )

    path_is_policy = any(
        term.replace(" ", "") in normalized_path
        for term in (
            "privacy",
            "개인정보처리방침",
        )
    )

    policy_error = None

    if path_is_policy:

        policy = homepage

        links = [{
            "url": homepage.final_url,
            "label": "입력한 페이지 자체를 정책 페이지로 분석",
            "same_host": "true",
        }]

    else:

        links = find_privacy_policy_links(
            homepage.html,
            homepage.final_url,
        )

        internal_links = [
            item
            for item in links
            if item["same_host"] == "true"
        ]

        policy = None

        for candidate in internal_links[:3]:

            try:
                policy = fetch_public_html(
                    candidate["url"]
                )
                break

            except ScanError as exc:
                policy_error = str(exc)

        if policy is None and internal_links and policy_error:
            policy_error = (
                "정책 링크는 찾았지만 자동으로 열지 못했습니다: "
                + policy_error
            )

    policy_results = (
        analyze_policy_text(policy.html)
        if policy
        else []
    )

    return {
        "requested_url": homepage.requested_url,
        "final_url": homepage.final_url,
        "status": homepage.status,
        "is_https": is_https,
        "policy_links": links,
        "policy": policy,
        "policy_error": policy_error,
        "topic_results": policy_results,
        "homepage_host": homepage_host,
    }


# ==========================================
# VIRUSTOTAL PUBLIC API V3
# ==========================================


def virustotal_url_id(raw_url: str) -> str:
    """Create an unpadded URL-safe Base64 URL identifier."""

    normalized = normalize_url(raw_url)

    return base64.urlsafe_b64encode(
        normalized.encode("utf-8")
    ).decode("ascii").rstrip("=")


def _virustotal_request(
    method: str,
    endpoint: str,
    api_key: str,
    **kwargs,
) -> dict:
    """Send one VirusTotal API request and handle common errors."""

    key = (api_key or "").strip()

    if not key:
        raise VirusTotalError(
            "VirusTotal API 키가 설정되지 않았습니다. "
            "Streamlit Secrets에 VIRUSTOTAL_API_KEY를 등록해 주세요."
        )

    headers = {
        "x-apikey": key,
        "accept": "application/json",
        "user-agent": "PrivacyScanSchoolProject/2.2",
    }

    try:
        response = requests.request(
            method=method.upper(),
            url=(
                f"{VIRUSTOTAL_BASE_URL}"
                f"{endpoint}"
            ),
            headers=headers,
            timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
            allow_redirects=False,
            **kwargs,
        )

    except requests.Timeout as exc:
        raise VirusTotalError(
            "VirusTotal 응답 시간이 초과되었습니다. "
            "잠시 후 다시 시도해 주세요."
        ) from exc

    except requests.RequestException as exc:
        raise VirusTotalError(
            "VirusTotal 서버에 연결하지 못했습니다. "
            "네트워크 상태를 확인해 주세요."
        ) from exc

    # No existing report
    if response.status_code == 404:
        raise VirusTotalNotFoundError(
            "VirusTotal에서 이 URL의 기존 보고서를 찾지 못했습니다. "
            "새 검사를 요청할 수 있습니다."
        )

    # Invalid API key
    if response.status_code == 401:
        raise VirusTotalError(
            "API 키가 올바르지 않습니다. "
            "Streamlit Secrets의 키를 확인해 주세요."
        )

    # Permission error
    if response.status_code == 403:
        raise VirusTotalError(
            "이 API 요청은 현재 계정 권한으로 사용할 수 없습니다. "
            "공개 API 지원 범위인지 확인해 주세요."
        )

    # Rate limit
    if response.status_code == 429:
        raise VirusTotalError(
            "VirusTotal 공개 API 요청 한도에 도달했습니다. "
            "기본 한도는 분당 4회, 하루 500회입니다. "
            "잠시 후 다시 시도해 주세요."
        )

    # Server error
    if response.status_code >= 500:
        raise VirusTotalError(
            f"VirusTotal 서버에서 일시적인 오류 "
            f"(HTTP {response.status_code})가 발생했습니다."
        )

    if not response.ok:
        raise VirusTotalError(
            f"VirusTotal 요청에 실패했습니다. "
            f"(HTTP {response.status_code})"
        )

    try:
        payload = response.json()

    except ValueError as exc:
        raise VirusTotalError(
            "VirusTotal 응답을 JSON으로 해석하지 못했습니다."
        ) from exc

    if not isinstance(payload, dict):
        raise VirusTotalError(
            "VirusTotal 응답 형식이 예상과 다릅니다."
        )

    return payload


# ==========================================
# 1. LOOK UP EXISTING URL REPORT
# ==========================================

def lookup_virustotal_url(
    api_key: str,
    raw_url: str,
) -> dict:
    """Retrieve the latest URL reputation report.

    The user interface must obtain explicit consent before calling this
    function because VirusTotal warns that queried indicators may be
    included in its community dataset.
    """

    url_id = virustotal_url_id(raw_url)

    payload = _virustotal_request(
        "GET",
        f"/urls/{url_id}",
        api_key,
    )

    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}

    if not isinstance(attributes, dict):
        raise VirusTotalError(
            "URL 평판 보고서의 형식이 올바르지 않습니다."
        )

    return {
        "url": normalize_url(raw_url),
        "url_id": data.get("id") or url_id,
        "attributes": attributes,
        "links": data.get("links") or {},
    }


# ==========================================
# 2. SUBMIT A NEW URL SCAN
# ==========================================

def submit_virustotal_url(
    api_key: str,
    raw_url: str,
) -> dict:
    """Submit a new public URL scan."""

    normalized = normalize_url(raw_url)

    payload = _virustotal_request(
        "POST",
        "/urls",
        api_key,
        data={
            "url": normalized
        },
    )

    data = payload.get("data") or {}

    analysis_id = data.get("id")

    if not analysis_id:
        raise VirusTotalError(
            "검사 요청은 전송했지만 "
            "분석 ID를 응답에서 찾지 못했습니다."
        )

    return {
        "url": normalized,
        "analysis_id": analysis_id,
        "url_id": virustotal_url_id(normalized),
        "status": (
            data.get("attributes") or {}
        ).get("status", "queued"),
    }


# ==========================================
# 3. GET ANALYSIS STATUS
# ==========================================

def get_virustotal_analysis(
    api_key: str,
    analysis_id: str,
) -> dict:
    """Retrieve analysis status and available engine results."""

    safe_id = (analysis_id or "").strip()

    if (
        not safe_id
        or "/" in safe_id
        or "?" in safe_id
    ):
        raise VirusTotalError(
            "분석 ID 형식이 올바르지 않습니다."
        )

    payload = _virustotal_request(
        "GET",
        f"/analyses/{safe_id}",
        api_key,
    )

    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}

    if not isinstance(attributes, dict):
        raise VirusTotalError(
            "분석 결과의 형식이 올바르지 않습니다."
        )

    return {
        "analysis_id": data.get("id") or safe_id,
        "status": attributes.get("status", "unknown"),
        "stats": attributes.get("stats") or {},
        "results": attributes.get("results") or {},
        "date": attributes.get("date"),
    }
