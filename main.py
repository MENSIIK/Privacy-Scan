from __future__ import annotations

import os
from datetime import datetime, timezone

import streamlit as st

from scanner_core import (
    ScanError,
    VirusTotalError,
    VirusTotalNotFoundError,
    analyze_policy_text,
    analyze_website,
    get_virustotal_analysis,
    lookup_virustotal_url,
    normalize_url,
    submit_virustotal_url,
)

EXPECTED_TOPIC_COUNT = 11
VT_RATE_PER_MINUTE = 4
VT_REQUESTS_PER_DAY = 500


def _item_value(item, key, default=None):
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _policy_html(policy):
    if isinstance(policy, dict):
        return policy.get("html", "")
    return getattr(policy, "html", "")


def _get_virustotal_api_key() -> str:
    """Read the API key from Streamlit Secrets or an environment variable."""
    try:
        secret_value = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    except Exception:
        secret_value = ""
    return str(secret_value or os.getenv("VIRUSTOTAL_API_KEY", "")).strip()


def _render_terminal_stats(stats: dict):
    stats = stats if isinstance(stats, dict) else {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout = int(stats.get("timeout", 0) or 0)

    total = sum(
        int(value or 0)
        for value in stats.values()
        if isinstance(value, (int, float))
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("MALICIOUS", malicious)
    c2.metric("SUSPICIOUS", suspicious)
    c3.metric("HARMLESS", harmless)
    c4.metric("UNDETECTED", undetected)

    st.caption(
        f"총 {total}개 결과 · 시간 초과 {timeout}개. "
        "탐지 결과는 VirusTotal에 참여하는 엔진의 판단이며 "
        "최종 안전 판정이 아닙니다."
    )

    if malicious > 0:
        st.error(
            "악성으로 분류한 엔진이 있습니다. "
            "해당 URL을 열지 말고 별도로 확인하세요."
        )
    elif suspicious > 0:
        st.warning(
            "의심으로 분류한 엔진이 있습니다. "
            "URL을 신중하게 확인하세요."
        )
    elif total > 0:
        st.success(
            "현재 보고서에서 악성·의심 탐지가 보고되지 않았습니다."
        )
        st.caption(
            "탐지가 없다는 사실이 사이트의 안전을 보증하지는 않습니다."
        )
    else:
        st.info(
            "아직 통계 결과가 제공되지 않았습니다. "
            "분석 상태를 다시 확인해 주세요."
        )


def _render_engine_detections(results: dict):
    if not isinstance(results, dict):
        return

    detections = []

    for engine_name, engine_result in results.items():
        if not isinstance(engine_result, dict):
            continue

        category = str(
            engine_result.get("category", "")
        ).lower()

        if category in {"malicious", "suspicious"}:
            detections.append({
                "검사 엔진": str(engine_name),
                "분류": category,
                "판정": str(
                    engine_result.get("result") or "상세 판정 없음"
                ),
            })

    if detections:
        st.markdown("#### 탐지한 엔진")
        st.dataframe(
            detections[:20],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("표시할 악성·의심 엔진 결과가 없습니다.")


st.set_page_config(
    page_title="Privacy Scan | Windows Terminal Edition",
    page_icon="🖥️",
    layout="wide",
)


# ==========================================
# WINDOWS TERMINAL THEME
# ==========================================

st.markdown(
    """
    <style>
    :root {
        --terminal-bg: #0c0c0c;
        --terminal-panel: #111111;
        --terminal-panel-2: #181818;
        --terminal-border: #333333;
        --terminal-green: #13a10e;
        --terminal-green-bright: #4cff4c;
        --terminal-blue: #0078d4;
        --terminal-cyan: #3a96dd;
        --terminal-text: #cccccc;
        --terminal-muted: #969696;
        --terminal-amber: #fce100;
        --terminal-red: #e74856;
    }

    html, body, [data-testid="stAppViewContainer"], .stApp {
        background: var(--terminal-bg) !important;
        color: var(--terminal-text) !important;
        font-family: "Cascadia Mono", "Cascadia Code",
                     Consolas, monospace !important;
    }

    .stApp, .stApp p, .stApp li, .stApp label,
    .stApp input, .stApp textarea, .stApp button,
    .stApp div, .stApp span {
        font-family: "Cascadia Mono", "Cascadia Code",
                     Consolas, monospace;
    }

    [data-testid="stHeader"] {
        background: #0c0c0c !important;
    }

    [data-testid="stToolbar"] {
        right: 1rem;
    }

    [data-testid="stDecoration"] {
        background: var(--terminal-blue) !important;
    }

    [data-testid="stSidebar"] {
        background: #101010 !important;
        border-right: 1px solid #333;
    }

    h1, h2, h3, h4, h5, h6 {
        color: #f2f2f2 !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
    }

    p, li, label, .stMarkdown,
    [data-testid="stCaptionContainer"] p {
        color: var(--terminal-text);
    }

    a {
        color: #75c7ff !important;
    }

    a:hover {
        color: #a8dcff !important;
    }

    code, pre {
        font-family: "Cascadia Mono", Consolas, monospace !important;
    }

    .terminal-window {
        background: #0c0c0c;
        border: 1px solid #3b3b3b;
        border-radius: 10px;
        overflow: hidden;
        margin-bottom: 1rem;
        box-shadow: 0 8px 30px rgba(0,0,0,.32);
    }

    .terminal-titlebar {
        height: 40px;
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 0 14px;
        background: #202020;
        border-bottom: 1px solid #393939;
        color: #e6e6e6;
        font-size: .82rem;
    }

    .terminal-dot {
        width: 9px;
        height: 9px;
        border-radius: 50%;
        display: inline-block;
    }

    .terminal-title {
        margin-left: 7px;
        color: #dddddd;
    }

    .terminal-body {
        padding: 1.2rem 1.35rem 1.35rem;
    }

    .terminal-prompt {
        color: #75beff !important;
        font-weight: 700;
        font-size: .9rem;
    }

    .terminal-command {
        color: #4cff4c !important;
        font-size: clamp(1.35rem, 3vw, 2rem);
        font-weight: 800;
        margin: .5rem 0;
    }

    .terminal-subtitle {
        color: #c5c5c5 !important;
        margin: .35rem 0 0;
        font-size: .9rem;
    }

    .terminal-status {
        color: #4cff4c !important;
        margin-top: .8rem;
        font-size: .78rem;
    }

    .terminal-notice {
        background: #111111;
        border: 1px solid #383838;
        border-left: 4px solid var(--terminal-blue);
        border-radius: 4px;
        padding: .85rem 1rem;
        margin: .8rem 0 1rem;
        color: #d4d4d4 !important;
        font-size: .85rem;
    }

    .terminal-kicker {
        color: #75beff !important;
        font-size: .78rem;
        font-weight: 800;
        letter-spacing: .1em;
        margin: .75rem 0 .55rem;
    }

    .module-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .65rem;
        margin: .7rem 0 1.1rem;
    }

    .module-card {
        background: #111111;
        border: 1px solid #373737;
        border-radius: 5px;
        padding: .85rem;
        min-height: 112px;
    }

    .module-card .module-icon {
        color: #75beff;
        font-size: 1.25rem;
        margin-bottom: .35rem;
    }

    .module-card .module-title {
        color: #eeeeee !important;
        font-weight: 800;
        font-size: .88rem;
        margin-bottom: .25rem;
    }

    .module-card .module-desc {
        color: #a9a9a9 !important;
        font-size: .75rem;
        line-height: 1.4;
    }

    [data-testid="stTextInput"] label,
    [data-testid="stCheckbox"] label {
        color: #dddddd !important;
    }

    [data-testid="stTextInput"] input {
        background: #050505 !important;
        color: #4cff4c !important;
        border: 1px solid #555555 !important;
        border-radius: 3px !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
        min-height: 2.8rem;
    }

    [data-testid="stTextInput"] input:focus {
        border-color: #0078d4 !important;
        box-shadow: 0 0 0 .15rem rgba(0,120,212,.22) !important;
    }

    [data-testid="stTextInput"] input::placeholder {
        color: #777777 !important;
    }

    button[kind="primary"],
    [data-testid="stBaseButton-primary"] {
        background: #0078d4 !important;
        color: #ffffff !important;
        border: 1px solid #2b9bff !important;
        border-radius: 3px !important;
        min-height: 2.8rem !important;
        font-weight: 800 !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
        box-shadow: 0 3px 12px rgba(0,120,212,.25) !important;
    }

    button[kind="primary"]:hover,
    [data-testid="stBaseButton-primary"]:hover {
        background: #1689e8 !important;
    }

    button[kind="secondary"],
    [data-testid="stBaseButton-secondary"] {
        background: #202020 !important;
        color: #dddddd !important;
        border: 1px solid #555555 !important;
        border-radius: 3px !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
    }

    button[kind="secondary"]:hover,
    [data-testid="stBaseButton-secondary"]:hover {
        border-color: #75beff !important;
        color: #ffffff !important;
    }

    [data-testid="stVerticalBlockBorderWrapper"] {
        background: #111111;
        border-color: #3a3a3a !important;
        border-radius: 5px;
    }

    [data-testid="stAlert"] {
        border-radius: 4px;
    }

    [data-testid="stCode"] {
        border: 1px solid #3b3b3b;
        border-radius: 4px;
    }

    [data-testid="stCode"] pre {
        background: #050505 !important;
        color: #4cff4c !important;
    }

    [data-testid="stMetric"] {
        background: #111111;
        border: 1px solid #3b3b3b;
        padding: .75rem;
        border-radius: 4px;
    }

    [data-testid="stMetricLabel"] {
        color: #a9a9a9 !important;
    }

    [data-testid="stMetricValue"] {
        color: #4cff4c !important;
    }

    hr {
        border-color: #3b3b3b !important;
    }

    .result-card {
        background: #111111;
        border: 1px solid #3b3b3b;
        border-left: 3px solid #13a10e;
        padding: .85rem;
        border-radius: 4px;
        min-height: 100px;
    }

    .result-card h4 {
        color: #75beff !important;
        margin: 0 0 .45rem;
        font-size: .82rem;
    }

    .result-card p {
        color: #4cff4c !important;
        margin: 0;
        font-size: 1rem;
        font-weight: 700;
        overflow-wrap: anywhere;
    }

    .scan-status {
        display: inline-block;
        padding: .22rem .42rem;
        border-radius: 3px;
        font-size: .72rem;
        font-weight: 800;
    }

    .scan-status.found {
        background: #102510;
        border: 1px solid #237a23;
        color: #4cff4c !important;
    }

    .scan-status.missing {
        background: #28220a;
        border: 1px solid #8a741b;
        color: #fce100 !important;
    }

    .quota-panel {
        background: #101820;
        border: 1px solid #225c89;
        border-left: 4px solid #0078d4;
        padding: .8rem 1rem;
        border-radius: 4px;
    }

    .quota-title {
        color: #75beff !important;
        font-weight: 800;
        font-size: .8rem;
        letter-spacing: .08em;
    }

    .quota-value {
        color: #ffffff !important;
        font-size: 1.1rem;
        font-weight: 800;
        margin-top: .25rem;
    }

    @media (max-width: 800px) {
        .module-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }
    }

    @media (max-width: 480px) {
        .module-grid {
            grid-template-columns: 1fr;
        }

        .terminal-body {
            padding: 1rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==========================================
# TERMINAL HEADER
# ==========================================

st.markdown(
    """
    <div class="terminal-window">
      <div class="terminal-titlebar">
        <span class="terminal-dot" style="background:#e74856"></span>
        <span class="terminal-dot" style="background:#fce100"></span>
        <span class="terminal-dot" style="background:#13a10e"></span>
        <span class="terminal-title">
            Windows Terminal — Privacy Scan
        </span>
      </div>

      <div class="terminal-body">
        <div class="terminal-prompt">PS C:\\PRIVACY-SCAN&gt;</div>

        <div class="terminal-command">
            PRIVACY SCAN
            <span style="color:#75beff">v2.2</span>
        </div>

        <div class="terminal-subtitle">
            웹사이트 개인정보 보호 문구 + VirusTotal URL 평판 검사
        </div>

        <div class="terminal-status">
            [OK] SYSTEM READY |
            [OK] POLICY MODULE |
            [READY] VIRUSTOTAL API
        </div>
      </div>
    </div>

    <div class="terminal-notice">
      <strong>검사 안내</strong><br>
      공개 웹페이지의 개인정보 처리방침 문구를 분석하고,
      별도 동의를 받은 경우 VirusTotal 공개 API로 URL 평판을 조회합니다.
      이 도구는 사이트의 안전성이나 법 준수 여부를 보증하지 않습니다.
    </div>

    <div class="terminal-kicker">[ MODULES ]</div>

    <div class="module-grid">
      <div class="module-card">
        <div class="module-icon">[01]</div>
        <div class="module-title">HTTPS / WEB</div>
        <div class="module-desc">
          연결 방식, 응답 상태, 공개 웹페이지 확인
        </div>
      </div>

      <div class="module-card">
        <div class="module-icon">[02]</div>
        <div class="module-title">PRIVACY POLICY</div>
        <div class="module-desc">
          처리방침 자동 탐색 및 11개 주제 문구 분석
        </div>
      </div>

      <div class="module-card">
        <div class="module-icon">[03]</div>
        <div class="module-title">VIRUSTOTAL</div>
        <div class="module-desc">
          외부 보안 엔진의 URL 평판 및 탐지 결과 조회
        </div>
      </div>

      <div class="module-card">
        <div class="module-icon">[04]</div>
        <div class="module-title">EVIDENCE</div>
        <div class="module-desc">
          일치한 표현과 원문 문맥을 결과에 표시
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ==========================================
# URL INPUT
# ==========================================

st.markdown(
    '<div class="terminal-kicker">'
    '[ TARGET ] Enter public website URL'
    '</div>',
    unsafe_allow_html=True,
)

url = st.text_input(
    "분석할 웹사이트 주소",
    placeholder="https://example.com",
    help=(
        "공개 웹사이트 주소를 입력하세요. "
        "주소 앞에 https://를 생략해도 됩니다."
    ),
    key="target_url_input",
)

current_normalized_url = ""

if url.strip():
    try:
        current_normalized_url = normalize_url(url)
    except ScanError:
        current_normalized_url = ""


button_left, button_right = st.columns(2)

with button_left:
    privacy_clicked = st.button(
        "▶ RUN PRIVACY POLICY SCAN",
        type="primary",
        use_container_width=True,
    )

with button_right:
    vt_clicked = st.button(
        "▶ QUERY VIRUSTOTAL",
        use_container_width=True,
        disabled=not bool(url.strip()),
    )


share_consent = st.checkbox(
    "VirusTotal에 URL을 전송하는 데 동의합니다. "
    "조회·제출한 URL은 VirusTotal 커뮤니티 데이터셋에 추가되어 "
    "다른 사용자에게 공개될 수 있으며, "
    "민감정보·개인정보가 포함된 URL은 전송하지 않겠습니다.",
    key="vt_public_share_consent",
)


# ==========================================
# PRIVACY POLICY SCAN ACTION
# ==========================================

if privacy_clicked:
    try:
        with st.spinner(
            "[WEB] 공개 페이지 및 개인정보 처리방침 분석 중..."
        ):
            result = analyze_website(url)

        st.session_state["last_scan_result"] = result
        st.session_state["last_scan_url"] = url.strip()

        st.success(
            "[OK] 개인정보 처리방침 분석이 완료되었습니다."
        )

    except ScanError as exc:
        st.error(str(exc))
        st.caption(
            "사이트가 자동 접속을 차단했거나 "
            "공개 HTML을 제공하지 않을 수 있습니다."
        )

    except Exception:
        st.error(
            "예상하지 못한 오류가 발생했습니다. "
            "주소와 배포 로그를 확인해 주세요."
        )


# ==========================================
# VIRUSTOTAL LOOKUP ACTION
# ==========================================

if vt_clicked:
    if not share_consent:
        st.warning(
            "VirusTotal에 URL이 전송될 수 있다는 안내를 "
            "확인하고 동의해 주세요."
        )

    else:
        api_key = _get_virustotal_api_key()

        if not api_key:
            st.error(
                "VirusTotal API 키를 찾지 못했습니다. "
                "Streamlit Cloud의 App settings → Secrets에 "
                'VIRUSTOTAL_API_KEY = "발급받은 키" '
                "를 등록해 주세요."
            )

        else:
            try:
                with st.spinner(
                    "[VT] 기존 URL 평판 보고서를 조회하는 중..."
                ):
                    vt_report = lookup_virustotal_url(
                        api_key,
                        url,
                    )

                st.session_state["vt_report"] = vt_report
                st.session_state["vt_report_url"] = url.strip()
                st.session_state.pop("vt_not_found_url", None)

                st.success(
                    "[OK] VirusTotal URL 보고서를 불러왔습니다."
                )

            except VirusTotalNotFoundError:
                try:
                    normalized = normalize_url(url)

                    st.session_state["vt_not_found_url"] = normalized
                    st.session_state.pop("vt_report", None)
                    st.session_state["vt_report_url"] = normalized

                except ScanError as exc:
                    st.error(str(exc))

            except (VirusTotalError, ScanError) as exc:
                st.error(str(exc))


# ==========================================
# PRIVACY POLICY RESULTS
# ==========================================

result = st.session_state.get("last_scan_result")
last_scan_url = st.session_state.get("last_scan_url", "")

if result and last_scan_url == url.strip():
    current_topics = result.get("topic_results", []) or []

    policy = result.get("policy")
    policy_html = _policy_html(policy)

    # 이전 4개 항목 버전의 세션 결과를 11개 항목으로 갱신한다.
    if policy_html and len(current_topics) < EXPECTED_TOPIC_COUNT:
        try:
            current_topics = analyze_policy_text(policy_html)

            result["topic_results"] = current_topics
            st.session_state["last_scan_result"] = result

        except Exception:
            pass

    st.markdown("---")

    st.markdown(
        '<div class="terminal-kicker">'
        '[01] PRIVACY POLICY REPORT'
        '</div>',
        unsafe_allow_html=True,
    )

    st.caption(
        f"요청 주소: {result.get('requested_url', '')}"
    )

    st.caption(
        f"최종 주소: {result.get('final_url', '')}"
    )

    topic_count = sum(
        1 for item in current_topics
        if _item_value(item, "found", False)
    )

    topic_total = len(current_topics)

    policy_label = (
        "본문 분석 완료"
        if policy is not None
        else (
            "링크 발견"
            if result.get("policy_links")
            else "링크 미발견"
        )
    )

    c1, c2, c3 = st.columns(3)

    c1.markdown(
        '<div class="result-card">'
        '<h4>CONNECTION</h4><p>'
        + (
            "HTTPS 사용"
            if result.get("is_https")
            else "HTTP 사용"
        )
        + "</p></div>",
        unsafe_allow_html=True,
    )

    c2.markdown(
        '<div class="result-card">'
        '<h4>POLICY</h4><p>'
        + policy_label
        + "</p></div>",
        unsafe_allow_html=True,
    )

    c3.markdown(
        '<div class="result-card">'
        '<h4>TOPIC MATCH</h4><p>'
        + (
            f"{topic_count} / {topic_total}"
            if topic_total
            else "분석 불가"
        )
        + "</p></div>",
        unsafe_allow_html=True,
    )

    if topic_total:
        st.progress(
            topic_count / topic_total,
            text=(
                f"11개 검사 주제 중 {topic_count}개에서 "
                "설정된 표현을 발견했습니다."
            ),
        )

    st.markdown("#### [LINKS] 개인정보 처리방침 링크")

    if result.get("policy_links"):
        for item in result["policy_links"]:
            host_note = (
                "같은 호스트 · 자동 분석 대상"
                if item.get("same_host") == "true"
                else "외부 호스트 · 자동 열람 생략"
            )

            st.write(
                f"- [{item.get('label', '개인정보 처리방침')}]"
                f"({item.get('url', '')}) · {host_note}"
            )

    else:
        st.info(
            "첫 페이지에서 개인정보 처리방침 링크를 찾지 못했습니다. "
            "링크가 없다는 뜻은 아닙니다."
        )

    if result.get("policy_error"):
        st.warning(result["policy_error"])

    st.markdown("#### [EVIDENCE] 11개 항목별 근거")

    st.caption(
        "아래는 설정된 표현과 일치하는지 확인한 결과입니다. "
        "문구 발견만으로 정책의 충분성이나 적법성이 증명되지는 않습니다."
    )

    if current_topics:
        for item in current_topics:
            item_topic = str(
                _item_value(item, "topic", "검사 항목")
            )

            item_found = bool(
                _item_value(item, "found", False)
            )

            item_phrase = str(
                _item_value(item, "matched_phrase", "") or ""
            )

            item_evidence = str(
                _item_value(item, "evidence", "") or ""
            )

            with st.container(border=True):
                left, right = st.columns([1, 3])

                with left:
                    st.markdown(f"**{item_topic}**")

                    if item_found:
                        st.markdown(
                            '<span class="scan-status found">'
                            '[FOUND]</span>',
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            '<span class="scan-status missing">'
                            '[NOT FOUND]</span>',
                            unsafe_allow_html=True,
                        )

                with right:
                    if item_found:
                        st.caption("MATCHED PHRASE")

                        st.code(
                            item_phrase or "일치 표현 정보 없음",
                            language=None,
                        )

                        st.caption("SOURCE CONTEXT")

                        st.code(
                            item_evidence
                            or "근거 문맥을 추출하지 못했습니다.",
                            language=None,
                        )

                    else:
                        st.caption(
                            "설정된 검색 표현을 찾지 못했습니다. "
                            "다른 표현으로 작성되었거나 페이지 구조 때문에 "
                            "탐지되지 않았을 수 있습니다."
                        )


# ==========================================
# VIRUSTOTAL RESULTS
# ==========================================

st.markdown("---")

st.markdown(
    '<div class="terminal-kicker">'
    '[02] VIRUSTOTAL URL REPUTATION'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    f'<div class="quota-panel">'
    f'<div class="quota-title">'
    f'PUBLIC API — DEFAULT BASIC QUOTA'
    f'</div>'
    f'<div class="quota-value">'
    f'{VT_RATE_PER_MINUTE} requests / minute &nbsp; | &nbsp; '
    f'{VT_REQUESTS_PER_DAY} requests / day'
    f'</div>'
    f'<div style="color:#b8c7d5;font-size:.78rem;margin-top:.35rem;">'
    f'비상업적·학술 목적 공개 API 기준. '
    f'요청 1회가 일반적으로 사용량 1회로 계산됩니다. '
    f'계정별 최신 사용량은 VirusTotal API Key 페이지에서 확인하세요.'
    f'</div></div>',
    unsafe_allow_html=True,
)

st.caption(
    "중요: VirusTotal에 조회하거나 제출한 URL은 커뮤니티 데이터셋에 "
    "포함되어 공개될 수 있습니다. 비공개 서비스 주소, 인증 토큰, "
    "개인 식별 정보가 들어간 URL은 절대 전송하지 마세요."
)


# ==========================================
# SUBMIT NEW SCAN IF REPORT NOT FOUND
# ==========================================

not_found_url = st.session_state.get("vt_not_found_url")

if not_found_url and not_found_url == current_normalized_url:
    st.warning(
        "기존 VirusTotal 보고서를 찾지 못했습니다. "
        "아래 버튼을 누르면 VirusTotal에 새 URL 검사 요청을 전송합니다."
    )

    if st.button(
        "▶ SUBMIT NEW URL SCAN TO VIRUSTOTAL",
        type="primary",
        use_container_width=True,
        disabled=not share_consent,
    ):
        api_key = _get_virustotal_api_key()

        if not api_key:
            st.error(
                "Streamlit Secrets에서 "
                "VIRUSTOTAL_API_KEY를 찾지 못했습니다."
            )

        else:
            try:
                with st.spinner(
                    "[VT] 새 검사 요청을 전송하는 중..."
                ):
                    submitted_scan = submit_virustotal_url(
                        api_key,
                        url,
                    )

                st.session_state["vt_pending_scan"] = submitted_scan
                st.session_state.pop("vt_analysis_result", None)

                st.success(
                    "[OK] 새 URL 검사 요청을 전송했습니다."
                )

            except (VirusTotalError, ScanError) as exc:
                st.error(str(exc))


# ==========================================
# CHECK ANALYSIS STATUS
# ==========================================

pending_scan = st.session_state.get("vt_pending_scan")

if pending_scan and pending_scan.get("url") == current_normalized_url:
    st.write("분석 ID:")

    st.code(
        pending_scan.get("analysis_id", ""),
        language=None,
    )

    st.caption(
        "분석이 완료되기까지 시간이 걸릴 수 있습니다. "
        "상태 확인 버튼을 너무 자주 누르지 마세요. "
        "확인 1회도 API 요청으로 계산됩니다."
    )

    if st.button(
        "↻ CHECK ANALYSIS STATUS",
        use_container_width=True,
    ):
        api_key = _get_virustotal_api_key()

        if not api_key:
            st.error(
                "Streamlit Secrets에서 "
                "VIRUSTOTAL_API_KEY를 찾지 못했습니다."
            )

        else:
            try:
                with st.spinner(
                    "[VT] 분석 상태를 확인하는 중..."
                ):
                    analysis_result = get_virustotal_analysis(
                        api_key,
                        pending_scan["analysis_id"],
                    )

                st.session_state["vt_analysis_result"] = analysis_result

            except VirusTotalError as exc:
                st.error(str(exc))


analysis_result = st.session_state.get("vt_analysis_result")

if (
    analysis_result
    and pending_scan
    and pending_scan.get("url") == current_normalized_url
):
    status = str(
        analysis_result.get("status", "unknown")
    ).lower()

    st.markdown(
        f"**ANALYSIS STATUS:** `{status.upper()}`"
    )

    if status == "completed":
        _render_terminal_stats(
            analysis_result.get("stats", {})
        )

        _render_engine_detections(
            analysis_result.get("results", {})
        )

    else:
        st.info(
            "분석이 아직 진행 중입니다. "
            "잠시 후 상태 확인 버튼을 다시 눌러 주세요."
        )


# ==========================================
# EXISTING URL REPORT DISPLAY
# ==========================================

vt_report = st.session_state.get("vt_report")
vt_report_url = st.session_state.get("vt_report_url", "")

if vt_report and vt_report_url == current_normalized_url:
    attributes = vt_report.get("attributes", {})

    st.markdown("#### [REPORT] 기존 URL 평판 보고서")

    _render_terminal_stats(
        attributes.get("last_analysis_stats", {})
    )

    _render_engine_detections(
        attributes.get("last_analysis_results", {})
    )

    if attributes.get("last_analysis_date"):
        try:
            analyzed_at = datetime.fromtimestamp(
                int(attributes["last_analysis_date"]),
                tz=timezone.utc,
            )

            st.caption(
                f"마지막 분석 시각(UTC): "
                f"{analyzed_at:%Y-%m-%d %H:%M:%S}"
            )

        except (TypeError, ValueError, OSError):
            pass

    st.caption(
        f"VirusTotal URL ID: {vt_report.get('url_id', '')}"
    )

    st.caption(
        "탐지 결과가 0이어도 안전을 보증하지 않습니다. "
        "오탐 또는 미탐 가능성이 있습니다."
    )


# ==========================================
# SYSTEM / API NOTES
# ==========================================

st.markdown("---")

st.markdown(
    '<div class="terminal-kicker">'
    '[ SYSTEM / API NOTES ]'
    '</div>',
    unsafe_allow_html=True,
)

with st.expander("VirusTotal API 한도 및 키 설정 방법"):
    st.markdown(
        """
        **공개 API 기본 한도**
        - 분당 최대 4회 요청
        - 하루 최대 500회 요청
        - 비상업적·학술 목적의 공개 API

        **Streamlit Secrets 설정**
        ```toml
        VIRUSTOTAL_API_KEY = "발급받은_API_키"
        ```

        Streamlit Cloud의 App settings → Secrets에 등록하세요.
        API 키를 `main.py`에 직접 적거나 GitHub에 올리지 마세요.

        **주의**
        - VirusTotal에 조회·제출한 URL은 커뮤니티 데이터셋에 포함되어 공개될 수 있습니다.
        - 실제 개인정보, 인증 토큰, 비공개 주소가 들어간 URL은 조회하지 마세요.
        - 악성 탐지 결과가 없다는 것이 사이트의 안전을 보증하지는 않습니다.
        - 공개 API를 상업 서비스에 사용하지 마세요.
        """
    )

    st.link_button(
        "VirusTotal API 사용량 확인",
        "https://www.virustotal.com/gui/my-apikey",
        use_container_width=True,
    )


st.caption(
    "SAFETY: public URLs only · private IP blocking · redirect validation · "
    "request timeout · response-size limit · VirusTotal API key stored in Secrets"
)

st.caption(
    "PRIVACY SCAN v2.2 · WINDOWS TERMINAL EDITION · "
    "11 POLICY TOPICS + VIRUSTOTAL URL REPUTATION"
)
