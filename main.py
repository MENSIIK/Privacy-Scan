from __future__ import annotations

import html
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


def _safe_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _render_terminal_stats(stats: dict):
    """Render VirusTotal counters with static HTML, not st.metric.

    This avoids the lazily-loaded metric frontend chunk that can fail to load
    in some Streamlit Cloud browser sessions after an app deployment.
    """
    stats = stats if isinstance(stats, dict) else {}
    keys = ["malicious", "suspicious", "harmless", "undetected"]
    labels = ["MALICIOUS", "SUSPICIOUS", "HARMLESS", "UNDETECTED"]
    values = [_safe_int(stats.get(key, 0)) for key in keys]
    timeout = _safe_int(stats.get("timeout", 0))
    total = sum(
        _safe_int(value)
        for value in stats.values()
        if isinstance(value, (int, float)) or str(value).isdigit()
    )

    cards = []
    for key, label, value in zip(keys, labels, values):
        cards.append(
            '<div class="vt-stat-card vt-stat-'
            + html.escape(key)
            + '"><div class="vt-stat-label">'
            + html.escape(label)
            + '</div><div class="vt-stat-value">'
            + str(value)
            + '</div></div>'
        )

    st.markdown(
        '<div class="vt-stat-grid">' + "".join(cards) + "</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="terminal-inline-note">총 '
        + str(total)
        + '개 결과 · 시간 초과 '
        + str(timeout)
        + '개. 탐지 결과는 VirusTotal 참여 엔진의 판단이며 최종 안전 판정이 아닙니다.</div>',
        unsafe_allow_html=True,
    )

    malicious = values[0]
    suspicious = values[1]

    if malicious > 0:
        st.error(
            "악성으로 분류한 엔진이 있습니다. 해당 URL을 열지 말고 별도로 확인하세요."
        )
    elif suspicious > 0:
        st.warning(
            "의심으로 분류한 엔진이 있습니다. URL을 신중하게 확인하세요."
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
            "아직 통계 결과가 제공되지 않았습니다. 분석 상태를 다시 확인해 주세요."
        )


def _render_engine_detections(results: dict):
    """Render detections as a simple HTML table instead of a dynamic dataframe."""
    if not isinstance(results, dict):
        return

    detections = []
    for engine_name, engine_result in results.items():
        if not isinstance(engine_result, dict):
            continue
        category = str(engine_result.get("category", "")).lower()
        if category in {"malicious", "suspicious"}:
            detections.append(
                (
                    str(engine_name),
                    category,
                    str(engine_result.get("result") or "상세 판정 없음"),
                )
            )

    if not detections:
        st.markdown(
            '<div class="terminal-inline-note">표시할 악성·의심 엔진 결과가 없습니다.</div>',
            unsafe_allow_html=True,
        )
        return

    rows = []
    for engine, category, verdict in detections[:20]:
        rows.append(
            "<tr><td>"
            + html.escape(engine)
            + "</td><td>"
            + html.escape(category.upper())
            + "</td><td>"
            + html.escape(verdict)
            + "</td></tr>"
        )

    st.markdown(
        '<div class="terminal-table-wrap"><table class="terminal-table">'
        "<thead><tr><th>검사 엔진</th><th>분류</th><th>판정</th></tr></thead>"
        "<tbody>"
        + "".join(rows)
        + "</tbody></table></div>",
        unsafe_allow_html=True,
    )


def _render_policy_evidence(item):
    topic = html.escape(str(_item_value(item, "topic", "검사 항목")))
    found = bool(_item_value(item, "found", False))
    phrase = html.escape(str(_item_value(item, "matched_phrase", "") or ""))
    evidence = html.escape(str(_item_value(item, "evidence", "") or ""))

    if found:
        status = '<span class="scan-status found">[FOUND] 근거 문구 발견</span>'
        detail = (
            '<div class="evidence-label">MATCHED PHRASE</div>'
            '<pre class="evidence-code">' + (phrase or "일치 표현 정보 없음") + "</pre>"
            '<div class="evidence-label">SOURCE CONTEXT</div>'
            '<pre class="evidence-code">'
            + (evidence or "근거 문맥을 추출하지 못했습니다.")
            + "</pre>"
        )
    else:
        status = '<span class="scan-status missing">[NOT FOUND] 표현 미발견</span>'
        detail = (
            '<div class="evidence-missing">설정된 검색 표현을 찾지 못했습니다. '
            '다른 표현으로 작성되었거나 페이지 구조 때문에 탐지되지 않았을 수 있습니다. '
            '정책에 해당 내용이 없다고 단정할 수는 없습니다.</div>'
        )

    st.markdown(
        '<section class="evidence-card">'
        '<div class="evidence-head"><div class="evidence-topic">'
        + topic
        + "</div>"
        + status
        + '</div><div class="evidence-detail">'
        + detail
        + "</div></section>",
        unsafe_allow_html=True,
    )


st.set_page_config(
    page_title="Privacy Scan | Windows Terminal Edition",
    page_icon="🖥️",
    layout="wide",
)

# Scoped styling: do not apply font/layout rules to every nested div/span.
st.markdown(
    """
    <style>
    :root {
        --terminal-bg: #0c0c0c;
        --terminal-panel: #111111;
        --terminal-panel-2: #181818;
        --terminal-border: #3b3b3b;
        --terminal-green: #13a10e;
        --terminal-green-bright: #4cff4c;
        --terminal-blue: #0078d4;
        --terminal-text: #cccccc;
        --terminal-muted: #999999;
        --terminal-amber: #fce100;
        --terminal-red: #e74856;
    }

    html, body, [data-testid="stAppViewContainer"], .stApp {
        background: var(--terminal-bg) !important;
        color: var(--terminal-text) !important;
        font-family: "Cascadia Mono", "Cascadia Code", Consolas, monospace !important;
    }
    .stApp p, .stApp li, .stApp label, .stApp input,
    .stApp textarea, .stApp button, code, pre {
        font-family: "Cascadia Mono", "Cascadia Code", Consolas, monospace !important;
    }
    .stApp p, .stApp li, .stApp label { line-height: 1.55 !important; }
    [data-testid="stHeader"] { background: #0c0c0c !important; }
    [data-testid="stToolbar"] { right: 1rem; }
    [data-testid="stDecoration"] { background: var(--terminal-blue) !important; }
    [data-testid="stSidebar"] { background: #101010 !important; border-right: 1px solid #333; }
    [data-testid="stMarkdownContainer"] { line-height: 1.55; overflow-wrap: anywhere; }
    [data-testid="stMarkdownContainer"] p { margin-bottom: .65rem; }

    h1, h2, h3, h4, h5, h6 {
        color: #f2f2f2 !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
        line-height: 1.35 !important;
    }
    a { color: #75c7ff !important; }
    a:hover { color: #a8dcff !important; }

    .terminal-window {
        background: #0c0c0c;
        border: 1px solid #3b3b3b;
        border-radius: 8px;
        overflow: hidden;
        margin-bottom: 1rem;
        box-shadow: 0 8px 25px rgba(0,0,0,.28);
    }
    .terminal-titlebar {
        min-height: 40px;
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 7px 14px;
        background: #202020;
        border-bottom: 1px solid #393939;
        color: #e6e6e6;
        font-size: .82rem;
        line-height: 1.4;
    }
    .terminal-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: 0 0 9px; }
    .terminal-title { margin-left: 7px; color: #dddddd; }
    .terminal-body { padding: 1.1rem 1.3rem 1.2rem; }
    .terminal-prompt { color: #75beff !important; font-weight: 700; font-size: .9rem; line-height: 1.5; }
    .terminal-command { color: #4cff4c !important; font-size: clamp(1.35rem, 3vw, 2rem); font-weight: 800; margin: .45rem 0; line-height: 1.3; }
    .terminal-subtitle { color: #c5c5c5 !important; margin: .35rem 0 0; font-size: .9rem; line-height: 1.5; }
    .terminal-status { color: #4cff4c !important; margin-top: .8rem; font-size: .78rem; line-height: 1.6; overflow-wrap: anywhere; }
    .terminal-notice {
        background: #111111; border: 1px solid #383838;
        border-left: 4px solid var(--terminal-blue); border-radius: 4px;
        padding: .85rem 1rem; margin: .8rem 0 1rem;
        color: #d4d4d4 !important; font-size: .85rem; line-height: 1.65;
        overflow-wrap: anywhere;
    }
    .terminal-kicker {
        color: #75beff !important; font-size: .78rem; font-weight: 800;
        letter-spacing: .08em; line-height: 1.6; margin: .8rem 0 .55rem;
    }
    .module-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .65rem; margin: .7rem 0 1.1rem; }
    .module-card { background: #111111; border: 1px solid #373737; border-radius: 5px; padding: .85rem; min-height: 112px; }
    .module-card .module-icon { color: #75beff; font-size: 1.2rem; margin-bottom: .35rem; line-height: 1.5; }
    .module-card .module-title { color: #eeeeee !important; font-weight: 800; font-size: .88rem; margin-bottom: .25rem; line-height: 1.5; }
    .module-card .module-desc { color: #a9a9a9 !important; font-size: .75rem; line-height: 1.55; }

    [data-testid="stTextInput"] label, [data-testid="stCheckbox"] label { color: #dddddd !important; }
    [data-testid="stTextInput"] input {
        background: #050505 !important; color: #4cff4c !important;
        border: 1px solid #555555 !important; border-radius: 3px !important;
        font-family: "Cascadia Mono", Consolas, monospace !important; min-height: 2.8rem;
    }
    [data-testid="stTextInput"] input:focus { border-color: #0078d4 !important; box-shadow: 0 0 0 .15rem rgba(0,120,212,.22) !important; }
    [data-testid="stTextInput"] input::placeholder { color: #777777 !important; }
    button[kind="primary"], [data-testid="stBaseButton-primary"] {
        background: #0078d4 !important; color: #ffffff !important;
        border: 1px solid #2b9bff !important; border-radius: 3px !important;
        min-height: 2.8rem !important; font-weight: 800 !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
        box-shadow: 0 3px 12px rgba(0,120,212,.25) !important;
    }
    button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover { background: #1689e8 !important; }
    button[kind="secondary"], [data-testid="stBaseButton-secondary"] {
        background: #202020 !important; color: #dddddd !important;
        border: 1px solid #555555 !important; border-radius: 3px !important;
        font-family: "Cascadia Mono", Consolas, monospace !important;
        min-height: 2.8rem !important;
    }
    button[kind="secondary"]:hover, [data-testid="stBaseButton-secondary"]:hover { border-color: #75beff !important; color: #ffffff !important; }

    .vt-stat-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .7rem; margin: .8rem 0 .5rem; }
    .vt-stat-card { min-width: 0; background: #151515; border: 1px solid #3b3b3b; border-radius: 5px; padding: .9rem 1rem; min-height: 92px; display: flex; flex-direction: column; justify-content: space-between; }
    .vt-stat-label { color: #b8b8b8; font-size: .75rem; font-weight: 800; letter-spacing: .05em; line-height: 1.5; overflow-wrap: anywhere; }
    .vt-stat-value { color: #f2f2f2; font-size: 1.75rem; font-weight: 800; line-height: 1.3; margin-top: .35rem; }
    .vt-stat-malicious { border-top: 3px solid #e74856; }
    .vt-stat-suspicious { border-top: 3px solid #fce100; }
    .vt-stat-harmless { border-top: 3px solid #13a10e; }
    .vt-stat-undetected { border-top: 3px solid #0078d4; }
    .terminal-inline-note { color: #aaaaaa; font-size: .82rem; line-height: 1.7; margin: .45rem 0 .8rem; overflow-wrap: anywhere; }
    .terminal-table-wrap { width: 100%; overflow-x: auto; margin: .6rem 0 1rem; }
    .terminal-table { width: 100%; border-collapse: collapse; background: #111111; color: #cccccc; font-size: .84rem; }
    .terminal-table th, .terminal-table td { text-align: left; padding: .65rem .75rem; border: 1px solid #383838; line-height: 1.5; overflow-wrap: anywhere; }
    .terminal-table th { color: #75beff; background: #1b1b1b; }

    .result-card { background: #111111; border: 1px solid #3b3b3b; border-left: 3px solid #13a10e; padding: .85rem; border-radius: 4px; min-height: 92px; margin: .5rem 0; }
    .result-card h4 { color: #75beff !important; margin: 0 0 .4rem; font-size: .78rem; line-height: 1.5; }
    .result-card p { color: #4cff4c !important; margin: 0; font-size: 1rem; font-weight: 700; line-height: 1.5; overflow-wrap: anywhere; }
    .result-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .7rem; margin: .8rem 0; }
    .scan-status { display: inline-block; padding: .22rem .42rem; border-radius: 3px; font-size: .72rem; font-weight: 800; line-height: 1.5; white-space: nowrap; }
    .scan-status.found { background: #102510; border: 1px solid #237a23; color: #4cff4c !important; }
    .scan-status.missing { background: #28220a; border: 1px solid #8a741b; color: #fce100 !important; }
    .evidence-card { background: #111111; border: 1px solid #383838; border-left: 3px solid #13a10e; border-radius: 4px; margin: .65rem 0; padding: .85rem; min-width: 0; }
    .evidence-head { display: flex; align-items: center; justify-content: space-between; gap: .7rem; flex-wrap: wrap; margin-bottom: .7rem; }
    .evidence-topic { color: #f2f2f2; font-size: .95rem; font-weight: 800; line-height: 1.5; }
    .evidence-label { color: #75beff; font-size: .72rem; font-weight: 800; margin: .55rem 0 .3rem; line-height: 1.5; }
    .evidence-code { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; background: #050505; color: #c9f7d0; border: 1px solid #333333; border-radius: 3px; padding: .65rem .75rem; margin: 0; font: .82rem/1.65 "Cascadia Mono", Consolas, monospace; }
    .evidence-missing { color: #b8b8b8; font-size: .82rem; line-height: 1.65; }
    .quota-panel { background: #101820; border: 1px solid #225c89; border-left: 4px solid #0078d4; padding: .8rem 1rem; border-radius: 4px; line-height: 1.65; overflow-wrap: anywhere; }
    .quota-title { color: #75beff !important; font-weight: 800; font-size: .8rem; letter-spacing: .08em; line-height: 1.5; }
    .quota-value { color: #ffffff !important; font-size: 1.05rem; font-weight: 800; margin-top: .3rem; line-height: 1.5; }
    .system-notes { background: #111111; border: 1px solid #383838; border-radius: 4px; padding: 1rem; margin: .5rem 0; color: #cccccc; line-height: 1.75; overflow-wrap: anywhere; }
    .system-notes h4 { color: #75beff !important; margin: .15rem 0 .6rem; }
    .system-notes ul { margin: .35rem 0 .8rem 1.2rem; padding: 0; }
    .system-notes li { margin: .25rem 0; color: #cccccc; }
    .terminal-footer { border-top: 1px solid #3b3b3b; margin-top: 1.5rem; padding-top: .85rem; color: #999999; font-size: .74rem; line-height: 1.8; overflow-wrap: anywhere; }
    [data-testid="stAlert"] { border-radius: 4px; }
    [data-testid="stCode"] { border: 1px solid #3b3b3b; border-radius: 4px; }
    [data-testid="stCode"] pre { background: #050505 !important; color: #4cff4c !important; }
    hr { border-color: #3b3b3b !important; }

    @media (max-width: 900px) {
        .module-grid, .vt-stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 650px) {
        .module-grid, .vt-stat-grid, .result-grid { grid-template-columns: 1fr; }
        .terminal-body { padding: 1rem; }
        .evidence-head { align-items: flex-start; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="terminal-window">
      <div class="terminal-titlebar">
        <span class="terminal-dot" style="background:#e74856"></span>
        <span class="terminal-dot" style="background:#fce100"></span>
        <span class="terminal-dot" style="background:#13a10e"></span>
        <span class="terminal-title">Windows Terminal — Privacy Scan</span>
      </div>
      <div class="terminal-body">
        <div class="terminal-prompt">PS C:\\PRIVACY-SCAN&gt;</div>
        <div class="terminal-command">PRIVACY SCAN <span style="color:#75beff">v2.2.1</span></div>
        <div class="terminal-subtitle">웹사이트 개인정보 보호 문구 + VirusTotal URL 평판 검사</div>
        <div class="terminal-status">[OK] SYSTEM READY &nbsp; | &nbsp; [OK] POLICY MODULE &nbsp; | &nbsp; [READY] VIRUSTOTAL API</div>
      </div>
    </div>
    <div class="terminal-notice">
      <strong>검사 안내</strong><br>
      공개 웹페이지의 개인정보 처리방침 문구를 분석하고, 별도 동의를 받은 경우 VirusTotal 공개 API로 URL 평판을 조회합니다.
      이 도구는 사이트의 안전성이나 법 준수 여부를 보증하지 않습니다.
    </div>
    <div class="terminal-kicker">[ MODULES ]</div>
    <div class="module-grid">
      <div class="module-card"><div class="module-icon">[01]</div><div class="module-title">HTTPS / WEB</div><div class="module-desc">연결 방식, 응답 상태, 공개 웹페이지 확인</div></div>
      <div class="module-card"><div class="module-icon">[02]</div><div class="module-title">PRIVACY POLICY</div><div class="module-desc">처리방침 자동 탐색 및 11개 주제 문구 분석</div></div>
      <div class="module-card"><div class="module-icon">[03]</div><div class="module-title">VIRUSTOTAL</div><div class="module-desc">외부 보안 엔진의 URL 평판 및 탐지 결과 조회</div></div>
      <div class="module-card"><div class="module-icon">[04]</div><div class="module-title">EVIDENCE</div><div class="module-desc">일치한 표현과 원문 문맥을 결과에 표시</div></div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="terminal-kicker">[ TARGET ] Enter public website URL</div>', unsafe_allow_html=True)
url = st.text_input(
    "분석할 웹사이트 주소",
    placeholder="https://example.com",
    help="공개 웹사이트 주소를 입력하세요. 주소 앞에 https://를 생략해도 됩니다.",
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
    "VirusTotal에 URL을 전송하는 데 동의합니다. 조회·제출한 URL은 VirusTotal 커뮤니티 데이터셋에 추가되어 다른 사용자에게 공개될 수 있으며, 민감정보·개인정보가 포함된 URL은 전송하지 않겠습니다.",
    key="vt_public_share_consent",
)

if privacy_clicked:
    try:
        with st.spinner("[WEB] 공개 페이지 및 개인정보 처리방침 분석 중..."):
            result = analyze_website(url)
        st.session_state["last_scan_result"] = result
        st.session_state["last_scan_url"] = url.strip()
        st.success("[OK] 개인정보 처리방침 분석이 완료되었습니다.")
    except ScanError as exc:
        st.error(str(exc))
        st.caption("사이트가 자동 접속을 차단했거나 공개 HTML을 제공하지 않을 수 있습니다.")
    except Exception:
        st.error("예상하지 못한 오류가 발생했습니다. 주소와 배포 로그를 확인해 주세요.")

if vt_clicked:
    if not share_consent:
        st.warning("VirusTotal에 URL이 전송될 수 있다는 안내를 확인하고 동의해 주세요.")
    else:
        api_key = _get_virustotal_api_key()
        if not api_key:
            st.error(
                "VirusTotal API 키를 찾지 못했습니다. Streamlit Cloud의 App settings → Secrets에 "
                'VIRUSTOTAL_API_KEY = "발급받은 키" 를 등록해 주세요.'
            )
        else:
            try:
                with st.spinner("[VT] 기존 URL 평판 보고서를 조회하는 중..."):
                    vt_report = lookup_virustotal_url(api_key, url)
                st.session_state["vt_report"] = vt_report
                st.session_state["vt_report_url"] = url.strip()
                st.session_state.pop("vt_not_found_url", None)
                st.success("[OK] VirusTotal URL 보고서를 불러왔습니다.")
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

# Privacy policy results
result = st.session_state.get("last_scan_result")
last_scan_url = st.session_state.get("last_scan_url", "")
if result and last_scan_url == url.strip():
    current_topics = result.get("topic_results", []) or []
    policy = result.get("policy")
    policy_html = _policy_html(policy)

    # Refresh stale four-topic session results using the current 11-topic matcher.
    if policy_html and len(current_topics) < EXPECTED_TOPIC_COUNT:
        try:
            current_topics = analyze_policy_text(policy_html)
            result["topic_results"] = current_topics
            st.session_state["last_scan_result"] = result
        except Exception:
            pass

    st.markdown("---")
    st.markdown('<div class="terminal-kicker">[01] PRIVACY POLICY REPORT</div>', unsafe_allow_html=True)
    st.caption(f"요청 주소: {result.get('requested_url', '')}")
    st.caption(f"최종 주소: {result.get('final_url', '')}")

    topic_count = sum(1 for item in current_topics if _item_value(item, "found", False))
    topic_total = len(current_topics)
    policy_label = "본문 분석 완료" if policy is not None else ("링크 발견" if result.get("policy_links") else "링크 미발견")

    connection_label = "HTTPS 사용" if result.get("is_https") else "HTTP 사용"
    summary_cards = [
        ("CONNECTION", connection_label),
        ("POLICY", policy_label),
        ("TOPIC MATCH", f"{topic_count} / {topic_total}" if topic_total else "분석 불가"),
    ]
    summary_html = []
    for title, value in summary_cards:
        summary_html.append(
            '<div class="result-card"><h4>'
            + html.escape(title)
            + '</h4><p>'
            + html.escape(value)
            + "</p></div>"
        )
    st.markdown(
        '<div class="result-grid">' + "".join(summary_html) + "</div>",
        unsafe_allow_html=True,
    )

    if topic_total:
        st.markdown(
            '<div class="terminal-inline-note">11개 검사 주제 중 '
            + str(topic_count)
            + '개에서 설정된 표현을 발견했습니다.</div>',
            unsafe_allow_html=True,
        )

    st.markdown("#### [LINKS] 개인정보 처리방침 링크")
    if result.get("policy_links"):
        for item in result["policy_links"]:
            host_note = "같은 호스트 · 자동 분석 대상" if item.get("same_host") == "true" else "외부 호스트 · 자동 열람 생략"
            label = html.escape(str(item.get("label", "개인정보 처리방침")))
            link = html.escape(str(item.get("url", "")), quote=True)
            st.markdown(
                f'<div class="terminal-inline-note">• <a href="{link}" target="_blank" rel="noopener noreferrer">{label}</a> · {html.escape(host_note)}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("첫 페이지에서 개인정보 처리방침 링크를 찾지 못했습니다. 링크가 없다는 뜻은 아닙니다.")

    if result.get("policy_error"):
        st.warning(result["policy_error"])

    st.markdown("#### [EVIDENCE] 11개 항목별 근거")
    st.caption("아래는 설정된 표현과 일치하는지 확인한 결과입니다. 문구 발견만으로 정책의 충분성이나 적법성이 증명되지는 않습니다.")
    if current_topics:
        for item in current_topics:
            _render_policy_evidence(item)

# VirusTotal panel
st.markdown("---")
st.markdown('<div class="terminal-kicker">[02] VIRUSTOTAL URL REPUTATION</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="quota-panel">'
    '<div class="quota-title">PUBLIC API — DEFAULT BASIC QUOTA</div>'
    '<div class="quota-value">4 requests / minute &nbsp; | &nbsp; 500 requests / day</div>'
    '<div class="terminal-inline-note">비상업적·학술 목적의 공개 API 기본 안내치입니다. 계정별 실제 한도와 사용량은 VirusTotal 계정 페이지에서 확인하세요.</div>'
    '</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="terminal-inline-note">중요: VirusTotal에 조회하거나 제출한 URL은 커뮤니티 데이터셋에 포함되어 공개될 수 있습니다. 비공개 서비스 주소, 인증 토큰, 개인 식별 정보가 들어간 URL은 전송하지 마세요.</div>',
    unsafe_allow_html=True,
)

not_found_url = st.session_state.get("vt_not_found_url")
if not_found_url and not_found_url == current_normalized_url:
    st.warning("기존 VirusTotal 보고서를 찾지 못했습니다. 아래 버튼을 누르면 VirusTotal에 새 URL 검사 요청을 전송합니다.")
    if st.button("▶ SUBMIT NEW URL SCAN TO VIRUSTOTAL", type="primary", use_container_width=True, disabled=not share_consent):
        api_key = _get_virustotal_api_key()
        if not api_key:
            st.error("Streamlit Secrets에서 VIRUSTOTAL_API_KEY를 찾지 못했습니다.")
        else:
            try:
                with st.spinner("[VT] 새 검사 요청을 전송하는 중..."):
                    submitted_scan = submit_virustotal_url(api_key, url)
                st.session_state["vt_pending_scan"] = submitted_scan
                st.session_state.pop("vt_analysis_result", None)
                st.success("[OK] 새 URL 검사 요청을 전송했습니다.")
            except (VirusTotalError, ScanError) as exc:
                st.error(str(exc))

pending_scan = st.session_state.get("vt_pending_scan")
if pending_scan and pending_scan.get("url") == current_normalized_url:
    st.markdown("#### [VT] ANALYSIS JOB")
    st.code(pending_scan.get("analysis_id", ""), language=None)
    st.caption("분석이 완료되기까지 시간이 걸릴 수 있습니다. 상태 확인 버튼을 너무 자주 누르지 마세요. 확인 1회도 API 요청으로 계산됩니다.")
    if st.button("↻ CHECK ANALYSIS STATUS", use_container_width=True):
        api_key = _get_virustotal_api_key()
        if not api_key:
            st.error("Streamlit Secrets에서 VIRUSTOTAL_API_KEY를 찾지 못했습니다.")
        else:
            try:
                with st.spinner("[VT] 분석 상태를 확인하는 중..."):
                    analysis_result = get_virustotal_analysis(api_key, pending_scan["analysis_id"])
                st.session_state["vt_analysis_result"] = analysis_result
            except VirusTotalError as exc:
                st.error(str(exc))

analysis_result = st.session_state.get("vt_analysis_result")
if analysis_result and pending_scan and pending_scan.get("url") == current_normalized_url:
    status = str(analysis_result.get("status", "unknown")).lower()
    st.markdown(f"**ANALYSIS STATUS:** `{html.escape(status.upper())}`")
    if status == "completed":
        _render_terminal_stats(analysis_result.get("stats", {}))
        _render_engine_detections(analysis_result.get("results", {}))
    else:
        st.info("분석이 아직 진행 중입니다. 잠시 후 상태 확인 버튼을 다시 눌러 주세요.")

vt_report = st.session_state.get("vt_report")
vt_report_url = st.session_state.get("vt_report_url", "")
if vt_report and vt_report_url == current_normalized_url:
    attributes = vt_report.get("attributes", {})
    st.markdown("#### [REPORT] 기존 URL 평판 보고서")
    _render_terminal_stats(attributes.get("last_analysis_stats", {}))
    _render_engine_detections(attributes.get("last_analysis_results", {}))

    if attributes.get("last_analysis_date"):
        try:
            analyzed_at = datetime.fromtimestamp(
                int(attributes["last_analysis_date"]),
                tz=timezone.utc,
            )
            st.markdown(
                '<div class="terminal-inline-note">마지막 분석 시각(UTC): '
                + analyzed_at.strftime("%Y-%m-%d %H:%M:%S")
                + "</div>",
                unsafe_allow_html=True,
            )
        except (TypeError, ValueError, OSError):
            pass

    st.markdown(
        '<div class="terminal-inline-note">VirusTotal URL ID: '
        + html.escape(str(vt_report.get("url_id", "")))
        + "</div>",
        unsafe_allow_html=True,
    )
    st.caption("탐지 결과가 0이어도 안전을 보증하지 않습니다. 오탐 또는 미탐 가능성이 있습니다.")

# Static help panel replaces st.expander and st.link_button to avoid their
# extra frontend widgets and prevent the footer text from colliding.
st.markdown("---")
st.markdown('<div class="terminal-kicker">[ SYSTEM / API NOTES ]</div>', unsafe_allow_html=True)
st.markdown(
    """
    <div class="system-notes">
      <h4>VirusTotal API 한도 및 키 설정 방법</h4>
      <ul>
        <li>공개 API 기본 안내치: 분당 최대 4회, 하루 최대 500회 요청.</li>
        <li>공개 API는 비상업적·학술 목적의 이용 조건을 따라야 합니다.</li>
        <li>계정별 실제 한도 및 사용량은 VirusTotal 계정 화면에서 확인하세요.</li>
      </ul>
      <h4>Streamlit Secrets 설정</h4>
      <pre class="evidence-code">VIRUSTOTAL_API_KEY = "발급받은_API_키"</pre>
      <p>Streamlit Cloud의 App settings → Secrets에 등록하세요. API 키를 main.py에 직접 적거나 GitHub에 올리지 마세요.</p>
      <h4>사용 시 주의사항</h4>
      <ul>
        <li>VirusTotal에 조회·제출한 URL은 커뮤니티 데이터셋에 포함되어 공개될 수 있습니다.</li>
        <li>실제 개인정보, 인증 토큰, 비공개 주소가 들어간 URL은 조회하지 마세요.</li>
        <li>악성 탐지 결과가 없다는 것이 사이트의 안전을 보증하지는 않습니다.</li>
        <li>공개 API를 상업 서비스에 사용하지 마세요.</li>
      </ul>
      <p><a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener noreferrer">VirusTotal API 키 및 사용량 확인 페이지 열기 ↗</a></p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="terminal-footer">
      SAFETY: public URLs only · private IP blocking · redirect validation · request timeout · response-size limit · API key stored in Streamlit Secrets<br>
      PRIVACY SCAN v2.2.1 · WINDOWS TERMINAL EDITION · 11 POLICY TOPICS + VIRUSTOTAL URL REPUTATION
    </div>
    """,
    unsafe_allow_html=True,
)
