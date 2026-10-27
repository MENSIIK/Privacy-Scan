import streamlit as st
from scanner_core import ScanError, analyze_website

st.set_page_config(
    page_title="Privacy Scan | 개인정보 보호 자동 점검기",
    page_icon="🛡️",
    layout="wide",
)

# High-contrast black + neon-green theme with a blue primary action button.
st.markdown(
    """
    <style>
    :root {
        --bg: #050705;
        --panel: #0b110c;
        --panel-2: #101a12;
        --green: #39ff79;
        --green-soft: #b8ffc9;
        --muted: #91ab97;
        --line: #205b33;
        --blue: #1769ff;
        --blue-hover: #3980ff;
    }

    html, body, [data-testid="stAppViewContainer"], .stApp {
        background: var(--bg) !important;
        color: var(--green-soft) !important;
    }
    [data-testid="stHeader"] { background: rgba(5, 7, 5, 0.96) !important; }
    [data-testid="stSidebar"] { background: #080d09 !important; border-right: 1px solid var(--line); }
    [data-testid="stToolbar"] { right: 1rem; }
    [data-testid="stDecoration"] { background-image: linear-gradient(90deg, #39ff79, #1769ff) !important; }

    .stApp, .stApp p, .stApp li, .stApp label, .stApp [data-testid="stCaptionContainer"] {
        color: var(--green-soft);
    }
    h1, h2, h3, h4, h5, h6 {
        color: var(--green) !important;
        letter-spacing: 0.01em;
    }
    a { color: #70a6ff !important; }
    a:hover { color: #b4d0ff !important; }
    [data-testid="stCaptionContainer"] p, .small-muted { color: var(--muted) !important; }

    .hero {
        padding: 1.5rem 1.6rem;
        border: 1px solid var(--green);
        border-radius: 18px;
        background: radial-gradient(circle at 90% 0%, #10311a 0%, transparent 38%),
                    linear-gradient(135deg, #0b110c 0%, #07120b 65%, #091426 100%);
        box-shadow: 0 0 24px rgba(57, 255, 121, 0.10), inset 0 0 20px rgba(57, 255, 121, 0.025);
        margin: 0 0 1rem 0;
    }
    .hero .eyebrow {
        color: var(--green) !important;
        font-size: .78rem;
        font-weight: 800;
        letter-spacing: .17em;
        margin: 0 0 .45rem 0;
    }
    .hero h1 { margin: 0; font-size: clamp(1.65rem, 3vw, 2.35rem); color: #39ff79 !important; }
    .hero p { margin: .65rem 0 0; color: #b8ffc9 !important; font-size: 1rem; }

    .system-status {
        display: inline-block;
        border: 1px solid #267c43;
        color: var(--green) !important;
        background: #102619;
        padding: .35rem .6rem;
        border-radius: 8px;
        font-size: .75rem;
        font-weight: 800;
        letter-spacing: .07em;
        margin-top: .85rem;
    }
    .notice {
        border: 1px solid #28543a;
        background: #0a100b;
        border-left: 4px solid var(--green);
        color: #c4f5cf !important;
        padding: .85rem 1rem;
        border-radius: 10px;
        margin: .8rem 0 1.1rem;
    }
    .section-kicker {
        color: var(--green) !important;
        font-size: .78rem;
        font-weight: 800;
        letter-spacing: .14em;
        margin: .5rem 0 .75rem;
    }
    .module-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .75rem; margin: .8rem 0 1.2rem; }
    .module-card {
        border: 1px solid var(--line);
        background: linear-gradient(145deg, #0b110c, #0a100d);
        border-radius: 14px;
        padding: 1rem;
        min-height: 128px;
        box-shadow: 0 0 14px rgba(57,255,121,.035);
    }
    .module-card .module-icon { font-size: 1.55rem; margin-bottom: .45rem; }
    .module-card .module-title { color: #f1fff4 !important; font-weight: 800; margin-bottom: .35rem; }
    .module-card .module-desc { color: #91ab97 !important; font-size: .84rem; line-height: 1.4; }

    div[data-testid="stForm"] {
        background: #080d09;
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 1rem 1rem .75rem;
        box-shadow: 0 0 20px rgba(57,255,121,.045);
    }
    div[data-testid="stTextInput"] label, div[data-testid="stTextInput"] label p {
        color: var(--green) !important;
        font-weight: 700 !important;
    }
    div[data-testid="stTextInput"] input {
        background: #030503 !important;
        color: #b8ffc9 !important;
        border: 1px solid #267c43 !important;
        border-radius: 10px !important;
        min-height: 3rem;
        caret-color: var(--green);
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: var(--green) !important;
        box-shadow: 0 0 0 .18rem rgba(57,255,121,.15) !important;
    }
    div[data-testid="stTextInput"] input::placeholder { color: #66816d !important; }

    /* Make the main action button blue and visually dominant. */
    [data-testid="stFormSubmitButton"] button,
    [data-testid="stBaseButton-primary"],
    button[kind="primary"] {
        background: var(--blue) !important;
        color: #ffffff !important;
        border: 1px solid #5b96ff !important;
        border-radius: 10px !important;
        min-height: 3rem !important;
        font-weight: 800 !important;
        box-shadow: 0 5px 20px rgba(23,105,255,.28) !important;
        transition: background .15s ease, box-shadow .15s ease, transform .15s ease;
    }
    [data-testid="stFormSubmitButton"] button:hover,
    [data-testid="stBaseButton-primary"]:hover,
    button[kind="primary"]:hover {
        background: var(--blue-hover) !important;
        border-color: #91b8ff !important;
        box-shadow: 0 0 24px rgba(23,105,255,.45) !important;
        transform: translateY(-1px);
    }
    [data-testid="stFormSubmitButton"] button:focus-visible,
    [data-testid="stBaseButton-primary"]:focus-visible {
        outline: 3px solid #9cc2ff !important;
        outline-offset: 3px !important;
    }

    .result-card {
        border: 1px solid #267c43;
        background: linear-gradient(145deg, #0c150e, #0a100b);
        padding: 1.05rem;
        border-radius: 14px;
        min-height: 112px;
        box-shadow: 0 0 15px rgba(57,255,121,.05);
    }
    .result-card h4 { margin: 0 0 .55rem; color: var(--green) !important; font-size: .9rem; }
    .result-card p { margin: 0; color: #f1fff4 !important; font-size: 1.08rem; font-weight: 750; overflow-wrap: anywhere; }
    .scan-status { display: inline-block; padding: .28rem .5rem; border-radius: 7px; font-size: .76rem; font-weight: 800; line-height: 1.35; }
    .scan-status.found { color: #80ffab !important; background: #102b18; border: 1px solid #2e8a4c; }
    .scan-status.missing { color: #ffd98a !important; background: #2b2110; border: 1px solid #8d6822; }
    div[data-testid="stCode"] { border: 1px solid #205b33; border-radius: 9px; }
    div[data-testid="stCode"] pre { background: #030503 !important; color: #c4f5cf !important; }
    [data-testid="stVerticalBlockBorderWrapper"] { border-color: #205b33 !important; background: #080d09; border-radius: 12px; }
    [data-testid="stAlert"] { border-radius: 12px; }
    hr { border-color: #205b33 !important; }

    @media (max-width: 800px) {
        .module-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .hero { padding: 1.1rem; }
    }
    @media (max-width: 480px) {
        .module-grid { grid-template-columns: 1fr; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">WEB SECURITY ANALYZER</div>
      <h1>🛡️ PRIVACY SCAN</h1>
      <p>웹사이트 개인정보 보호 정보를 자동으로 점검합니다.</p>
      <div class="system-status">● SYSTEM READY</div>
    </div>
    <div class="notice">
      <strong>검사 안내</strong><br>
      공개 웹페이지와 개인정보 처리방침에서 확인 가능한 문구를 분석합니다.
      실제 보안성이나 법 준수 여부를 확정하는 도구는 아닙니다.
    </div>
    <div class="section-kicker">SCAN MODULES</div>
    <div class="module-grid">
      <div class="module-card"><div class="module-icon">🔒</div><div class="module-title">HTTPS 연결</div><div class="module-desc">연결 방식과 페이지 접속 여부 확인</div></div>
      <div class="module-card"><div class="module-icon">📄</div><div class="module-title">처리방침 탐색</div><div class="module-desc">개인정보 처리방침 링크 자동 검색</div></div>
      <div class="module-card"><div class="module-icon">🧭</div><div class="module-title">11개 주요 항목</div><div class="module-desc">수집·이용·보관·삭제 관련 안내 문구 검사</div></div>
      <div class="module-card"><div class="module-icon">🛡️</div><div class="module-title">권리·보호 조치</div><div class="module-desc">정보주체 권리, 위탁, 국외 이전 및 보호 조치 확인</div></div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="section-kicker">TARGET URL</div>', unsafe_allow_html=True)
with st.form("scan_form"):
    url = st.text_input(
        "분석할 웹사이트 주소",
        placeholder="https://example.com",
        help="공개 웹사이트 주소를 입력하세요. 주소 앞에 https://를 생략해도 됩니다.",
    )
    submitted = st.form_submit_button("🔎 검색 시작", type="primary", use_container_width=True)

if submitted:
    try:
        with st.spinner("공개 페이지를 확인하고 개인정보 처리방침을 찾는 중입니다..."):
            result = analyze_website(url)
        st.session_state["last_scan_result"] = result
        st.session_state["last_scan_url"] = url
    except ScanError as exc:
        st.error(str(exc))
        st.caption("확인되지 않은 웹사이트는 위험하다는 뜻이 아닙니다. 사이트가 자동 접속을 막았을 수도 있습니다.")
    except Exception:
        st.error("예상하지 못한 오류가 발생했습니다. 주소를 확인한 뒤 다시 시도해 주세요.")
        st.caption("오류 세부 내용은 화면에 노출하지 않았습니다.")

result = st.session_state.get("last_scan_result")
if result:
    st.markdown("---")
    st.markdown('<div class="section-kicker">ANALYSIS REPORT</div>', unsafe_allow_html=True)
    st.subheader("분석 결과")
    st.caption(f"입력 주소: {result['requested_url']}")
    st.caption(f"최종 주소: {result['final_url']}")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            '<div class="result-card"><h4>연결 방식</h4><p>'
            + ("HTTPS 사용" if result["is_https"] else "HTTP 사용")
            + "</p></div>",
            unsafe_allow_html=True,
        )
    with c2:
        internal_policy_found = result["policy"] is not None
        policy_link_found = bool(result["policy_links"])
        policy_label = "본문 분석 완료" if internal_policy_found else ("링크 발견" if policy_link_found else "링크 미발견")
        st.markdown(
            '<div class="result-card"><h4>개인정보 처리방침</h4><p>' + policy_label + "</p></div>",
            unsafe_allow_html=True,
        )
    with c3:
        topic_count = sum(1 for item in result["topic_results"] if item.found)
        topic_total = len(result["topic_results"])
        topic_label = f"{topic_count} / {topic_total}개 항목에서 근거 발견" if topic_total else "본문 분석 불가"
        st.markdown(
            '<div class="result-card"><h4>주요 안내 문구</h4><p>' + topic_label + "</p></div>",
            unsafe_allow_html=True,
        )

    if result["topic_results"]:
        st.progress(topic_count / topic_total, text=f"분석 항목 중 {topic_count}개에서 설정된 검색어와 일치하는 문구를 찾았습니다.")

    st.markdown("### 1. 개인정보 처리방침 링크")
    if result["policy_links"]:
        for item in result["policy_links"]:
            host_note = "같은 호스트 — 자동 분석 대상" if item["same_host"] == "true" else "외부 호스트 — 자동 열람 생략"
            st.markdown(f"- [{item['label']}]({item['url']}) · {host_note}")
    else:
        st.warning("첫 페이지에서 개인정보 처리방침으로 보이는 링크를 찾지 못했습니다. 링크가 없다는 사실을 의미하지는 않습니다.")

    if result["policy_error"]:
        st.warning(result["policy_error"])

    st.markdown("### 2. 개인정보 처리방침 항목별 근거 분석")
    st.caption("각 항목은 정해 둔 검색어와 표현 패턴을 기준으로 검사합니다. 문구가 발견되었다고 정책의 내용이 충분하거나 적법하다는 뜻은 아닙니다.")
    if result["topic_results"]:
        for item in result["topic_results"]:
            with st.container(border=True):
                left, right = st.columns([1, 3])
                with left:
                    st.markdown(f"**{item.topic}**")
                    if item.found:
                        st.markdown('<span class="scan-status found">● 근거 문구 발견</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="scan-status missing">○ 검색어 일치 문구 미발견</span>', unsafe_allow_html=True)
                with right:
                    if item.found:
                        st.caption("일치한 표현")
                        st.code(item.matched_phrase or "일치 표현 정보 없음", language=None)
                        st.caption("원문 문맥 — 일치한 표현 주변의 텍스트")
                        st.code(item.evidence or "근거 문맥을 추출하지 못했습니다.", language=None)
                        st.caption("자동 검색으로 발견한 문구입니다. 실제 개인정보 처리 방식의 안전성·법 준수 여부는 별도 확인이 필요합니다.")
                    else:
                        st.caption("설정된 검색어와 일치하는 표현을 찾지 못했습니다. 같은 의미가 다른 표현으로 작성되었거나 페이지 구조 때문에 탐지되지 않았을 수 있습니다.")
    elif result["policy_links"]:
        st.info("개인정보 처리방침 링크는 발견했지만, 같은 호스트에서 자동 분석할 수 있는 문서를 가져오지 못했습니다.")
    else:
        st.info("분석할 개인정보 처리방침 본문이 없어 세부 항목을 판정하지 않았습니다.")

    st.markdown("### 3. 결과 해석")
    st.write(
        f"이 화면은 개인정보 처리방침에서 {len(result['topic_results'])}개 주제와 관련된 문구가 발견되는지 요약합니다. "
        "'검색어와 일치하는 문구 미발견'은 해당 정책이 실제로 없다는 뜻이 아닙니다. 표현 방식이나 페이지 구조가 달라 자동 탐지되지 않을 수 있습니다. "
        "'근거 문구 발견'도 실제 처리 과정이 안전하거나 법을 준수한다는 증거는 아니므로 원문 정책과 서비스 설정을 함께 확인하세요."
    )

st.markdown("---")
st.caption(
    "안전장치: 로컬·사설 IP 차단, 리디렉션 목적지 재검사, 접속 시간 제한, HTML 응답 크기 제한, "
    "동일 호스트의 개인정보 처리방침 링크만 자동 분석. 실제 비밀번호나 개인정보를 입력하지 마세요."
)
