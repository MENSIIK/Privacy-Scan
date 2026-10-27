import streamlit as st
from scanner_core import ScanError, analyze_website

st.set_page_config(
    page_title="웹사이트 개인정보 보호 정보 자동 점검기",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp { background: linear-gradient(180deg, #0b1220 0%, #101b2d 100%); color: #edf3fb; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    [data-testid="stSidebar"] { background-color: #101827; }
    .hero { padding: 1.35rem 1.5rem; border: 1px solid #28384f; border-radius: 18px;
            background: linear-gradient(135deg, #14243a, #122d36); margin-bottom: 1rem; }
    .hero h1 { margin: 0; font-size: 2rem; color: #f4f8ff; }
    .hero p { margin: .55rem 0 0 0; color: #b8c9dc; }
    .small-muted { color: #aabbd0; font-size: .9rem; }
    .result-card { border: 1px solid #2c4058; background: rgba(20, 35, 54, .82);
                   padding: 1rem; border-radius: 14px; min-height: 100px; }
    .result-card h4 { margin: 0 0 .5rem 0; color: #b7cbe1; font-size: .95rem; }
    .result-card p { margin: 0; color: #f1f6fc; font-size: 1.05rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <h1>🛡️ 웹사이트 개인정보 보호 정보 자동 점검기</h1>
      <p>공개 웹페이지와 개인정보 처리방침에서 주요 안내 문구를 찾아 확인합니다.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.info(
    "학습용 도구입니다. 사이트의 실제 보안성이나 법 준수 여부를 확정하지 않습니다. "
    "분석 결과는 공개된 HTML에서 관련 문구를 찾았는지에 대한 참고 정보입니다."
)

with st.form("scan_form"):
    url = st.text_input(
        "분석할 웹사이트 주소",
        placeholder="https://example.com",
        help="공개 웹사이트 주소를 입력하세요. 주소 앞에 https://를 생략해도 됩니다.",
    )
    submitted = st.form_submit_button("🔍 자동 분석 시작", type="primary", use_container_width=True)

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
        topic_label = f"{topic_count} / {len(result['topic_results'])}개 항목에서 문구 발견" if result["topic_results"] else "본문 분석 불가"
        st.markdown(
            '<div class="result-card"><h4>주요 안내 문구</h4><p>' + topic_label + "</p></div>",
            unsafe_allow_html=True,
        )

    st.markdown("### 1. 개인정보 처리방침 링크")
    if result["policy_links"]:
        for item in result["policy_links"]:
            host_note = "같은 호스트 — 자동 분석 대상" if item["same_host"] == "true" else "외부 호스트 — 자동 열람 생략"
            st.markdown(f"- [{item['label']}]({item['url']}) · {host_note}")
    else:
        st.warning("첫 페이지에서 개인정보 처리방침으로 보이는 링크를 찾지 못했습니다. 링크가 없다는 사실을 의미하지는 않습니다.")

    if result["policy_error"]:
        st.warning(result["policy_error"])

    st.markdown("### 2. 주요 안내 문구 검사")
    if result["topic_results"]:
        for item in result["topic_results"]:
            with st.container(border=True):
                left, right = st.columns([1, 3])
                with left:
                    st.markdown(f"**{item.topic}**")
                    st.write("✅ 관련 문구 발견" if item.found else "⚪ 관련 문구를 찾지 못함")
                with right:
                    if item.evidence:
                        st.caption("발견 근거 일부")
                        st.write("…" + item.evidence + "…")
                    else:
                        st.caption("분석된 문서에서 설정한 검색어와 일치하는 문구를 찾지 못했습니다.")
    elif result["policy_links"]:
        st.info("개인정보 처리방침 링크는 발견했지만, 같은 호스트에서 자동 분석할 수 있는 문서를 가져오지 못했습니다.")
    else:
        st.info("분석할 개인정보 처리방침 본문이 없어 세부 항목을 판정하지 않았습니다.")

    st.markdown("### 3. 결과 해석")
    st.write(
        "이 화면은 확인 가능한 공개 문구를 요약합니다. '문구를 찾지 못함'은 해당 정책이 실제로 없다는 뜻이 아니며, "
        "'문구 발견'도 실제 처리 과정이 안전하다는 증거는 아닙니다. 중요한 판단은 원문 정책과 서비스 설정을 함께 확인하세요."
    )

st.markdown("---")
st.caption(
    "안전장치: 로컬·사설 IP 차단, 리디렉션 목적지 재검사, 접속 시간 제한, HTML 응답 크기 제한, "
    "동일 호스트의 개인정보 처리방침 링크만 자동 분석. 실제 비밀번호나 개인정보를 입력하지 마세요."
)
