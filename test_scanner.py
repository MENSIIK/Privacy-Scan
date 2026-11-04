import base64
import socket
import unittest

from unittest.mock import Mock, patch

import scanner_core

from scanner_core import (
    FetchResult,
    ScanError,
    VirusTotalError,
    VirusTotalNotFoundError,
    analyze_policy_text,
    analyze_website,
    find_privacy_policy_links,
    get_virustotal_analysis,
    lookup_virustotal_url,
    normalize_url,
    submit_virustotal_url,
    virustotal_url_id,
)


# ==========================================
# URL TESTS
# ==========================================

class URLTests(unittest.TestCase):

    def test_adds_https_when_scheme_missing(self):
        self.assertEqual(
            normalize_url("example.com"),
            "https://example.com/",
        )

    def test_removes_fragment(self):
        self.assertEqual(
            normalize_url(
                "https://example.com/page#section"
            ),
            "https://example.com/page",
        )

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ScanError):
            normalize_url("file:///etc/passwd")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ScanError):
            normalize_url(
                "https://user:password@example.com"
            )

    def test_rejects_localhost(self):
        with self.assertRaises(ScanError):
            normalize_url(
                "http://localhost:8501"
            )

    def test_rejects_nonstandard_ports(self):
        with self.assertRaises(ScanError):
            normalize_url(
                "https://example.com:8443"
            )

    def test_rejects_private_ip_literal(self):
        with self.assertRaises(ScanError):
            normalize_url(
                "http://192.168.0.10"
            )

    def test_blocks_private_dns_answer(self):
        private_info = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("127.0.0.1", 443),
            )
        ]

        with patch(
            "scanner_core.socket.getaddrinfo",
            return_value=private_info,
        ):
            with self.assertRaises(ScanError):
                scanner_core._resolve_public_addresses(
                    "example.test",
                    443,
                )


# ==========================================
# PRIVACY POLICY TESTS
# ==========================================

class ParsingTests(unittest.TestCase):

    def test_finds_same_host_privacy_policy_link(self):
        html = (
            '<html><body>'
            '<a href="/privacy">개인정보 처리방침</a>'
            '</body></html>'
        )

        links = find_privacy_policy_links(
            html,
            "https://example.com/",
        )

        self.assertEqual(len(links), 1)

        self.assertEqual(
            links[0]["url"],
            "https://example.com/privacy",
        )

        self.assertEqual(
            links[0]["same_host"],
            "true",
        )

    def test_finds_privacy_policy_when_hyphenated_url_is_used(self):
        html = (
            '<html><body>'
            '<a href="/privacy-policy">Privacy</a>'
            '</body></html>'
        )

        links = find_privacy_policy_links(
            html,
            "https://example.com/",
        )

        self.assertEqual(len(links), 1)

        self.assertEqual(
            links[0]["url"],
            "https://example.com/privacy-policy",
        )

    def test_flags_external_policy_link_without_fetching_it_here(self):
        html = (
            '<html><body>'
            '<a href="https://privacy-vendor.example/policy">'
            'Privacy Policy'
            '</a>'
            '</body></html>'
        )

        links = find_privacy_policy_links(
            html,
            "https://example.com/",
        )

        self.assertEqual(len(links), 1)

        self.assertEqual(
            links[0]["same_host"],
            "false",
        )

    def test_finds_topic_phrases_and_ignores_script_text(self):
        html = """
        <html>
          <body>
            개인정보 수집 목적을 안내합니다.
            개인정보 보유 기간은 1년입니다.
            제3자 제공은 별도로 안내합니다.
            개인정보 파기 절차를 운영합니다.

            <script>
              제3자 제공 보관 기간 개인정보 파기
            </script>
          </body>
        </html>
        """

        results = analyze_policy_text(html)

        self.assertEqual(len(results), 11)

        found_topics = {
            item.topic
            for item in results
            if item.found
        }

        self.assertTrue(
            {
                "수집 목적",
                "보관 기간",
                "제3자 제공",
                "삭제·파기 방법",
            }.issubset(found_topics)
        )

        purpose = next(
            item
            for item in results
            if item.topic == "수집 목적"
        )

        self.assertIn(
            "수집 목적",
            purpose.evidence,
        )

        self.assertTrue(
            purpose.matched_phrase
        )

    def test_detects_expanded_privacy_topics(self):
        html = """
        <html>
          <body>
            <p>수집 항목: 이름과 이메일</p>
            <p>개인정보 처리 업무 위탁 안내</p>
            <p>정보주체의 열람 및 정정 권리</p>
            <p>개인정보 보호책임자 문의처</p>
            <p>개인정보 국외 이전에 관한 안내</p>
            <p>쿠키를 통해 자동 수집되는 정보</p>
            <p>개인정보 안전성 확보 조치</p>
          </body>
        </html>
        """

        results = {
            item.topic: item
            for item in analyze_policy_text(html)
        }

        expected = [
            "개인정보 수집 항목",
            "개인정보 처리 위탁",
            "정보주체 권리 및 행사 방법",
            "개인정보 보호책임자·문의처",
            "국외 이전",
            "쿠키·자동 수집 정보",
            "안전성 확보 조치",
        ]

        for topic in expected:
            with self.subTest(topic=topic):
                self.assertTrue(
                    results[topic].found
                )

                self.assertTrue(
                    results[topic].evidence
                )

                self.assertTrue(
                    results[topic].matched_phrase
                )

    def test_unrelated_text_does_not_match_topics(self):
        results = analyze_policy_text(
            "<html><body>"
            "<p>회사 소개 및 고객센터</p>"
            "</body></html>"
        )

        self.assertTrue(
            all(not item.found for item in results)
        )

    def test_end_to_end_analysis_with_mocked_pages(self):

        home = FetchResult(
            requested_url="https://example.test/",
            final_url="https://example.test/",
            status=200,
            content_type="text/html",
            html=(
                '<html><a href="/privacy">'
                '개인정보 처리방침'
                '</a></html>'
            ),
        )

        policy = FetchResult(
            requested_url="https://example.test/privacy",
            final_url="https://example.test/privacy",
            status=200,
            content_type="text/html",
            html=(
                "<html><body>"
                "개인정보 수집 목적, 보관 기간, "
                "제3자 제공, 파기 절차"
                "</body></html>"
            ),
        )

        with patch(
            "scanner_core.fetch_public_html",
            side_effect=[home, policy],
        ):
            result = analyze_website(
                "https://example.test"
            )

        self.assertTrue(
            result["is_https"]
        )

        self.assertIsNotNone(
            result["policy"]
        )

        self.assertEqual(
            len(result["topic_results"]),
            11,
        )

        found_topics = {
            item.topic
            for item in result["topic_results"]
            if item.found
        }

        self.assertTrue(
            {
                "수집 목적",
                "보관 기간",
                "제3자 제공",
                "삭제·파기 방법",
            }.issubset(found_topics)
        )


# ==========================================
# VIRUSTOTAL API TESTS
# ==========================================

class VirusTotalTests(unittest.TestCase):

    def make_response(
        self,
        status_code,
        payload,
    ):
        response = Mock()

        response.status_code = status_code

        response.ok = (
            200 <= status_code < 300
        )

        response.json.return_value = payload

        return response

    def test_url_id_is_unpadded_urlsafe_base64(self):
        url = "https://example.com/"

        expected = (
            base64.urlsafe_b64encode(
                url.encode()
            )
            .decode()
            .rstrip("=")
        )

        result = virustotal_url_id(url)

        self.assertEqual(
            result,
            expected,
        )

        self.assertNotIn(
            "=",
            result,
        )

    @patch("scanner_core.requests.request")
    def test_lookup_existing_url_report(
        self,
        request_mock,
    ):

        request_mock.return_value = self.make_response(
            200,
            {
                "data": {
                    "id": "sample-url-id",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "harmless": 5,
                        },
                        "last_analysis_results": {},
                    },
                }
            },
        )

        report = lookup_virustotal_url(
            "test-key",
            "https://example.com",
        )

        self.assertEqual(
            report["url_id"],
            "sample-url-id",
        )

        self.assertEqual(
            report["attributes"][
                "last_analysis_stats"
            ]["malicious"],
            1,
        )

        self.assertEqual(
            request_mock.call_args.kwargs[
                "headers"
            ]["x-apikey"],
            "test-key",
        )

    @patch("scanner_core.requests.request")
    def test_lookup_raises_not_found_for_unknown_url(
        self,
        request_mock,
    ):

        request_mock.return_value = self.make_response(
            404,
            {
                "error": {
                    "code": "NotFoundError"
                }
            },
        )

        with self.assertRaises(
            VirusTotalNotFoundError
        ):
            lookup_virustotal_url(
                "test-key",
                "https://unknown.example",
            )

    @patch("scanner_core.requests.request")
    def test_submit_new_url_scan(
        self,
        request_mock,
    ):

        request_mock.return_value = self.make_response(
            200,
            {
                "data": {
                    "id": "analysis-123",
                    "attributes": {
                        "status": "queued"
                    },
                }
            },
        )

        submitted = submit_virustotal_url(
            "test-key",
            "https://example.com",
        )

        self.assertEqual(
            submitted["analysis_id"],
            "analysis-123",
        )

        self.assertEqual(
            submitted["status"],
            "queued",
        )

        self.assertEqual(
            request_mock.call_args.kwargs[
                "data"
            ]["url"],
            "https://example.com/",
        )

        self.assertEqual(
            request_mock.call_args.kwargs[
                "method"
            ],
            "POST",
        )

    @patch("scanner_core.requests.request")
    def test_get_analysis_status_and_results(
        self,
        request_mock,
    ):

        request_mock.return_value = self.make_response(
            200,
            {
                "data": {
                    "id": "analysis-123",
                    "attributes": {
                        "status": "completed",
                        "stats": {
                            "malicious": 0,
                            "harmless": 8,
                        },
                        "results": {},
                    },
                }
            },
        )

        analysis = get_virustotal_analysis(
            "test-key",
            "analysis-123",
        )

        self.assertEqual(
            analysis["status"],
            "completed",
        )

        self.assertEqual(
            analysis["stats"]["harmless"],
            8,
        )

    @patch("scanner_core.requests.request")
    def test_rate_limit_error_has_clear_message(
        self,
        request_mock,
    ):

        request_mock.return_value = self.make_response(
            429,
            {
                "error": {
                    "code": "QuotaExceededError"
                }
            },
        )

        with self.assertRaises(
            VirusTotalError
        ) as context:

            lookup_virustotal_url(
                "test-key",
                "https://example.com",
            )

        self.assertIn(
            "분당 4회",
            str(context.exception),
        )

    def test_missing_api_key_is_rejected_without_request(self):

        with patch(
            "scanner_core.requests.request"
        ) as request_mock:

            with self.assertRaises(
                VirusTotalError
            ):
                lookup_virustotal_url(
                    "",
                    "https://example.com",
                )

            request_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
