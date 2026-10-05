from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    blocked: bool
    accessible: bool
    provider: Optional[str]
    reason: str
    signals: list[str]


class AntiBotDetector:
    def detect(
        self,
        *,
        title: str,
        html: str,
        body_text: str = "",
        status_code: int | None,
        final_url: str,
    ) -> DetectionResult:
        title_l = (title or "").lower()
        html_l = (html or "").lower()
        body_l = (body_text or "").lower()
        url_l = (final_url or "").lower()

        combined = "\n".join(
            [
                title_l,
                html_l,
                body_l,
                url_l,
            ]
        )

        signals: list[str] = []

        # ------------------------------------------------------------
        # Cloudflare
        # ------------------------------------------------------------
        cloudflare_patterns = {
            "just a moment": "cloudflare:just a moment",
            "performing security verification": "cloudflare:performing security verification",
            "security verification": "cloudflare:security verification",
            "cloudflare": "cloudflare:cloudflare",
            "ray id:": "cloudflare:ray id:",
            "cf-chl-": "cloudflare:cf-chl-",
            "cf_chl_": "cloudflare:cf_chl_",
            "challenge-platform": "cloudflare:challenge-platform",
            "/cdn-cgi/challenge-platform/": "cloudflare:/cdn-cgi/challenge-platform/",
        }

        cloudflare_hits = 0

        for pattern, signal in cloudflare_patterns.items():
            if pattern in combined:
                signals.append(signal)
                cloudflare_hits += 1

        # Strong Cloudflare challenge evidence.
        if (
            cloudflare_hits >= 2
            or "just a moment" in title_l
            or "/cdn-cgi/challenge-platform/" in combined
            or "cf-chl-" in combined
            or "cf_chl_" in combined
        ):
            if status_code is not None:
                signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider="cloudflare",
                reason="Cloudflare security challenge detected",
                signals=self._unique(signals),
            )

        # ------------------------------------------------------------
        # CAPTCHA / generic bot checks
        # ------------------------------------------------------------
        captcha_patterns = {
            "captcha": "generic:captcha",
            "recaptcha": "google:recaptcha",
            "hcaptcha": "hcaptcha:hcaptcha",
            "verify you are human": "generic:verify you are human",
            "verify that you are human": "generic:verify that you are human",
            "are you a robot": "generic:are you a robot",
            "security verification": "generic:security verification",
            "unusual traffic": "generic:unusual traffic",
            "automated requests": "generic:automated requests",
        }

        captcha_hits = 0

        for pattern, signal in captcha_patterns.items():
            if pattern in combined:
                signals.append(signal)
                captcha_hits += 1

        if captcha_hits > 0:
            if status_code is not None:
                signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider="captcha",
                reason="CAPTCHA or human verification detected",
                signals=self._unique(signals),
            )

        # ------------------------------------------------------------
        # DataDome
        # ------------------------------------------------------------
        datadome_patterns = [
            "datadome",
            "geo.captcha-delivery.com",
            "captcha-delivery.com",
        ]

        if any(pattern in combined for pattern in datadome_patterns):
            signals.append("datadome:detected")

            if status_code is not None:
                signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider="datadome",
                reason="DataDome anti-bot protection detected",
                signals=self._unique(signals),
            )

        # ------------------------------------------------------------
        # PerimeterX / HUMAN Security
        # ------------------------------------------------------------
        perimeterx_patterns = [
            "perimeterx",
            "_pxhd",
            "_pxvid",
            "px-captcha",
            "human security",
        ]

        if any(pattern in combined for pattern in perimeterx_patterns):
            signals.append("perimeterx:detected")

            if status_code is not None:
                signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider="perimeterx",
                reason="PerimeterX/HUMAN anti-bot protection detected",
                signals=self._unique(signals),
            )

        # ------------------------------------------------------------
        # Imperva / Incapsula
        # ------------------------------------------------------------
        imperva_patterns = [
            "incapsula",
            "imperva",
            "_incap_ses_",
            "visid_incap_",
        ]

        if any(pattern in combined for pattern in imperva_patterns):
            signals.append("imperva:detected")

            if status_code is not None:
                signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider="imperva",
                reason="Imperva/Incapsula protection detected",
                signals=self._unique(signals),
            )

        # ------------------------------------------------------------
        # Akamai
        # ------------------------------------------------------------
        akamai_patterns = [
            "akamai bot manager",
            "akamai",
            "_abck",
            "bm_sz",
        ]

        if any(pattern in combined for pattern in akamai_patterns):
            signals.append("akamai:detected")

            if status_code in (403, 429):
                signals.append(f"http_status:{status_code}")

                return DetectionResult(
                    blocked=True,
                    accessible=False,
                    provider="akamai",
                    reason="Akamai anti-bot protection detected",
                    signals=self._unique(signals),
                )

        # ------------------------------------------------------------
        # HTTP responses that usually mean access was denied.
        # Keep provider unknown unless there is provider-specific evidence.
        # ------------------------------------------------------------
        if status_code == 429:
            signals.append("http_status:429")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider=None,
                reason="HTTP 429 Too Many Requests",
                signals=self._unique(signals),
            )

        if status_code == 403:
            signals.append("http_status:403")

            return DetectionResult(
                blocked=True,
                accessible=False,
                provider=None,
                reason="HTTP 403 Forbidden",
                signals=self._unique(signals),
            )

        if status_code in (401, 407):
            signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=False,
                accessible=False,
                provider=None,
                reason=f"HTTP {status_code} authentication/proxy access required",
                signals=self._unique(signals),
            )

        if status_code is not None and status_code >= 500:
            signals.append(f"http_status:{status_code}")

            return DetectionResult(
                blocked=False,
                accessible=False,
                provider=None,
                reason=f"Server returned HTTP {status_code}",
                signals=self._unique(signals),
            )

        # ------------------------------------------------------------
        # Normal page
        # ------------------------------------------------------------
        if status_code is not None:
            signals.append(f"http_status:{status_code}")

        return DetectionResult(
            blocked=False,
            accessible=True,
            provider=None,
            reason="No anti-bot challenge detected",
            signals=self._unique(signals),
        )

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))
