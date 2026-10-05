from fastapi import FastAPI, Query
from playwright.async_api import (
    async_playwright,
    TimeoutError as PlaywrightTimeoutError,
)

from app.detector import AntiBotDetector


app = FastAPI(
    title="Web Guard Checker",
    description="Check whether a website blocks browser automation",
    version="1.0.0",
)

detector = AntiBotDetector()


@app.get("/")
async def root():
    return {
        "service": "web-guard-checker",
        "status": "running",
        "usage": "/check?url=https://example.com",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
    }


@app.get("/check")
async def check_url(
    url: str = Query(
        ...,
        description="Website URL to check",
    ),
    timeout_ms: int = Query(
        20000,
        ge=1000,
        le=60000,
    ),
    headless: bool = Query(
        True,
        description="Run Chromium headless or visible",
    ),
):
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=headless,
            )

            try:
                context = await browser.new_context(
                    viewport={
                        "width": 1280,
                        "height": 800,
                    },
                )

                page = await context.new_page()

                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )

                # Give JavaScript a little time to render challenge pages.
                await page.wait_for_timeout(2000)

                title = await page.title()
                html = await page.content()
                final_url = page.url

                try:
                    body_text = await page.locator("body").inner_text(
                        timeout=3000,
                    )
                except Exception:
                    body_text = ""

                status_code = response.status if response else None

                detection = detector.detect(
                    title=title,
                    html=html,
                    body_text=body_text,
                    status_code=status_code,
                    final_url=final_url,
                )

                return {
                    "success": True,
                    "requested_url": url,
                    "final_url": final_url,
                    "status_code": status_code,
                    "title": title,
                    "accessible": detection.accessible,
                    "blocked": detection.blocked,
                    "provider": detection.provider,
                    "reason": detection.reason,
                    "detected_signals": detection.signals,
                    "html_length": len(html),
                    "body_preview": body_text[:500],
                }

            finally:
                await browser.close()

    except PlaywrightTimeoutError:
        return {
            "success": False,
            "requested_url": url,
            "accessible": False,
            "blocked": True,
            "provider": "unknown",
            "reason": "Navigation timeout",
            "detected_signals": [
                "navigation_timeout",
            ],
        }

    except Exception as exc:
        return {
            "success": False,
            "requested_url": url,
            "accessible": False,
            "blocked": False,
            "provider": None,
            "reason": "checker_error",
            "error": str(exc),
            "detected_signals": [
                "checker_error",
            ],
        }
