"""
Public targets maintained explicitly for security scanner testing.
All sites below have open policies permitting automated security testing.
Reachability verified 2026-06-06 — only responding targets are listed.
"""

TEST_TARGETS = [
    {
        "url": "http://testaspnet.vulnweb.com",
        "name": "Acunetix ASP.NET Test Site",
        "description": "ASP.NET app with OWASP Top 10 vulnerabilities",
        "stack": "ASP.NET",
    },
    {
        "url": "http://demo.testfire.net",
        "name": "IBM AltoroMutual (TestFire)",
        "description": "Fake bank app — CSRF, auth flaws, multi-page crawl target",
        "stack": "Java",
    },
]
