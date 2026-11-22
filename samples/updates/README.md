# Update samples (Guard demo)

Newer builds of two sample extensions, used by `python -m blindspot demo-fleet`:

| Extension | Approved | Update | What Guard does |
| --- | --- | --- | --- |
| Quick Translate | 1.9.0 | 1.9.1 adds a helper function, nothing else | approves it automatically |
| Corp SSO Helper | 1.0.4 | 1.0.5 adds `cookies`, `<all_urls>` and a new server, same extension ID | quarantines it |

The 1.0.5 build is modelled on the Cyberhaven incident (December 2024): an attacker published a
new version under the same ID, so allowlists kept trusting it. It is inert (never loaded by a
browser) and its server uses the reserved `.invalid` domain.
