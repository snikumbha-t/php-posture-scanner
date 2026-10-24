# PHP Posture Scanner

**Live:** https://snikumbha-t.github.io/php-posture-scanner/

Enter a website address and get a real security-posture report: whether the site runs PHP, its version/EOL status, security headers, cookie flags, information disclosure, and publicly-exposed sensitive files — graded A–F with a prioritised action plan where every fix includes the exact config line to add.

## What's here

| Path | What it is |
|---|---|
| `index.html` | **The real front-end.** Calls a live scanning backend and renders a genuine report — no simulation. On first use, set the *Backend API* field to your deployed backend URL (remembered in your browser), or use `?api=https://your-backend`. |
| `demo.html` | The old interactive demo. It never contacts a real website — any address gets a report *simulated from its name*. Kept for reference. |
| `scanner/` | An early PHP version of the real scanner. |

## Important: Pages can't run PHP

GitHub Pages serves static files only, so it **cannot run the scanning backend** — it can only host `index.html`. To get real results you deploy the PHP backend somewhere and point this page at it.

The full, maintained backend lives in **[php-posture-scanner-enterprise](https://github.com/snikumbha-t/php-posture-scanner-enterprise)** and deploys in one command:

```bash
# Fly.io
fly launch --copy-config --now
# or Docker anywhere
docker compose up --build -d        # http://localhost:8080
```

Then open this page, paste the backend URL into *Backend API*, and scan. (Set `PVC_CORS_ORIGIN=https://snikumbha-t.github.io` on the backend to lock the API to this page.)

Until a backend URL is set, the page honestly tells you to set one — it does not fabricate results.

## Ethics

Scan only sites you own or are authorised to test. The backend makes ordinary GET/HEAD requests and reads only public responses — no exploits, no brute-forcing.
