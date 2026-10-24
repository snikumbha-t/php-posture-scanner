# PHP Posture Scanner

**Live demo:** https://snikumbha-t.github.io/php-posture-scanner/

Enter a website address and the scanner reports whether the site runs PHP, then gives it a grade from A to F with a prioritised action plan. Every fix includes the exact config line to add.

## What's here

| Path | What it is |
|---|---|
| `index.html` | Interactive demo with four fictional sample sites. Any other address gets a simulated report, and the demo never contacts a real website. |
| `scanner/` | The real scanner, a small PHP app that makes live requests to the address you enter. |

## Run the real scanner

You need PHP 8.0 or later with the cURL extension.

    cd scanner
    php -S localhost:8000

Then open http://localhost:8000.

## What it checks

- **PHP detection:** looks for the X-Powered-By header, the PHPSESSID cookie, links to .php pages and WordPress XML-RPC.
- **PHP version:** reports the exact version when the site discloses it and flags versions that no longer get security fixes.
- **App stack:** identifies the web server, plus WordPress, Laravel, Drupal, Joomla, Symfony and Magento.
- **HTTPS:** checks the site uses HTTPS and that plain HTTP redirects to it.
- **Server version:** flags when the web server reveals its software version.
- **Security headers:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy.
- **Cookie flags:** HttpOnly, Secure and SameSite.
- **Exposed files:** `.env`, `.git/config`, `composer.json` and `composer.lock`, phpinfo pages, `.htaccess`, config backups and `server-status`. Each one is checked by its content to avoid false alarms.

## Scope

The scanner only makes the same ordinary requests a browser makes. It sends no attack traffic, injection strings or password guesses, and it refuses internal or private addresses.

**Only scan sites you own or have permission to test.**
