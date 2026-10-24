<?php
/**
 * PHP Posture Scanner — passive security fingerprinting & reporting.
 *
 * This performs ONLY passive, observational checks (HTTP GET/HEAD requests,
 * the same traffic an ordinary browser makes). It sends no exploit payloads,
 * no injection strings, no brute force. It is intended for site owners and
 * authorised testers to review a site's public security posture.
 */

declare(strict_types=1);

class PhpPostureScanner
{
    private string $userAgent = 'PhpPostureScanner/1.0 (+passive security check)';
    private int $timeout = 12;

    /** Well-known paths that should normally NOT be publicly readable. */
    private array $sensitivePaths = [
        '/.env'            => 'Environment file (may leak DB creds, API keys, APP_KEY)',
        '/.git/config'     => 'Exposed Git repository (full source code can be downloaded)',
        '/composer.json'   => 'Dependency manifest (reveals exact library versions)',
        '/composer.lock'   => 'Locked dependency versions (reveals exact library versions)',
        '/phpinfo.php'     => 'phpinfo() page (leaks full server configuration)',
        '/info.php'        => 'phpinfo() page (leaks full server configuration)',
        '/.htaccess'       => 'Apache config served as text (should be denied)',
        '/wp-config.php.bak'=> 'WordPress config backup (may leak DB credentials)',
        '/config.php.bak'  => 'Config backup (may leak credentials)',
        '/server-status'   => 'Apache mod_status (leaks live request data)',
    ];

    /** PHP branch end-of-life dates (security support end). */
    private array $phpEol = [
        '5.6' => '2018-12-31', '7.0' => '2019-01-10', '7.1' => '2019-12-01',
        '7.2' => '2020-11-30', '7.3' => '2021-12-06', '7.4' => '2022-11-28',
        '8.0' => '2023-11-26', '8.1' => '2025-12-31', '8.2' => '2026-12-31',
        '8.3' => '2027-12-31', '8.4' => '2028-12-31',
    ];

    public function scan(string $rawUrl): array
    {
        $url = $this->normaliseUrl($rawUrl);
        if ($url === null) {
            return ['error' => 'That does not look like a valid http(s) URL.'];
        }
        if ($this->isPrivateHost((string) parse_url($url, PHP_URL_HOST))) {
            return ['error' => 'Internal, private or loopback addresses cannot be scanned.'];
        }

        $main = $this->request($url, 'GET');
        if ($main['error']) {
            return ['error' => 'Could not reach the site: ' . $main['error']];
        }

        $report = [
            'input'       => $rawUrl,
            'final_url'   => $main['final_url'],
            'scanned_at'  => gmdate('Y-m-d H:i:s') . ' UTC',
            'headers'     => $main['headers'],
            'status'      => $main['status'],
            'findings'    => [],
            'tech'        => [],
            'is_php'      => false,
            'php_version' => null,
        ];

        $php = $this->detectPhp($main, $url);
        $report['is_php']      = $php['is_php'];
        $report['php_version'] = $php['version'];
        $report['tech']        = $this->detectStack($main);

        // ---- Findings ----
        $f = [];
        $f = array_merge($f, $php['findings']);
        $f = array_merge($f, $this->checkHttps($url, $main));
        $f = array_merge($f, $this->checkServerDisclosure($main));
        $f = array_merge($f, $this->checkSecurityHeaders($main));
        $f = array_merge($f, $this->checkCookies($main));
        $f = array_merge($f, $this->checkSensitiveFiles($url));

        $report['findings'] = $f;
        $report['score']    = $this->score($f);
        return $report;
    }

    // ------------------------------------------------------------------ PHP

    private function detectPhp(array $main, string $url): array
    {
        $signals = [];
        $version = null;
        $h = $main['headers'];

        if (isset($h['x-powered-by']) && stripos($h['x-powered-by'], 'php') !== false) {
            $signals[] = 'X-Powered-By header advertises PHP';
            if (preg_match('#PHP/([0-9]+\.[0-9]+\.[0-9]+)#i', $h['x-powered-by'], $m)) {
                $version = $m[1];
            }
        }
        foreach ($main['set_cookie'] as $c) {
            if (stripos($c, 'PHPSESSID') !== false) {
                $signals[] = 'PHPSESSID session cookie present';
                break;
            }
        }
        if (preg_match('#\.php(\?|"|\'|\s|/|$)#i', $main['body'])) {
            $signals[] = 'Links to .php resources found in the page';
        }
        if (isset($h['x-pingback']) && stripos($h['x-pingback'], 'xmlrpc.php') !== false) {
            $signals[] = 'WordPress XML-RPC endpoint (xmlrpc.php) referenced';
        }
        if (stripos($main['final_url'], '.php') !== false) {
            $signals[] = 'URL path ends in a .php script';
        }

        $isPhp = count($signals) > 0;
        $findings = [];

        $findings[] = $this->finding(
            'php-detected',
            'PHP technology detection',
            $isPhp ? 'info' : 'info',
            $isPhp ? 'info' : 'pass',
            $isPhp
                ? 'The site appears to run PHP. Signals: ' . implode('; ', $signals) . '.'
                : 'No PHP signals were observed. The site may use a different stack or hides its fingerprint well.',
            $isPhp
                ? 'Keep PHP patched and remove unnecessary version disclosure (see below).'
                : 'No action needed for PHP; other posture checks below still apply.'
        );

        if ($version !== null) {
            $branch = implode('.', array_slice(explode('.', $version), 0, 2));
            $eol = $this->phpEol[$branch] ?? null;
            $isEol = $eol !== null && strtotime($eol) < time();
            $findings[] = $this->finding(
                'php-version',
                'PHP version exposure' . ($isEol ? ' (end-of-life)' : ''),
                $isEol ? 'high' : 'medium',
                'fail',
                "The exact PHP version ($version) is publicly disclosed."
                    . ($eol ? ($isEol
                        ? " Branch $branch reached end-of-life on $eol and no longer receives security fixes."
                        : " Branch $branch is supported until $eol.")
                        : ''),
                $isEol
                    ? "Upgrade to a supported PHP branch urgently, and set expose_php = Off in php.ini to stop leaking the version."
                    : "Set expose_php = Off in php.ini so the precise version is not advertised to attackers."
            );
        }

        return ['is_php' => $isPhp, 'version' => $version, 'findings' => $findings];
    }

    private function detectStack(array $main): array
    {
        $tech = [];
        $h = $main['headers'];
        $body = $main['body'];

        if (isset($h['server']))        $tech['Server'] = $h['server'];
        if (isset($h['x-powered-by']))  $tech['X-Powered-By'] = $h['x-powered-by'];

        $fingerprints = [
            'WordPress' => '#/wp-(content|includes)/#i',
            'Laravel'   => '#laravel_session|XSRF-TOKEN#i',
            'Drupal'    => '#Drupal\.settings|/sites/(default|all)/#i',
            'Joomla'    => '#/media/jui/|Joomla!#i',
            'Symfony'   => '#symfony|sf_redirect#i',
            'Magento'   => '#/static/version|Magento#i',
        ];
        $cookiesBlob = implode(' ', $main['set_cookie']);
        foreach ($fingerprints as $name => $re) {
            if (preg_match($re, $body) || preg_match($re, $cookiesBlob)) {
                $tech[] = $name;
            }
        }
        return $tech;
    }

    // ----------------------------------------------------------------- HTTPS

    private function checkHttps(string $url, array $main): array
    {
        $out = [];
        $isHttps = str_starts_with($main['final_url'], 'https://');

        $out[] = $this->finding(
            'https',
            'HTTPS / transport encryption',
            $isHttps ? 'info' : 'high',
            $isHttps ? 'pass' : 'fail',
            $isHttps
                ? 'The site is served over HTTPS.'
                : 'The site was reached over plain HTTP; traffic is unencrypted.',
            $isHttps
                ? 'Good. Ensure HTTP automatically redirects to HTTPS and HSTS is set.'
                : 'Install a TLS certificate (e.g. Let\'s Encrypt) and force all traffic to HTTPS.'
        );

        // Does http:// redirect to https://?
        if (str_starts_with($url, 'http://')) {
            $redir = str_starts_with($main['final_url'], 'https://');
            $out[] = $this->finding(
                'http-redirect',
                'HTTP → HTTPS redirect',
                $redir ? 'info' : 'medium',
                $redir ? 'pass' : 'warn',
                $redir ? 'Plain HTTP requests are redirected to HTTPS.'
                       : 'Plain HTTP was served without redirecting to HTTPS.',
                $redir ? 'No action needed.'
                       : 'Add a server-level 301 redirect from http:// to https://.'
            );
        }
        return $out;
    }

    // --------------------------------------------------------- Disclosure

    private function checkServerDisclosure(array $main): array
    {
        $h = $main['headers'];
        $out = [];
        if (isset($h['server']) && preg_match('#[0-9]+\.[0-9]#', $h['server'])) {
            $out[] = $this->finding(
                'server-version',
                'Web server version disclosure',
                'low', 'warn',
                "The Server header reveals software and version: {$h['server']}.",
                'Trim the Server header (e.g. ServerTokens Prod on Apache, server_tokens off on nginx).'
            );
        }
        return $out;
    }

    // ---------------------------------------------------- Security headers

    private function checkSecurityHeaders(array $main): array
    {
        $h = $main['headers'];
        $checks = [
            'strict-transport-security' => ['HSTS', 'high',
                'Forces browsers to use HTTPS. Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'],
            'content-security-policy'   => ['Content-Security-Policy', 'medium',
                'Mitigates XSS and injection. Define a policy restricting script/style/object sources.'],
            'x-content-type-options'    => ['X-Content-Type-Options', 'low',
                'Stops MIME sniffing. Add: X-Content-Type-Options: nosniff'],
            'x-frame-options'           => ['X-Frame-Options', 'medium',
                'Prevents clickjacking. Add: X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors).'],
            'referrer-policy'           => ['Referrer-Policy', 'low',
                'Limits referrer leakage. Add: Referrer-Policy: strict-origin-when-cross-origin'],
            'permissions-policy'        => ['Permissions-Policy', 'low',
                'Restricts browser features. Add a Permissions-Policy header disabling unused APIs.'],
        ];
        $out = [];
        foreach ($checks as $key => [$label, $sev, $rec]) {
            $present = isset($h[$key]);
            $out[] = $this->finding(
                'hdr-' . $key,
                "Security header: $label",
                $present ? 'info' : $sev,
                $present ? 'pass' : 'fail',
                $present ? "$label is present: {$h[$key]}" : "$label is missing.",
                $present ? 'No action needed.' : $rec
            );
        }
        return $out;
    }

    // ----------------------------------------------------------- Cookies

    private function checkCookies(array $main): array
    {
        $out = [];
        foreach ($main['set_cookie'] as $cookie) {
            $name = trim(explode('=', $cookie, 2)[0]);
            $missing = [];
            if (stripos($cookie, 'HttpOnly') === false) $missing[] = 'HttpOnly';
            if (stripos($cookie, 'Secure')   === false) $missing[] = 'Secure';
            if (stripos($cookie, 'SameSite') === false) $missing[] = 'SameSite';

            if ($missing) {
                $out[] = $this->finding(
                    'cookie-' . md5($name),
                    "Cookie flags: $name",
                    in_array('HttpOnly', $missing, true) ? 'medium' : 'low',
                    'warn',
                    "Cookie \"$name\" is missing flags: " . implode(', ', $missing) . '.',
                    'Set the missing attributes. HttpOnly blocks JS theft, Secure restricts to HTTPS, SameSite curbs CSRF.'
                );
            }
        }
        if (empty($out) && !empty($main['set_cookie'])) {
            $out[] = $this->finding('cookie-ok', 'Cookie flags', 'info', 'pass',
                'All observed cookies carry HttpOnly, Secure and SameSite.', 'No action needed.');
        }
        return $out;
    }

    // ------------------------------------------------- Sensitive files

    private function checkSensitiveFiles(string $url): array
    {
        $base = $this->origin($url);
        $out = [];
        $exposed = [];
        foreach ($this->sensitivePaths as $path => $why) {
            $r = $this->request($base . $path, 'GET');
            if (!$r['error'] && $r['status'] >= 200 && $r['status'] < 300 && strlen($r['body']) > 0) {
                // Avoid false positives from catch-all pages: require a hint it's the real file.
                if ($this->looksLikeRealFile($path, $r)) {
                    $exposed[] = $this->finding(
                        'file-' . md5($path),
                        "Exposed file: $path",
                        'high', 'fail',
                        "$path is publicly readable (HTTP {$r['status']}). $why",
                        "Block access to $path at the web server or move it outside the web root."
                    );
                }
            }
        }
        if ($exposed) return $exposed;
        return [$this->finding('files-ok', 'Common sensitive files', 'info', 'pass',
            'None of the common sensitive paths were publicly readable.', 'No action needed.')];
    }

    private function looksLikeRealFile(string $path, array $r): bool
    {
        $b = $r['body'];
        $ct = $r['headers']['content-type'] ?? '';
        // A real catch-all 200 usually returns HTML; these files shouldn't be HTML.
        return match (true) {
            str_contains($path, '.env')       => (bool) preg_match('#^[A-Z0-9_]+=#m', $b),
            str_contains($path, '.git')       => str_contains($b, '[core]') || str_contains($b, 'repositoryformatversion'),
            str_contains($path, 'composer')   => str_contains($b, '"require"') || str_contains($b, '"name"'),
            str_contains($path, 'phpinfo') || str_contains($path, 'info.php')
                                              => stripos($b, 'phpinfo()') !== false || stripos($b, 'PHP Version') !== false,
            str_contains($path, 'server-status') => stripos($b, 'Apache Server Status') !== false,
            str_contains($path, '.htaccess')  => stripos($ct, 'text/plain') !== false && (str_contains($b, 'RewriteRule') || str_contains($b, 'Options')),
            default                           => stripos($ct, 'html') === false,
        };
    }

    // ------------------------------------------------------------ Scoring

    private function score(array $findings): array
    {
        $weights = ['high' => 25, 'medium' => 12, 'low' => 5];
        $points = 100;
        $counts = ['high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($findings as $f) {
            if ($f['status'] === 'fail' || $f['status'] === 'warn') {
                $sev = $f['severity'];
                if (isset($weights[$sev])) {
                    $points -= $weights[$sev];
                    $counts[$sev]++;
                }
            }
        }
        $points = max(0, $points);
        $grade = match (true) {
            $points >= 90 => 'A',
            $points >= 75 => 'B',
            $points >= 60 => 'C',
            $points >= 40 => 'D',
            default       => 'F',
        };
        return ['points' => $points, 'grade' => $grade, 'counts' => $counts];
    }

    // ------------------------------------------------------------ Helpers

    private function finding(string $id, string $title, string $sev, string $status, string $detail, string $rec): array
    {
        return ['id' => $id, 'title' => $title, 'severity' => $sev, 'status' => $status,
                'detail' => $detail, 'recommendation' => $rec];
    }

    private function normaliseUrl(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '') return null;
        if (!preg_match('#^https?://#i', $raw)) $raw = 'https://' . $raw;
        $p = parse_url($raw);
        if (!$p || empty($p['host'])) return null;
        return $raw;
    }

    private function isPrivateHost(string $host): bool
    {
        if (in_array(strtolower($host), ['localhost'], true)) return true;
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return !filter_var($ip, FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        }
        return false;
    }

    private function origin(string $url): string
    {
        $p = parse_url($url);
        $scheme = $p['scheme'] ?? 'https';
        $host = $p['host'];
        $port = isset($p['port']) ? ':' . $p['port'] : '';
        return "$scheme://$host$port";
    }

    private function request(string $url, string $method = 'GET'): array
    {
        $ch = curl_init($url);
        $headerLines = [];
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_USERAGENT      => $this->userAgent,
            CURLOPT_NOBODY         => $method === 'HEAD',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headerLines) {
                $headerLines[] = $line;
                return strlen($line);
            },
        ]);
        $body = curl_exec($ch);
        $err  = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $final  = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        [$headers, $cookies] = $this->parseHeaders($headerLines);

        return [
            'error'      => $err ?: ($status === 0 ? 'no response' : ''),
            'status'     => $status,
            'headers'    => $headers,
            'set_cookie' => $cookies,
            'body'       => is_string($body) ? $body : '',
            'final_url'  => $final ?: $url,
        ];
    }

    private function parseHeaders(array $lines): array
    {
        $headers = [];
        $cookies = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || stripos($line, 'HTTP/') === 0) {
                // New response (after redirect) — reset single-value headers.
                if (stripos($line, 'HTTP/') === 0) { $headers = []; }
                continue;
            }
            $pos = strpos($line, ':');
            if ($pos === false) continue;
            $name = strtolower(trim(substr($line, 0, $pos)));
            $value = trim(substr($line, $pos + 1));
            if ($name === 'set-cookie') {
                $cookies[] = $value;
            } else {
                $headers[$name] = $value;
            }
        }
        return [$headers, $cookies];
    }
}
