<?php
declare(strict_types=1);
require __DIR__ . '/scanner.php';

$report = null;
$target = $_POST['url'] ?? ($_GET['url'] ?? '');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && trim((string) $target) !== '') {
    $report = (new PhpPostureScanner())->scan((string) $target);
}

$sevColor = [
    'high'   => '#e5484d',
    'medium' => '#f5a623',
    'low'    => '#f2cb30',
    'info'   => '#5b8def',
];
$statusIcon = ['pass' => '✓', 'fail' => '✕', 'warn' => '!', 'info' => 'i'];
$statusColor = ['pass' => '#30a46c', 'fail' => '#e5484d', 'warn' => '#f5a623', 'info' => '#5b8def'];

function h(?string $s): string { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP Posture Scanner</title>
<style>
  :root{
    --bg:#0e1116; --panel:#171b22; --panel2:#1e242d; --line:#2a313c;
    --text:#e6e9ee; --muted:#8a93a2; --accent:#5b8def; --accent2:#7c5cff;
  }
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:var(--bg);color:var(--text)}
  .wrap{max-width:880px;margin:0 auto;padding:28px 18px 80px}
  h1{font-size:24px;margin:0 0 4px;letter-spacing:-.3px}
  .sub{color:var(--muted);margin:0 0 22px;font-size:14px}
  form{display:flex;gap:10px;flex-wrap:wrap;background:var(--panel);border:1px solid var(--line);
       padding:14px;border-radius:14px}
  input[type=url],input[type=text]{flex:1;min-width:220px;background:var(--panel2);border:1px solid var(--line);
       color:var(--text);padding:12px 14px;border-radius:10px;font-size:15px;outline:none}
  input:focus{border-color:var(--accent)}
  button{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:0;
       padding:12px 22px;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer}
  .notice{background:#1a1407;border:1px solid #4a3a12;color:#f2cb6a;padding:10px 14px;
       border-radius:10px;font-size:13px;margin:14px 0 0}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin-top:18px}
  .grade{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
  .badge{width:72px;height:72px;border-radius:16px;display:grid;place-items:center;font-size:36px;
       font-weight:800;color:#fff}
  .meta{color:var(--muted);font-size:13px;word-break:break-all}
  .pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}
  .pill{background:var(--panel2);border:1px solid var(--line);padding:3px 10px;border-radius:999px;font-size:12px}
  .counts{display:flex;gap:14px;margin-top:8px;font-size:13px}
  .finding{display:flex;gap:12px;padding:14px 0;border-top:1px solid var(--line)}
  .finding:first-child{border-top:0}
  .dot{flex:0 0 26px;height:26px;border-radius:7px;display:grid;place-items:center;font-weight:700;color:#fff;font-size:14px}
  .ftitle{font-weight:600;margin:0 0 2px}
  .fsev{font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:1px 7px;border-radius:999px;
       margin-left:8px;vertical-align:middle;color:#fff}
  .fdetail{color:var(--text);font-size:14px;margin:2px 0 6px}
  .frec{color:var(--muted);font-size:13px;border-left:2px solid var(--line);padding-left:10px}
  .frec b{color:var(--text)}
  .err{background:#2a1416;border:1px solid #5a2327;color:#f3a3a6;padding:14px;border-radius:12px;margin-top:18px}
  .sec-title{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:0 0 4px}
  code{background:var(--panel2);padding:1px 5px;border-radius:5px;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
  <h1>PHP Posture Scanner</h1>
  <p class="sub">Passive fingerprinting &amp; security-posture report for a public URL.</p>

  <form method="post">
    <input type="text" name="url" placeholder="example.com  or  https://example.com"
           value="<?= h((string) $target) ?>" autofocus>
    <button type="submit">Scan</button>
  </form>
  <p class="notice">⚠ Only scan sites you own or are explicitly authorised to test.
     This tool sends ordinary, passive requests — no exploits — but unauthorised scanning may still breach policy or law.</p>

<?php if ($report && isset($report['error'])): ?>
  <div class="err"><?= h($report['error']) ?></div>
<?php elseif ($report): ?>
  <?php $g = $report['score']; ?>
  <div class="card">
    <div class="grade">
      <div class="badge" style="background:<?= $g['grade']==='A'?'#30a46c':($g['grade']==='B'?'#5b8def':($g['grade']==='C'?'#f5a623':'#e5484d')) ?>">
        <?= h($g['grade']) ?>
      </div>
      <div>
        <div style="font-size:18px;font-weight:700"><?= (int)$g['points'] ?>/100 posture score</div>
        <div class="meta"><?= h($report['final_url']) ?></div>
        <div class="meta">Scanned <?= h($report['scanned_at']) ?> · HTTP <?= (int)$report['status'] ?></div>
        <div class="counts">
          <span style="color:#e5484d">● <?= (int)$g['counts']['high'] ?> high</span>
          <span style="color:#f5a623">● <?= (int)$g['counts']['medium'] ?> medium</span>
          <span style="color:#f2cb30">● <?= (int)$g['counts']['low'] ?> low</span>
        </div>
      </div>
    </div>
    <div class="pills">
      <span class="pill"><?= $report['is_php'] ? 'PHP detected' : 'PHP not detected' ?></span>
      <?php if ($report['php_version']): ?><span class="pill">PHP <?= h($report['php_version']) ?></span><?php endif; ?>
      <?php foreach ($report['tech'] as $k => $v): ?>
        <span class="pill"><?= is_string($k) ? h($k).': '.h($v) : h($v) ?></span>
      <?php endforeach; ?>
    </div>
  </div>

  <div class="card">
    <p class="sec-title">Findings &amp; recommendations</p>
    <?php
      // Sort: fails/warns first, by severity.
      $order = ['high'=>0,'medium'=>1,'low'=>2,'info'=>3];
      usort($report['findings'], function($a,$b) use($order){
        $sa = ($a['status']==='pass'?1:0); $sb = ($b['status']==='pass'?1:0);
        if ($sa !== $sb) return $sa <=> $sb;
        return ($order[$a['severity']]??9) <=> ($order[$b['severity']]??9);
      });
      foreach ($report['findings'] as $f):
        $ic = $statusIcon[$f['status']] ?? 'i';
        $sc = $statusColor[$f['status']] ?? '#5b8def';
    ?>
      <div class="finding">
        <div class="dot" style="background:<?= $sc ?>"><?= $ic ?></div>
        <div style="flex:1">
          <p class="ftitle"><?= h($f['title']) ?>
            <span class="fsev" style="background:<?= $sevColor[$f['severity']] ?? '#5b8def' ?>"><?= h($f['severity']) ?></span>
          </p>
          <p class="fdetail"><?= h($f['detail']) ?></p>
          <p class="frec"><b>Action:</b> <?= h($f['recommendation']) ?></p>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>
</div>
</body>
</html>
