package httpapi

import "html/template"

// Templates are inlined so the binary has no runtime file dependency. The
// interstitial is the primary anti-phishing surface, so it is written to be
// unambiguous rather than pretty: the registrable domain is the largest thing
// on the page, next to a plain statement that the user is leaving the company
// domain.
func parseTemplates() *template.Template {
	return template.Must(template.New("t").Parse(interstitialHTML + blockedHTML))
}

const interstitialHTML = `
{{define "interstitial"}}<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>即将离开本公司网站</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;font:16px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#1b1f24;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border:1px solid #e3e6ea;border-radius:14px;max-width:520px;width:100%;padding:28px 24px;box-shadow:0 8px 30px rgba(0,0,0,.06)}
.leave{display:flex;align-items:center;gap:8px;color:#b2540a;font-size:14px;font-weight:600;margin-bottom:14px}
.dot{width:8px;height:8px;border-radius:50%;background:#f59e0b}
h1{font-size:18px;margin:0 0 6px}
.sub{color:#5b636d;font-size:14px;margin:0 0 20px}
.dest{border:1px solid #e3e6ea;border-radius:10px;padding:14px;background:#fafbfc;margin-bottom:16px;word-break:break-all}
.host{font-size:22px;font-weight:700;letter-spacing:.2px;line-height:1.3}
.host .amp{color:#98a1ab;font-weight:400}
.tld-bad{color:#b42318}
.url{font-size:12px;color:#6b7480;margin-top:6px}
.tls{font-size:12px;margin-top:8px}
.tls.ok{color:#067647}
.tls.bad{color:#b42318}
.reason{background:#fff7ed;border:1px solid #fed7aa;color:#8a4b00;border-radius:10px;padding:12px;font-size:14px;margin-bottom:18px}
.actions{display:flex;flex-direction:column;gap:10px}
.btn{display:block;text-align:center;padding:12px 16px;border-radius:10px;font-size:15px;font-weight:600;text-decoration:none;border:1px solid transparent;cursor:pointer}
.btn-go{background:#0b6bcb;color:#fff}
.btn-go:hover{background:#0a5cb0}
.btn-back{background:#fff;color:#1b1f24;border-color:#d5dae0}
.btn-back:hover{background:#f3f5f7}
.warn{font-size:13px;color:#5b636d;text-align:center;margin:16px 0 0}
.warn strong{color:#b42318}
.report{font-size:12px;text-align:center;margin-top:14px}
.report button{background:none;border:none;color:#6b7480;text-decoration:underline;cursor:pointer;font-size:12px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f0f2f5;padding:1px 5px;border-radius:4px;font-size:12px}
</style></head>
<body>
<div class="card" role="main">
  <div class="leave"><span class="dot"></span>你将离开本公司网站</div>
  <h1>此链接将带你前往外部网站</h1>
  <p class="sub">该网站并非由本公司运营。请确认下面的域名与你期望的一致。</p>

  <div class="dest">
    <div class="host">{{.Host}}</div>
    <div class="url">{{.Raw}}</div>
    {{if .HTTPS}}<div class="tls ok">🔒 使用 HTTPS 加密连接</div>{{else}}<div class="tls bad">⚠ 该网站未使用 HTTPS,请勿输入任何密码或验证码</div>{{end}}
  </div>

  <div class="reason">{{.ReasonText}}如果你不认识该网站,请不要继续。</div>

  <div class="actions">
    <a class="btn btn-go" href="/{{.Code}}/go?t={{.Token}}" rel="noreferrer noopener">继续前往 {{.Host}}</a>
    <button type="button" class="btn btn-back" onclick="back()">返回</button>
  </div>

  <p class="warn">本公司<b>不会</b>通过此类链接页面索要你的<strong>密码、短信验证码或银行卡信息</strong>。</p>
  <p class="report"><button type="button" onclick="reportIt()">这个链接有问题?点此举报</button></p>
  <script>
  function back(){ if(history.length>1){history.back();} else {window.location.href='/';} }
  function reportIt(){
    fetch('/{{.Code}}/report',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'reason=user_reported'})
      .then(function(){document.querySelector('.report').textContent='已收到举报,感谢反馈。';})
      .catch(function(){document.querySelector('.report').textContent='上报失败,请稍后再试。';});
  }
  </script>
</div>
</body></html>{{end}}`

const blockedHTML = `
{{define "blocked"}}<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>链接已被拦截</title>
<style>
body{margin:0;font:16px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;background:#fdf2f2;color:#3d1111;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border:1px solid #f3c6c6;border-radius:14px;max-width:500px;width:100%;padding:28px 24px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.07)}
.icon{width:56px;height:56px;border-radius:50%;background:#fee4e2;color:#b42318;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 16px}
h1{font-size:19px;margin:0 0 8px;color:#b42318}
p{color:#5b636d;font-size:14px;margin:0 0 10px}
.note{background:#faf5f5;border:1px solid #f3c6c6;border-radius:10px;padding:12px;font-size:14px;color:#7a2e2e;margin-top:16px;text-align:left}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#9b6b6b}
</style></head>
<body>
<div class="card" role="alert">
  <div class="icon">!</div>
  <h1>此链接已被安全系统拦截</h1>
  <p>为保护你的账户与资金安全,该链接已被暂停使用。</p>
  <div class="note">原因:{{.Reason}}<br>如果你认为这是误判,请联系发送该链接的机构或本公司客服核实。</div>
  <p style="margin-top:16px"><code>链接编号:{{.Code}}</code></p>
</div>
</body></html>{{end}}`
