// Migration notice for old domain
if (location.hostname === 'map.taishi-lab.com') {
  document.addEventListener('DOMContentLoaded', function() {
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5;font-family:system-ui,sans-serif;"><div style="background:white;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1);text-align:center;max-width:400px;margin:20px;"><div style="font-size:48px;margin-bottom:20px;">🏠</div><h1 style="color:#333;font-size:24px;margin-bottom:16px;">移転しました</h1><p style="color:#666;line-height:1.6;margin-bottom:24px;">Fieldnota commons は<br>新しいURLに移転しました。</p><a href="https://fieldnota-commons.com" style="display:inline-block;background:#4CAF50;color:white;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px;">新しいサイトへ</a><p style="color:#999;font-size:12px;margin-top:20px;">https://fieldnota-commons.com</p></div></div>';
  });
}
