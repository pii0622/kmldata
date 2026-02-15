// Email sending via Resend (https://resend.com)

const EMAIL_FROM = 'hello@fieldnota-commons.com';
const EMAIL_FROM_NAME = 'Fieldnota commons';

export async function sendEmail(env, to, subject, htmlBody, textBody) {
  if (!env.RESEND_API_KEY) {
    console.error('Email send failed: RESEND_API_KEY not configured');
    return false;
  }

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.RESEND_API_KEY}`
      },
      body: JSON.stringify({
        from: `${EMAIL_FROM_NAME} <${EMAIL_FROM}>`,
        to: [to],
        subject: subject,
        html: htmlBody,
        text: textBody
      })
    });

    if (!response.ok) {
      const errData = await response.json();
      console.error('Email send failed:', response.status, JSON.stringify(errData));
      return false;
    }

    const result = await response.json();
    console.log('Email sent successfully:', result.id);
    return true;
  } catch (err) {
    console.error('Email send error:', err);
    return false;
  }
}

// Send welcome email to external member
export async function sendExternalWelcomeEmail(env, email, displayName) {
  const appUrl = 'https://fieldnota-commons.com';
  const subject = 'Fieldnota commons へようこそ';

  const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="color: #4CAF50;">Fieldnota commons のご案内</h1>

  <p>${displayName} 様</p>

  <p>
    このたびは、「yafomans」へご参加いただきありがとうございます。
  </p>

  <p>
    yafomansの会員にご登録いただいた方は、自動的に<br>
    <strong>Fieldnota commonsの有料会員</strong>としてご利用いただけます。
  </p>

  <p>
    Fieldnota commons は、フィールドワークや探索で見つけた情報を地図上に記録・共有できるアプリです。<br>
    yafomansで活用できる地図情報や記録が掲載されており、ログインすることでより深く楽しんでいただけます。
  </p>

  <p>
    ご利用開始のため、以下のリンクからアカウント登録（パスワード設定）を行ってください。
  </p>

  <p style="text-align: center; margin: 30px 0;">
    <a href="${appUrl}?setup=password&email=${encodeURIComponent(email)}"
       style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
      アカウントを設定する
    </a>
  </p>

  <p>
    Fieldnota commons について詳しくは、以下をご覧ください。<br>
    <a href="https://fieldnota-commons.com/about" target="_blank">
      https://fieldnota-commons.com/about
    </a>
  </p>

  <p style="color: #666; font-size: 14px;">
    ※ このメールに心当たりがない場合は、破棄してください。
  </p>

  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">
    Fieldnota commons
  </p>
</body>
</html>
  `;

  const textBody = `
${displayName} 様

Fieldnota commons へようこそ！

有料会員登録ありがとうございます。

以下のリンクからパスワードを設定してください：
${appUrl}?setup=password&email=${encodeURIComponent(email)}

※ このメールに心当たりがない場合は、無視してください。

Fieldnota commons
  `;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}

// Send approval notification email
export async function sendApprovalEmail(env, email, displayName, username) {
  const appUrl = 'https://fieldnota-commons.com';
  const subject = 'アカウントが承認されました - Fieldnota commons';

  const htmlBody = `
<h2>アカウント承認のお知らせ</h2>
<p>${displayName || username} 様</p>
<p>Fieldnota commonsへのアカウント申請が承認されました。</p>
<p>以下のリンクからログインしてご利用ください。</p>
<p><a href="${appUrl}">${appUrl}</a></p>
<br>
<p><strong>※ユーザー名はフルネーム（ローマ字）で登録されています。</strong></p>
<p>例: Taro Yamada</p>
<br>
<p>Fieldnota commons</p>`;

  const textBody = `${displayName || username} 様

Fieldnota commonsへのアカウント申請が承認されました。
以下のリンクからログインしてご利用ください。

${appUrl}

※ユーザー名はフルネーム（ローマ字）で登録されています。
例: Taro Yamada

Fieldnota commons`;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}

// Send organization invitation email
export async function sendOrgInvitationEmail(env, email, orgName, inviterName, token) {
  const appUrl = 'https://fieldnota-commons.com';
  const subject = `${orgName} への招待 - Fieldnota commons`;

  const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="color: #4CAF50;">団体への招待</h1>
  <p>${inviterName} さんから、<strong>${orgName}</strong> への招待が届いています。</p>
  <p>以下のリンクから招待を承認してください：</p>
  <p style="text-align: center; margin: 30px 0;">
    <a href="${appUrl}?invite=${encodeURIComponent(token)}"
       style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
      招待を承認する
    </a>
  </p>
  <p style="color: #666; font-size: 14px;">
    ※ この招待は7日間有効です。<br>
    ※ このメールに心当たりがない場合は、無視してください。
  </p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">Fieldnota commons</p>
</body>
</html>
  `;

  const textBody = `
${inviterName} さんから、${orgName} への招待が届いています。

以下のリンクから招待を承認してください：
${appUrl}?invite=${encodeURIComponent(token)}

※ この招待は7日間有効です。
※ このメールに心当たりがない場合は、無視してください。

Fieldnota commons
  `;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}

// Send notification that user was directly added to organization (already has account)
export async function sendOrgAddedNotificationEmail(env, email, orgName, inviterName) {
  const appUrl = 'https://fieldnota-commons.com';
  const subject = `${orgName} に追加されました - Fieldnota commons`;

  const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="color: #4CAF50;">団体に追加されました</h1>
  <p>${inviterName} さんが、あなたを <strong>${orgName}</strong> に追加しました。</p>
  <p>ログインして団体のコンテンツをご覧ください：</p>
  <p style="text-align: center; margin: 30px 0;">
    <a href="${appUrl}"
       style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
      Fieldnota commons を開く
    </a>
  </p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">Fieldnota commons</p>
</body>
</html>
  `;

  const textBody = `
${inviterName} さんが、あなたを ${orgName} に追加しました。

ログインして団体のコンテンツをご覧ください：
${appUrl}

Fieldnota commons
  `;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}

// Send password reset email
export async function sendPasswordResetEmail(env, email, displayName, resetToken) {
  const appUrl = 'https://fieldnota-commons.com';
  const subject = 'パスワード再設定 - Fieldnota commons';

  const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="color: #4CAF50;">パスワード再設定</h1>
  <p>${displayName || ''} 様</p>
  <p>パスワード再設定のリクエストを受け付けました。</p>
  <p>以下のリンクからパスワードを再設定してください：</p>
  <p style="text-align: center; margin: 30px 0;">
    <a href="${appUrl}?reset_token=${encodeURIComponent(resetToken)}"
       style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
      パスワードを再設定する
    </a>
  </p>
  <p style="color: #666; font-size: 14px;">
    ※ このリンクは1時間有効です。<br>
    ※ このメールに心当たりがない場合は、無視してください。
  </p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">Fieldnota commons</p>
</body>
</html>
  `;

  const textBody = `
${displayName || ''} 様

パスワード再設定のリクエストを受け付けました。

以下のリンクからパスワードを再設定してください：
${appUrl}?reset_token=${encodeURIComponent(resetToken)}

※ このリンクは1時間有効です。
※ このメールに心当たりがない場合は、無視してください。

Fieldnota commons
  `;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}

// Send rejection notification email
export async function sendRejectionEmail(env, email, displayName, username) {
  const subject = 'アカウント申請について - Fieldnota commons';

  const htmlBody = `
<h2>アカウント申請のお知らせ</h2>
<p>${displayName || username} 様</p>
<p>申し訳ございませんが、Fieldnota commonsへのアカウント申請は承認されませんでした。</p>
<p>ご不明な点がございましたら、管理者までお問い合わせください。</p>
<br>
<p>Fieldnota commons</p>`;

  const textBody = `${displayName || username} 様

申し訳ございませんが、Fieldnota commonsへのアカウント申請は承認されませんでした。
ご不明な点がございましたら、管理者までお問い合わせください。

Fieldnota commons`;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}
