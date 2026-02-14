# WordPress/Stripe 連携セットアップガイド

WordPress の有料会員を Fieldnota commons と自動同期するための設定ガイドです。

## 概要

この連携により：
- WordPress で有料会員になると、Fieldnota commons のアカウントが自動作成されます
- ユーザーは初回ログイン時にユーザー名とパスワードを設定します
- WordPress の会員が解約されると、Fieldnota commons のアカウントも自動削除されます
- `org_name` を指定すると、団体メンバーとして自動追加されます（招待メール不要）

---

## 1. Cloudflare 環境変数の設定

### 1.1 共有シークレットの生成

セキュリティのため、WordPress と Fieldnota 間の通信に使用する秘密キーを生成します。

```bash
# ターミナルで実行
openssl rand -hex 32
```

出力例：`a1b2c3d4e5f6...` （64文字の16進数文字列）

### 1.2 Cloudflare Pages に環境変数を追加

1. [Cloudflare Dashboard](https://dash.cloudflare.com) にログイン
2. 左メニューから **Workers & Pages** を選択
3. 該当プロジェクト（例: `kmldata`）をクリック
4. 上部の **Settings** タブをクリック
5. 左メニューから **Variables and Secrets** を選択
6. **Add** ボタンをクリック

| 項目 | 値 |
|------|-----|
| Variable name | `EXTERNAL_SYNC_SECRET` |
| Value | 上で生成した秘密キー |
| Encrypt | ✅ チェック |

7. **Save** をクリック

### 1.3 本番環境とプレビュー環境

- **Production** と **Preview** 両方に同じ値を設定してください
- または、Production のみに設定してテスト後に Preview にも追加

---

## 2. データベースマイグレーション

### 2.1 マイグレーションの実行

```bash
# プロジェクトディレクトリで実行
npx wrangler d1 execute DB --file=migrations/0006_external_members.sql
```

### 2.2 確認

```bash
# テーブル構造を確認
npx wrangler d1 execute DB --command="PRAGMA table_info(users);"
```

以下のカラムが追加されていることを確認：
- `member_source` - 登録元（'wordpress' など）
- `plan` - プラン（'free' / 'premium'）
- `external_id` - 外部システムのユーザーID

---

## 3. WordPress 側の設定

### 3.1 Webhook エンドポイント

WordPress から Fieldnota に会員情報を送信するエンドポイント：

```
POST https://あなたのドメイン/api/external/member-sync
```

### 3.2 リクエスト形式

**ヘッダー：**
```
Content-Type: application/json
```

**会員作成時のボディ：**
```json
{
  "action": "create",
  "email": "user@example.com",
  "display_name": "山田 太郎",
  "plan": "premium",
  "external_id": "wp_123",
  "secret": "あなたの共有シークレット",
  "org_name": "yafomans"
}
```

**会員削除時のボディ：**
```json
{
  "action": "delete",
  "email": "user@example.com",
  "secret": "あなたの共有シークレット"
}
```

### 3.3 WordPress での実装例

#### functions.php に追加：

```php
<?php
// Fieldnota 連携設定
define('FIELDNOTA_API_URL', 'https://あなたのドメイン/api/external/member-sync');
define('FIELDNOTA_SECRET', 'あなたの共有シークレット');

/**
 * Stripe 決済完了時に Fieldnota にアカウント作成
 */
function sync_to_fieldnota_on_payment($user_id, $plan = 'premium', $org_name = 'yafomans') {
    $user = get_userdata($user_id);
    if (!$user) return false;

    $body = array(
        'action' => 'create',
        'email' => $user->user_email,
        'display_name' => $user->display_name,
        'plan' => $plan,
        'external_id' => 'wp_' . $user_id,
        'secret' => FIELDNOTA_SECRET
    );
    if ($org_name) {
        $body['org_name'] = $org_name;
    }

    $response = wp_remote_post(FIELDNOTA_API_URL, array(
        'headers' => array('Content-Type' => 'application/json'),
        'body' => json_encode($body),
        'timeout' => 30
    ));

    if (is_wp_error($response)) {
        error_log('Fieldnota sync error: ' . $response->get_error_message());
        return false;
    }

    $body = json_decode(wp_remote_retrieve_body($response), true);
    return isset($body['success']) && $body['success'];
}

/**
 * 会員解約時に Fieldnota アカウントを削除
 */
function delete_from_fieldnota_on_cancel($user_id) {
    $user = get_userdata($user_id);
    if (!$user) return false;

    $response = wp_remote_post(FIELDNOTA_API_URL, array(
        'headers' => array('Content-Type' => 'application/json'),
        'body' => json_encode(array(
            'action' => 'delete',
            'email' => $user->user_email,
            'secret' => FIELDNOTA_SECRET
        )),
        'timeout' => 30
    ));

    if (is_wp_error($response)) {
        error_log('Fieldnota delete error: ' . $response->get_error_message());
        return false;
    }

    return true;
}
```

### 3.4 Stripe Webhook との連携

Stripe の Webhook を処理するコードで、上記関数を呼び出します：

```php
<?php
// Stripe Webhook ハンドラー内で

// 決済成功時
case 'checkout.session.completed':
case 'invoice.payment_succeeded':
    $customer_email = $event->data->object->customer_email;
    $user = get_user_by('email', $customer_email);
    if ($user) {
        sync_to_fieldnota_on_payment($user->ID, 'premium');
    }
    break;

// サブスクリプション解約時
case 'customer.subscription.deleted':
    $customer_email = get_stripe_customer_email($event->data->object->customer);
    $user = get_user_by('email', $customer_email);
    if ($user) {
        delete_from_fieldnota_on_cancel($user->ID);
    }
    break;
```

---

## 4. ユーザー体験フロー

### 4.1 新規有料会員の流れ

1. ユーザーが WordPress で有料会員登録
2. Stripe 決済完了
3. WordPress が Fieldnota API を呼び出し（`org_name` 付き）
4. アカウント作成 + 団体メンバーに自動追加 + ウェルカムメール送信
5. ユーザーがウェルカムメールのリンクからパスワードを設定
6. 自動ログインして利用開始（既に団体に所属済み）

### 4.2 ウェルカムメールの内容

```
件名: Fieldnota commons へようこそ

○○ 様

有料会員登録ありがとうございます。

Fieldnota commons をご利用いただくには、
以下のリンクからパスワードを設定してください：

[パスワードを設定する]

※ このメールに心当たりがない場合は、無視してください。
```

---

## 5. API レスポンス

### 5.1 成功レスポンス

**アカウント作成成功（団体自動追加あり）：**
```json
{
  "success": true,
  "action": "created",
  "user_id": 123,
  "invitation": { "status": "added", "org_name": "yafomans" }
}
```

**既存ユーザーのプラン更新：**
```json
{
  "success": true,
  "action": "updated",
  "user_id": 123,
  "invitation": { "status": "added", "org_name": "yafomans" }
}
```

**通常ユーザーを有料化：**
```json
{
  "success": true,
  "action": "upgraded",
  "user_id": 123,
  "invitation": { "status": "already_member" }
}
```

**アカウント削除成功：**
```json
{
  "success": true,
  "action": "deleted",
  "user_id": 123
}
```

### 5.2 エラーレスポンス

```json
{
  "error": "エラーメッセージ"
}
```

| ステータス | 原因 |
|-----------|------|
| 401 | シークレットキーが無効 |
| 400 | リクエスト形式が不正 |
| 500 | サーバーエラー |

---

## 6. トラブルシューティング

### 6.1 「Unauthorized」エラー

- `EXTERNAL_SYNC_SECRET` が正しく設定されているか確認
- WordPress 側の `FIELDNOTA_SECRET` と一致しているか確認
- Cloudflare Pages を再デプロイ

### 6.2 ウェルカムメールが届かない

- `RESEND_API_KEY` が設定されているか確認
- Resend のダッシュボードでログを確認
- 送信元ドメインが Resend で認証されているか確認

### 6.3 ユーザーがパスワード設定画面にアクセスできない

手動でURLを共有：
```
https://あなたのドメイン/?setup=password&email=user@example.com
```

### 6.4 デバッグ方法

Cloudflare Pages Functions のログを確認：

1. Cloudflare Dashboard → Workers & Pages
2. プロジェクトを選択
3. **Logs** タブをクリック
4. Real-time Logs で API リクエストを確認

---

## 7. セキュリティ注意事項

1. **シークレットキーは絶対に公開しない**
   - Git にコミットしない
   - フロントエンドに露出しない

2. **HTTPS 必須**
   - HTTP での API 呼び出しは避ける

3. **IP 制限（オプション）**
   - 必要に応じて WordPress サーバーの IP からのみ許可

4. **ログ監視**
   - 不審なリクエストがないか定期的に確認
