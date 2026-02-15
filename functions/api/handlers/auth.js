// Authentication handlers

import {
  json, setCookieHeader, isValidEmail,
  hashPassword, verifyPassword, createToken,
  createSession, revokeSession, revokeSessionById, revokeAllUserSessions, getUserSessions,
  logSecurityEvent
} from '../lib/index.js';
import { sendExternalWelcomeEmail } from '../lib/email.js';

// Token refresh
export async function handleTokenRefresh(env, user, request) {
  const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  if (!dbUser || dbUser.status !== 'approved') {
    return json({ error: 'ユーザーが見つかりません' }, 404);
  }

  let sessionToken = user.sid;
  if (!sessionToken) {
    sessionToken = await createSession(env, user.id, request);
  }

  const token = await createToken({
    id: dbUser.id,
    username: dbUser.username,
    display_name: dbUser.display_name || dbUser.username,
    is_admin: !!dbUser.is_admin,
    sid: sessionToken
  }, env.JWT_SECRET);

  return json(
    { ok: true },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 259200, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

// Register
export async function handleRegister(request, env) {
  const { username, password, email, display_name } = await request.json();
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }
  if (!email) {
    return json({ error: 'メールアドレスを入力してください' }, 400);
  }
  if (!isValidEmail(email)) {
    return json({ error: '有効なメールアドレスを入力してください' }, 400);
  }
  if (username.length < 3) {
    return json({ error: 'ユーザー名は3文字以上にしてください' }, 400);
  }
  const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
  if (!fullNamePattern.test(username.trim())) {
    return json({ error: 'ユーザー名はローマ字のフルネームで入力してください（例: Taro Yamada）' }, 400);
  }
  if (password.length < 12) {
    return json({ error: 'パスワードは12文字以上にしてください' }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    await logSecurityEvent(env, 'register_duplicate_username', null, request, {});
    return json({ error: 'そのユーザー名は既に使われています' }, 400);
  }

  const actualDisplayName = (display_name || username).trim();
  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ?').bind(actualDisplayName).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  const { hash, salt } = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, password_salt, email, display_name, status) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(username, hash, salt, email, actualDisplayName, 'pending').run();

  const userId = result.meta.last_row_id;

  await env.DB.prepare(
    'INSERT INTO admin_notifications (type, message, data) VALUES (?, ?, ?)'
  ).bind('user_pending', `新規ユーザー「${actualDisplayName}」が承認待ちです`, JSON.stringify({ user_id: userId, display_name: actualDisplayName })).run();

  return json({
    pending: true,
    message: 'アカウント申請を受け付けました。管理者の承認をお待ちください。'
  });
}

// Login
export async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || !(await verifyPassword(password, user.password_hash, user.password_salt))) {
    await logSecurityEvent(env, 'login_failed', null, request, { reason: 'invalid_credentials' });
    return json({ error: 'ユーザー名またはパスワードが正しくありません' }, 401);
  }

  if (user.status === 'pending') {
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'pending_approval' });
    return json({ error: 'アカウントは承認待ちです。管理者の承認をお待ちください。' }, 403);
  }
  if (user.status === 'rejected') {
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'rejected' });
    return json({ error: 'アカウントは承認されませんでした。' }, 403);
  }
  if (user.status === 'needs_password') {
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'needs_password_setup' });
    return json({ error: 'パスワードを設定してください。登録時に送信されたメールをご確認ください。', needs_password: true }, 403);
  }

  const sessionToken = await createSession(env, user.id, request);
  await logSecurityEvent(env, 'login_success', user.id, request, {});

  const token = await createToken({
    id: user.id, username: user.username,
    display_name: user.display_name || user.username,
    is_admin: !!user.is_admin,
    sid: sessionToken
  }, env.JWT_SECRET);

  return json(
    { id: user.id, username: user.username, display_name: user.display_name, is_admin: !!user.is_admin },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 259200, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

// Logout
export async function handleLogout(env, user, request) {
  if (user && user.sid) {
    await revokeSession(env, user.sid);
    await logSecurityEvent(env, 'logout', user.id, request, {});
  }
  return json({ ok: true }, 200, { 'Set-Cookie': setCookieHeader('auth', '', { maxAge: 0 }) });
}

// Update profile
export async function handleUpdateProfile(request, env, user) {
  const { display_name } = await request.json();
  if (!display_name || !display_name.trim()) {
    return json({ error: '表示名を入力してください' }, 400);
  }

  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ? AND id != ?')
    .bind(display_name.trim(), user.id).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  await env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?')
    .bind(display_name.trim(), user.id).run();

  const token = await createToken({
    id: user.id,
    username: user.username,
    display_name: display_name.trim(),
    is_admin: user.is_admin,
    sid: user.sid
  }, env.JWT_SECRET);

  return json(
    { ok: true, display_name: display_name.trim() },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 259200, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

// Change password
export async function handleChangePassword(request, env, user) {
  const { current_password, new_password, revoke_other_sessions } = await request.json();

  if (!current_password) {
    return json({ error: '現在のパスワードを入力してください' }, 400);
  }
  if (!new_password || new_password.length < 12) {
    return json({ error: '新しいパスワードは12文字以上にしてください' }, 400);
  }

  const dbUser = await env.DB.prepare('SELECT password_hash, password_salt FROM users WHERE id = ?')
    .bind(user.id).first();
  if (!dbUser || !(await verifyPassword(current_password, dbUser.password_hash, dbUser.password_salt))) {
    return json({ error: '現在のパスワードが正しくありません' }, 401);
  }

  const { hash: newHash, salt: newSalt } = await hashPassword(new_password);
  await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(newHash, newSalt, user.id).run();

  if (revoke_other_sessions !== false && user.sid) {
    await revokeAllUserSessions(env, user.id, user.sid);
  }

  await logSecurityEvent(env, 'password_changed', user.id, request, { revoked_sessions: revoke_other_sessions !== false });

  return json({ ok: true });
}

// Session management handlers
export async function handleGetSessions(env, user) {
  const sessions = await getUserSessions(env, user.id);
  return json(sessions.map(session => ({ ...session, is_current: false })));
}

export async function handleRevokeSession(env, user, sessionId) {
  const success = await revokeSessionById(env, sessionId, user.id);
  if (!success) {
    return json({ error: 'セッションが見つかりません' }, 404);
  }
  await logSecurityEvent(env, 'session_revoked', user.id, null, { session_id: sessionId });
  return json({ ok: true });
}

export async function handleRevokeAllSessions(env, user) {
  if (!user.sid) {
    return json({ error: '現在のセッションが無効です' }, 400);
  }
  await revokeAllUserSessions(env, user.id, user.sid);
  await logSecurityEvent(env, 'all_sessions_revoked', user.id, null, {});
  return json({ ok: true });
}

// External member sync
export async function handleExternalMemberSync(request, env) {
  try {
    const { action, email, display_name, plan, external_id, secret } = await request.json();

    if (!env.EXTERNAL_SYNC_SECRET || secret !== env.EXTERNAL_SYNC_SECRET) {
      return json({ error: 'Unauthorized' }, 401);
    }

    if (!email) {
      return json({ error: 'Email is required' }, 400);
    }

    if (!isValidEmail(email)) {
      return json({ error: 'Invalid email format' }, 400);
    }

    if (action === 'create') {
      const existing = await env.DB.prepare('SELECT id, member_source FROM users WHERE email = ?').bind(email).first();

      if (existing) {
        if (existing.member_source === 'wordpress') {
          await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(plan || 'premium', existing.id).run();
          return json({ success: true, action: 'updated', user_id: existing.id });
        } else {
          await env.DB.prepare('UPDATE users SET plan = ?, member_source = ? WHERE id = ?')
            .bind(plan || 'premium', 'wordpress', existing.id).run();
          return json({ success: true, action: 'upgraded', user_id: existing.id });
        }
      }

      const username = email;
      const actualDisplayName = display_name || email.split('@')[0];
      const tempPassword = crypto.randomUUID();
      const { hash, salt } = await hashPassword(tempPassword);

      const result = await env.DB.prepare(
        `INSERT INTO users (username, password_hash, password_salt, email, display_name, status, member_source, plan, external_id)
         VALUES (?, ?, ?, ?, ?, 'needs_password', 'wordpress', ?, ?)`
      ).bind(username, hash, salt, email, actualDisplayName, plan || 'premium', external_id || null).run();

      const userId = result.meta.last_row_id;
      await sendExternalWelcomeEmail(env, email, actualDisplayName);
      return json({ success: true, action: 'created', user_id: userId });

    } else if (action === 'delete') {
      const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (!user) {
        return json({ success: true, action: 'not_found' });
      }
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
      return json({ success: true, action: 'deleted', user_id: user.id });

    } else {
      return json({ error: 'Invalid action. Use "create" or "delete"' }, 400);
    }
  } catch (err) {
    console.error('External member sync error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

// Setup password for external members
export async function handleSetupPassword(request, env) {
  try {
    const { email, username, display_name, password } = await request.json();

    if (!email || !username || !password) {
      return json({ error: 'すべての必須項目を入力してください' }, 400);
    }

    const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
    if (!fullNamePattern.test(username.trim())) {
      return json({ error: 'ユーザー名はローマ字のフルネームで入力してください（例: Taro Yamada）' }, 400);
    }

    if (password.length < 12) {
      return json({ error: 'パスワードは12文字以上にしてください' }, 400);
    }

    const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (!user) {
      return json({ error: 'ユーザーが見つかりません' }, 404);
    }

    if (user.status !== 'needs_password') {
      return json({ error: 'このアカウントは既にパスワードが設定されています。ログインしてください。' }, 400);
    }

    const existingUsername = await env.DB.prepare('SELECT id FROM users WHERE username = ? AND id != ?')
      .bind(username.trim(), user.id).first();
    if (existingUsername) {
      return json({ error: 'そのユーザー名は既に使われています' }, 400);
    }

    const actualDisplayName = (display_name || username).trim();
    const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ? AND id != ?')
      .bind(actualDisplayName, user.id).first();
    if (existingDisplayName) {
      return json({ error: 'その表示名は既に使われています' }, 400);
    }

    const { hash, salt } = await hashPassword(password);
    await env.DB.prepare('UPDATE users SET username = ?, display_name = ?, password_hash = ?, password_salt = ?, status = ? WHERE id = ?')
      .bind(username.trim(), actualDisplayName, hash, salt, 'approved', user.id).run();

    const sessionToken = await createSession(env, user.id, request);

    const token = await createToken({
      id: user.id,
      username: username.trim(),
      display_name: actualDisplayName,
      is_admin: !!user.is_admin,
      sid: sessionToken
    }, env.JWT_SECRET);

    await logSecurityEvent(env, 'account_setup_complete', user.id, request, { member_source: user.member_source });

    return json(
      {
        success: true,
        message: 'アカウントを設定しました',
        user: { id: user.id, username: username.trim(), display_name: actualDisplayName, is_admin: !!user.is_admin }
      },
      200,
      { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 259200, httpOnly: true, secure: true, sameSite: 'Strict' }) }
    );
  } catch (err) {
    console.error('Account setup error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
