// Sentry Error Monitoring - Frontend
// DSNはconfig.jsのAPP_CONFIG.sentryDsnで設定
// 未設定の場合、Sentryは無効化され、エラーはconsoleにのみ出力
(function() {
  'use strict';

  // Sentryが設定されていない場合のno-opラッパー
  window.ErrorMonitor = {
    initialized: false,

    // エラーキャプチャ（APIエラー、手動キャプチャ用）
    captureError: function(error, context) {
      if (window.Sentry && this.initialized) {
        window.Sentry.captureException(error, {
          extra: context || {}
        });
      }
    },

    // メッセージキャプチャ（警告・情報レベル用）
    captureMessage: function(message, level, context) {
      if (window.Sentry && this.initialized) {
        window.Sentry.captureMessage(message, {
          level: level || 'info',
          extra: context || {}
        });
      }
    },

    // ユーザーコンテキスト設定（ログイン後に呼ぶ）
    setUser: function(user) {
      if (window.Sentry && this.initialized) {
        window.Sentry.setUser(user ? {
          id: user.id,
          username: user.username
        } : null);
      }
    },

    // APIエラーを記録
    captureApiError: function(url, status, message) {
      if (window.Sentry && this.initialized) {
        window.Sentry.captureMessage('API Error: ' + status + ' ' + url, {
          level: status >= 500 ? 'error' : 'warning',
          extra: { url: url, status: status, message: message }
        });
      }
    }
  };

  // Sentry SDK読み込みと初期化
  var dsn = window.APP_CONFIG && window.APP_CONFIG.sentryDsn;
  if (!dsn) {
    console.info('[ErrorMonitor] Sentry DSN not configured. Error monitoring disabled.');
    console.info('[ErrorMonitor] Set APP_CONFIG.sentryDsn in config.js to enable.');
    return;
  }

  // Sentry SDK をCDN経由で動的読み込み
  var script = document.createElement('script');
  script.src = 'https://browser.sentry-cdn.com/8.48.0/bundle.min.js';
  script.crossOrigin = 'anonymous';
  script.onload = function() {
    if (!window.Sentry) return;

    window.Sentry.init({
      dsn: dsn,
      release: window.APP_CONFIG.version || 'unknown',
      environment: location.hostname === 'localhost' ? 'development' : 'production',

      // パフォーマンス: 本番では10%サンプリング
      tracesSampleRate: location.hostname === 'localhost' ? 1.0 : 0.1,

      // エラーフィルタリング
      beforeSend: function(event) {
        // 開発環境ではconsoleにも出力
        if (location.hostname === 'localhost') {
          console.warn('[Sentry]', event);
        }
        // 既知の無害なエラーを除外
        if (event.exception && event.exception.values) {
          var msg = event.exception.values[0].value || '';
          // ブラウザ拡張機能のエラーを除外
          if (msg.match(/extension|chrome-extension|moz-extension/i)) {
            return null;
          }
          // ResizeObserver loopエラーを除外（無害）
          if (msg.includes('ResizeObserver loop')) {
            return null;
          }
        }
        return event;
      },

      // PII(個人情報)を送信しない
      sendDefaultPii: false,

      // ネットワークエラーの詳細を記録
      integrations: function(integrations) {
        return integrations;
      }
    });

    window.ErrorMonitor.initialized = true;
    console.info('[ErrorMonitor] Sentry initialized (release: ' + (window.APP_CONFIG.version || 'unknown') + ')');
  };

  script.onerror = function() {
    console.warn('[ErrorMonitor] Failed to load Sentry SDK. Error monitoring disabled.');
  };

  document.head.appendChild(script);
})();
