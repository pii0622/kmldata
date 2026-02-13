// App Configuration - Easy to change
const APP_CONFIG = {
  // App name and branding
  name: 'Fieldnota commons',
  shortName: 'Fieldnota',
  tagline: '見つけたナニカを、notaに記録する。共有する。',

  // Domain (change this when domain changes)
  domain: 'fieldnota-commons.com',

  // Logo paths (replace with actual logos)
  logoIcon: '/images/logo-icon.svg',
  logoTitle: '/images/logo-title.png',

  // Contact/Support
  contactEmail: 'support@example.com',

  // Error monitoring (Sentry)
  // Sentry DSNを設定するとエラー監視が有効になります
  // 例: 'https://examplePublicKey@o0.ingest.sentry.io/0'
  sentryDsn: '',

  // Version
  version: '2.0.0'
};

// Make it available globally
window.APP_CONFIG = APP_CONFIG;
