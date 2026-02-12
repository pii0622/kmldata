-- Session management table for token invalidation
-- Allows tracking active sessions and revoking them server-side

CREATE TABLE sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  session_token TEXT UNIQUE NOT NULL,  -- Random token stored in JWT, checked on each request
  ip_address TEXT,
  user_agent TEXT,
  device_name TEXT,  -- Derived from user agent (e.g., "Chrome on Windows")
  created_at TEXT DEFAULT (datetime('now')),
  last_active_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,  -- Session expiration (matches JWT expiration)
  is_revoked INTEGER DEFAULT 0,  -- Set to 1 when session is invalidated
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for fast token lookup
CREATE INDEX idx_sessions_token ON sessions(session_token);

-- Index for user's sessions lookup
CREATE INDEX idx_sessions_user ON sessions(user_id, is_revoked);

-- Index for cleanup of expired sessions
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
