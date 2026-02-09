-- Add approval status to users
-- status: 'pending' (awaiting approval), 'approved' (can login), 'rejected' (denied)
ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'approved';

-- Set existing users to approved
UPDATE users SET status = 'approved' WHERE status IS NULL;

-- Admin notifications table
CREATE TABLE IF NOT EXISTS admin_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  message TEXT NOT NULL,
  data TEXT,
  is_read INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_admin_notifications_read ON admin_notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_admin_notifications_type ON admin_notifications(type);
