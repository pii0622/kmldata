-- Support for external members (e.g., WordPress/Stripe integration)

-- member_source: NULL (regular signup) or 'wordpress' (external)
ALTER TABLE users ADD COLUMN member_source TEXT DEFAULT NULL;

-- plan: 'free' or 'premium'
ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free';

-- external_id: ID from external system (e.g., WordPress user ID)
ALTER TABLE users ADD COLUMN external_id TEXT DEFAULT NULL;

-- Create index for external lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_external ON users(member_source, external_id);
