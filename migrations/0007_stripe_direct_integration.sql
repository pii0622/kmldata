-- Stripe direct payment integration
-- Extends member_source to support direct Stripe payments

-- member_source values:
--   NULL        -> Regular free user (signed up directly)
--   'stripe'    -> Premium via direct Stripe payment (managed in-app)
--   'wordpress' -> Premium via WordPress/Stripe (managed externally)

-- Add stripe_customer_id for users who pay directly through Stripe
ALTER TABLE users ADD COLUMN stripe_customer_id TEXT DEFAULT NULL;

-- Add stripe_subscription_id to track active subscription
ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT DEFAULT NULL;

-- Add subscription_ends_at for tracking when premium expires
-- (useful for grace period after cancellation)
ALTER TABLE users ADD COLUMN subscription_ends_at TEXT DEFAULT NULL;

-- Create index for Stripe lookups
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id);
