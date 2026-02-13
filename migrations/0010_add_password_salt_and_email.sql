-- Add password_salt column for PBKDF2 password hashing
-- Existing users with NULL salt will use legacy SHA-256 verification
ALTER TABLE users ADD COLUMN password_salt TEXT DEFAULT NULL;

-- Add email column for user contact
ALTER TABLE users ADD COLUMN email TEXT DEFAULT NULL;
