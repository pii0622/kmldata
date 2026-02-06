-- Users table with display_name
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Pin folders (hierarchical)
CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  parent_id INTEGER,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Pins
CREATE TABLE IF NOT EXISTS pins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  folder_id INTEGER,
  user_id INTEGER NOT NULL,
  is_public INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Pin images (stored in R2)
CREATE TABLE IF NOT EXISTS pin_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pin_id INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (pin_id) REFERENCES pins(id) ON DELETE CASCADE
);

-- KML folders for organizing KML files
CREATE TABLE IF NOT EXISTS kml_folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  is_public INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- KML files (stored in R2)
CREATE TABLE IF NOT EXISTS kml_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folder_id INTEGER,
  user_id INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  is_public INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (folder_id) REFERENCES kml_folders(id) ON DELETE SET NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Folder sharing (share pin folders with specific users)
CREATE TABLE IF NOT EXISTS folder_shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folder_id INTEGER NOT NULL,
  shared_with_user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
  FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(folder_id, shared_with_user_id)
);

-- KML folder sharing (share KML folders with specific users)
CREATE TABLE IF NOT EXISTS kml_folder_shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kml_folder_id INTEGER NOT NULL,
  shared_with_user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (kml_folder_id) REFERENCES kml_folders(id) ON DELETE CASCADE,
  FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(kml_folder_id, shared_with_user_id)
);

-- KML folder visibility (per-user toggle for showing/hiding KML folders on map)
CREATE TABLE IF NOT EXISTS kml_folder_visibility (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kml_folder_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  is_visible INTEGER DEFAULT 1,
  FOREIGN KEY (kml_folder_id) REFERENCES kml_folders(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(kml_folder_id, user_id)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_pins_user ON pins(user_id);
CREATE INDEX IF NOT EXISTS idx_pins_folder ON pins(folder_id);
CREATE INDEX IF NOT EXISTS idx_kml_files_folder ON kml_files(folder_id);
CREATE INDEX IF NOT EXISTS idx_kml_files_user ON kml_files(user_id);
CREATE INDEX IF NOT EXISTS idx_folder_shares_folder ON folder_shares(folder_id);
CREATE INDEX IF NOT EXISTS idx_folder_shares_user ON folder_shares(shared_with_user_id);
CREATE INDEX IF NOT EXISTS idx_kml_folder_shares_folder ON kml_folder_shares(kml_folder_id);
CREATE INDEX IF NOT EXISTS idx_kml_folder_shares_user ON kml_folder_shares(shared_with_user_id);
