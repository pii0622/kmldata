-- Add parent_id to kml_folders for hierarchical structure
ALTER TABLE kml_folders ADD COLUMN parent_id INTEGER REFERENCES kml_folders(id) ON DELETE CASCADE;

-- Create index for kml_folders parent
CREATE INDEX IF NOT EXISTS idx_kml_folders_parent ON kml_folders(parent_id);

-- Pin folder visibility (per-user toggle for showing/hiding pin folders on map)
CREATE TABLE IF NOT EXISTS folder_visibility (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folder_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  is_visible INTEGER DEFAULT 1,
  FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(folder_id, user_id)
);

-- Create index for folder_visibility
CREATE INDEX IF NOT EXISTS idx_folder_visibility_folder ON folder_visibility(folder_id);
CREATE INDEX IF NOT EXISTS idx_folder_visibility_user ON folder_visibility(user_id);
