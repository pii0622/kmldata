-- Add sort_order column to folders
ALTER TABLE folders ADD COLUMN sort_order INTEGER DEFAULT 0;

-- Add sort_order column to kml_folders
ALTER TABLE kml_folders ADD COLUMN sort_order INTEGER DEFAULT 0;

-- Add is_public column to folders if not exists (may already exist)
ALTER TABLE folders ADD COLUMN is_public INTEGER DEFAULT 0;

-- Create indexes for sorting
CREATE INDEX IF NOT EXISTS idx_folders_sort ON folders(parent_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_kml_folders_sort ON kml_folders(sort_order);
