-- Add provider_url column to reports table
-- Defaults to 'https://github.com' for existing and new rows

ALTER TABLE reports ADD COLUMN provider_url TEXT NOT NULL DEFAULT 'https://github.com';
