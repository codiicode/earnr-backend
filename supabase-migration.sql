-- Migration: Production hardening for launch
-- Run this in your Supabase SQL Editor before deploying

-- 1. OAuth states table (for persistent login state across deploys)
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  verifier TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Auto-cleanup: delete states older than 10 minutes
CREATE INDEX IF NOT EXISTS idx_oauth_states_created_at ON oauth_states(created_at);

-- 2. Atomic slot increment (prevents race condition on task submissions)
CREATE OR REPLACE FUNCTION increment_slot(task_id_input UUID)
RETURNS void AS $$
BEGIN
  UPDATE tasks
  SET slots_filled = slots_filled + 1
  WHERE id = task_id_input
    AND slots_filled < slots_total;
END;
$$ LANGUAGE plpgsql;

-- 3. Atomic slot decrement (for rejections)
CREATE OR REPLACE FUNCTION decrement_slot(task_id_input UUID)
RETURNS void AS $$
BEGIN
  UPDATE tasks
  SET slots_filled = GREATEST(slots_filled - 1, 0)
  WHERE id = task_id_input;
END;
$$ LANGUAGE plpgsql;
