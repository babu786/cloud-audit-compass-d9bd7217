-- STEP 2: Drop foreign key constraints that reference auth.users, then alter columns

-- Drop FK constraints referencing auth.users
ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_id_fkey;
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_user_id_fkey;

-- Now alter column types to TEXT for Firebase UIDs
ALTER TABLE enrollments ALTER COLUMN user_id TYPE text USING user_id::text;
ALTER TABLE certificates ALTER COLUMN user_id TYPE text USING user_id::text;
ALTER TABLE profiles ALTER COLUMN id TYPE text USING id::text;
ALTER TABLE user_roles ALTER COLUMN user_id TYPE text USING user_id::text;