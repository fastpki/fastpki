-- 0003-web-session-idle.sql — when each console session was last used, for the idle timeout.
--
-- Carries a v0.3.0 database forward. web_sessions is node-local (not in fastpki_pub), so
-- nothing is published. Sessions that exist when this runs get 0, which is idle, so everyone
-- signs in once more after the update.
-- Identical to the definition in createdb.sql, which a new install uses instead.
alter table web_sessions add column if not exists last_seen bigint NOT NULL DEFAULT 0;

INSERT INTO schema_version(version, name, applied)
  VALUES (3, 'web-session-idle', 0) ON CONFLICT (version) DO NOTHING;
