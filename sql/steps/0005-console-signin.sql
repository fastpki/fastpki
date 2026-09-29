-- 0005-console-signin.sql — console sign-in with an attested device certificate and a PIN,
-- and with passkeys.
--
-- Carries a v0.4.0 database forward.
--   device_certs         the certificates issued through an Apple-attested ACME device order;
--                        replicated, so the console on any node can recognise one
--   console_pins         each person's console PIN, hashed; replicated
--   passkeys             each person's registered passkeys; replicated
--   passkey_challenges   outstanding passkey challenges; node-local, like ACME nonces
--   web_sessions         gains how the session signed in, the device certificate it is bound
--                        to, and when it began. Existing sessions are ended, so everyone signs
--                        in once more after the update.
-- Identical to the definitions in createdb.sql, which a new install uses instead.
create table if not exists device_certs(serial text PRIMARY KEY, owner text NOT NULL, ca_instance_id text NOT NULL, device_serial text NOT NULL, spki bytea NOT NULL, created bigint NOT NULL DEFAULT 0);
create table if not exists console_pins(subject text PRIMARY KEY, hash text NOT NULL, created bigint NOT NULL DEFAULT 0, updated bigint NOT NULL DEFAULT 0);
create table if not exists passkeys(credential_id text PRIMARY KEY, subject text NOT NULL, user_handle text NOT NULL, public_key bytea NOT NULL, alg integer NOT NULL, sign_count bigint NOT NULL DEFAULT 0, name text NOT NULL DEFAULT '', created bigint NOT NULL DEFAULT 0, last_used bigint NOT NULL DEFAULT 0, updated bigint NOT NULL DEFAULT 0);
create index if not exists passkeys_subject_idx on passkeys(lower(subject));
create table if not exists passkey_challenges(challenge text PRIMARY KEY, purpose text NOT NULL, subject text NOT NULL DEFAULT '', expires bigint NOT NULL);

alter table web_sessions add column if not exists method text NOT NULL DEFAULT '';
alter table web_sessions add column if not exists cert_serial text NOT NULL DEFAULT '';
alter table web_sessions add column if not exists created bigint NOT NULL DEFAULT 0;
delete from web_sessions where method = '';

-- The device certificates this node already issued. acme_device_tickets is node-local, so each
-- node records its own, and replication carries them to the others.
insert into device_certs(serial, owner, ca_instance_id, device_serial, spki, created)
  select cert_serial, owner, ca_instance_id, device_serial, attested_spki, created
    from acme_device_tickets
   where cert_serial is not null and cert_serial <> ''
     and device_serial is not null and device_serial <> ''
     and attested_spki is not null
  on conflict (serial) do nothing;

-- Publish the replicated ones on a mesh node. schema-apply.sh then refreshes the subscriptions,
-- which copies them to peers, and regenerates the last-writer-wins triggers. A single
-- deployment has no publication.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'fastpki_pub') THEN
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables
                    WHERE pubname = 'fastpki_pub' AND tablename = 'device_certs') THEN
        ALTER PUBLICATION fastpki_pub ADD TABLE device_certs;
        RAISE NOTICE 'device_certs added to fastpki_pub';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables
                    WHERE pubname = 'fastpki_pub' AND tablename = 'console_pins') THEN
        ALTER PUBLICATION fastpki_pub ADD TABLE console_pins;
        RAISE NOTICE 'console_pins added to fastpki_pub';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables
                    WHERE pubname = 'fastpki_pub' AND tablename = 'passkeys') THEN
        ALTER PUBLICATION fastpki_pub ADD TABLE passkeys;
        RAISE NOTICE 'passkeys added to fastpki_pub';
    END IF;
END $$;

INSERT INTO schema_version(version, name, applied)
  VALUES (5, 'console-signin', 0) ON CONFLICT (version) DO NOTHING;
