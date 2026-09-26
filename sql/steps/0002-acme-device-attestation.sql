-- 0002-acme-device-attestation.sql — ACME device attestation for Apple devices.
--
-- Carries a v0.2.3 database to the shape v0.3.0 needs. Both tables are new, so nothing in
-- an existing database is touched:
--   acme_device_tickets  one-time device tickets, and the ticket an order by a registered
--                        serial gets; node-local, like the other ACME session tables
--   acme_device_serials  the serial numbers an MDM fleet enrols by; replicated across a mesh
-- Identical to the definitions in createdb.sql, which a new install uses instead.
create table if not exists acme_device_tickets(ticket text PRIMARY KEY, ca_instance_id text NOT NULL, owner text NOT NULL, profile text NOT NULL DEFAULT '', expires bigint NOT NULL, created bigint NOT NULL, order_id text, device_serial text, device_udid text, attested_spki bytea, cert_serial text, expected_serial text);
create index if not exists acme_device_tickets_order_idx on acme_device_tickets(order_id);
create index if not exists acme_device_tickets_serial_idx on acme_device_tickets(device_serial);
create table if not exists acme_device_serials(serial text NOT NULL, ca_instance_id text NOT NULL, owner text NOT NULL, profile text NOT NULL DEFAULT '', created bigint NOT NULL DEFAULT 0, updated bigint NOT NULL DEFAULT 0, PRIMARY KEY(serial, ca_instance_id));

-- Publish the replicated one on a mesh node. Nothing else adds a table a step created to
-- fastpki_pub; schema-apply.sh then refreshes the subscriptions, which copies it to peers,
-- and regenerates the last-writer-wins triggers. A single deployment has no publication.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'fastpki_pub') THEN
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables
                    WHERE pubname = 'fastpki_pub' AND tablename = 'acme_device_serials') THEN
        ALTER PUBLICATION fastpki_pub ADD TABLE acme_device_serials;
        RAISE NOTICE 'acme_device_serials added to fastpki_pub';
    END IF;
END $$;

INSERT INTO schema_version(version, name, applied)
  VALUES (2, 'acme-device-attestation', 0) ON CONFLICT (version) DO NOTHING;
