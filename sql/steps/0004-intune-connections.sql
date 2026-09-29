-- 0004-intune-connections.sql — Microsoft Intune tenants whose devices enrol over SCEP.
--
-- Carries a v0.3.1 database forward. The table is new, so nothing in an existing database is
-- touched. It is administrator-maintained and replicated across a mesh.
-- Identical to the definition in createdb.sql, which a new install uses instead.
create table if not exists intune_connections(id text PRIMARY KEY, tenant_id text NOT NULL, app_id text NOT NULL, ca_instance_id text NOT NULL, profile text NOT NULL DEFAULT '', enabled boolean NOT NULL DEFAULT true, login_url text NOT NULL DEFAULT 'https://login.microsoftonline.com', graph_url text NOT NULL DEFAULT 'https://graph.microsoft.com', intune_resource text NOT NULL DEFAULT 'https://api.manage.microsoft.com/', created bigint NOT NULL DEFAULT 0, updated bigint NOT NULL DEFAULT 0);

-- Publish it on a mesh node. schema-apply.sh then refreshes the subscriptions, which copies it
-- to peers, and regenerates the last-writer-wins triggers. A single deployment has no
-- publication.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'fastpki_pub') THEN
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_publication_tables
                    WHERE pubname = 'fastpki_pub' AND tablename = 'intune_connections') THEN
        ALTER PUBLICATION fastpki_pub ADD TABLE intune_connections;
        RAISE NOTICE 'intune_connections added to fastpki_pub';
    END IF;
END $$;

INSERT INTO schema_version(version, name, applied)
  VALUES (4, 'intune-connections', 0) ON CONFLICT (version) DO NOTHING;
