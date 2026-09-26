-- `certs` holds leaf certificates AND CA rows (merged from the ca_instances table).
-- A CA row carries is_ca=true; id is the CA's stable identifier (NULL for a leaf).
-- private_key is a pkcs11: URI naming this row's key (NULL when not in this node's token).
-- name / ca_enabled / ms_enroll_permission are NULL for a leaf.
-- ca_instance_id names the CA each row belongs to, without FK.
-- cert_id tags a transport-cert row. dc_range trigger exempts rows carrying cert_id.
-- cert_id is not unique — selection orders CA-issued ahead of self-signed, then newest.
create table if not exists certs(
  serial text PRIMARY KEY, status integer, "revocationReason" integer, "revocationDate" bigint,
  "notBefore" bigint, "notAfter" bigint, subject text, owner text, cert bytea, cn text,
  fingerprint bytea, "sHash" bytea, "iHash" bytea, "iAndSHash" bytea, "sKIDHash" bytea,
  "keyAlgo" text, "keyBits" integer, "sigAlgo" text,
  ca_instance_id text, cert_id text,
  name text, ca_enabled boolean, ms_enroll_permission boolean,
  id text, private_key text, is_ca boolean NOT NULL DEFAULT false,
  -- Per-node insertion order, so a "notBefore" tie between two live generations of
  -- a re-keyed CA has a deterministic winner. High 15 bits are this DC's serial_prefix,
  -- low 48 a node-local sequence — the same partitioning as the serial, so values from
  -- different DCs cannot collide. NO DEFAULT: the insert sets it under this node's
  -- prefix, and a row that arrives from a mesh peer carries the value its origin gave it.
  -- Consumers order `ins_seq DESC NULLS LAST, serial DESC`.
  ins_seq bigint,
  -- What a PERSON searches by, derived from the certificate at insert like the hash columns
  -- above it. fp_sha1 is the SHA-1 thumbprint Windows and browsers display; `sans` is every
  -- additional name, type-tagged ("DNS:host", "IP:10.0.0.1"), because a server certificate is
  -- usually looked for by a name that is not its CN. `fingerprint` (SHA-256) is already here.
  fp_sha1 text,
  sans text);

-- Node-local, never replicated — logical replication does not carry sequences, and
-- it must not: each node counts for itself beneath its own prefix. MAXVALUE is the low
-- 48 bits, so exhaustion RAISES instead of carrying into a peer's prefix space.
create sequence if not exists certs_seq_local
    as bigint MAXVALUE 281474976710655 NO CYCLE;
create index if not exists ihash_idx on certs("iHash");
create index if not exists subj_idx on certs(subject);
create index if not exists status_idx on certs(status);
create index if not exists from_idx on certs("notBefore");
create index if not exists to_idx on certs("notAfter");
create index if not exists owner_idx on certs(owner);
create index if not exists cn_idx on certs(cn);
create index if not exists fingerprint_idx on certs(fingerprint);
create index if not exists sHash_idx on certs("sHash");
create index if not exists iAndSHash_idx on certs("iAndSHash");
create index if not exists sKIDHash_idx on certs("sKIDHash");
create index if not exists certs_ca_idx on certs(ca_instance_id);
create index if not exists certs_cert_id_idx on certs(cert_id) WHERE cert_id IS NOT NULL;
create index if not exists certs_id_idx on certs(id) WHERE id IS NOT NULL;
create index if not exists certs_is_ca_idx on certs(is_ca) WHERE is_ca;
-- RFC 4387 §2 `uri` selector: a cert's SubjectAltName URIs, one row
-- each (a cert may carry several), so the store can find it by ?uri=<value>.
create table if not exists cert_uris(serial text NOT NULL, uri text NOT NULL, PRIMARY KEY(serial, uri));
create index if not exists cert_uri_idx on cert_uris(uri);
create table if not exists cert_req_ids(serial text PRIMARY KEY, "certReqId" text, timestamp integer, nonce text, "transactionID" text);
create index if not exists certReqId_idx on cert_req_ids("certReqId");
create index if not exists transactionID_idx on cert_req_ids("transactionID");
-- Per-user symmetric enrolment secrets, minted by a role grant and read through
-- get_shared_secret: the CMP password-based-MAC secret, the ACME External Account
-- Binding HMAC key, and the SCEP challengePassword.
--
-- `kid` is the USERNAME for all three and `protocol` tells the rows apart. The kid
-- used to carry the distinction as a suffix ("alice:eab", "alice:scep") because this
-- table was keyed by kid alone — which put a storage detail on the wire and recorded
-- ACME certificates under an owner named `alice:eab`.
--
-- `updated` carries the last-writer-wins stamp so this replicates cluster-wide like
-- the other admin-managed tables — a credential that existed on only the DC that
-- created it would make a downloaded client config work on one node out of three.
-- ⚠️ The LWW trigger locates a row by the PRIMARY KEY, so kMgmtTables must name BOTH
-- columns; with `kid` alone one user's three secrets look like one row to the apply
-- worker and it deletes two of them.
create table if not exists keys(kid text NOT NULL, protocol text NOT NULL DEFAULT 'cmp',
                                key text, updated bigint NOT NULL DEFAULT 0,
                                PRIMARY KEY(kid, protocol));
-- Multi-data-center active-active replication: the
-- data center map. A node's identity in the mesh is a small integer PREFIX that
-- occupies the top 2 octets of every serial it mints, replacing the old
-- [serial_min, serial_max) range. Same guarantee — two data centers can never mint the same
-- serial, so the certs primary key never collides — with nothing to configure, validate for
-- overlap, or keep in two places.
--
-- serial_prefix is 1..32767 so the high bit of the leading octet is always clear: DER
-- integers are signed, and a value with the top bit set would be padded with a leading 0x00
-- to stay positive, pushing the serial to 21 octets and out of RFC 5280 §4.1.2.2.
--
-- conninfo is why this table cannot simply go away: fastpki-mesh builds the subscriptions
-- from it.
create table if not exists datacenters(
  dc_id         text PRIMARY KEY,
  serial_prefix integer NOT NULL UNIQUE CHECK (serial_prefix between 1 and 32767),
  conninfo      text,
  -- The public base URL a client uses to reach THIS data center — scheme and host only,
  -- e.g. https://pki-dc2.example.com. Every certificate issued anywhere in the mesh
  -- carries one CRLDP and one AIA entry per data center built from these, so a relying
  -- party that cannot reach one node has another to try. A certificate already issued
  -- cannot learn a new URL, which is why this belongs to the node rather than to a
  -- config key someone has to remember to update when a data center joins.
  base_url text);
-- Tamper-evident, append-only audit log. hash = SHA-256(canonical(row) || prev_hash).

-- ⚠️ KEYED ON THE HOST, NOT THE DATA CENTER. These two certificates identify a MACHINE to
-- the token tunnel: one node dials another and each end verifies the other's. A mesh has one
-- host per data center, so they lived on `datacenters` — and an HA pair is two hosts in ONE,
-- which left a Postgres standby with nowhere to publish its client certificate and therefore
-- no way to replicate a CA key out of its primary. dc_id is recorded but not part of the
-- key, and may be null: a standby has no DATACENTER_ID of its own and still has to be
-- admitted by its primary.
create table if not exists p11_transport(
  host_id     text PRIMARY KEY,
  dc_id       text,
  client_cert text,
  server_cert text);
-- What each HOST reports about itself, for the console's Replication page: its keys, its
-- database connection and certificate, the replication it sees, and its last key sync.
-- Keyed on the host for the same reason as p11_transport, and written only by that host —
-- a console behind a load balancer is served by whichever host was picked, and can read
-- its own token only, so each host publishing its own row is how one page shows them all.
--   report            JSON, rewritten by the host's console about once a minute
--   key_sync          JSON, the result of the host's last `fastpki-ca key sync`
--   key_sync_request  the node_sync_requests.requested_at this host last started
create table if not exists node_status(
  host_id          text PRIMARY KEY,
  dc_id            text,
  reported_at      bigint NOT NULL DEFAULT 0,
  report           text,
  key_sync         text,
  key_sync_at      bigint NOT NULL DEFAULT 0,
  key_sync_request bigint NOT NULL DEFAULT 0);
-- A console's request that a host run `key sync` now. Separate from node_status because it
-- is written by whichever console an operator used, while node_status is written only by
-- the host itself: one writer per row keeps last-writer-wins from dropping either.
create table if not exists node_sync_requests(
  host_id      text PRIMARY KEY,
  requested_at bigint NOT NULL DEFAULT 0,
  requested_by text);
create table if not exists audit_log(seq bigserial PRIMARY KEY, ts bigint NOT NULL, category text NOT NULL, action text NOT NULL, actor text, actor_ip text, target text, status text NOT NULL, detail text, prev_hash text NOT NULL, hash text NOT NULL, ca_instance_id text);
create index if not exists audit_ts_idx on audit_log(ts);
create index if not exists audit_cat_idx on audit_log(category);
create index if not exists audit_actor_idx on audit_log(actor);
create index if not exists audit_ca_idx on audit_log(ca_instance_id);
-- Discovered (unmanaged) certificates harvested from TLS endpoints.
create table if not exists discovered_certs(id bigserial PRIMARY KEY, target text, serial text, subject text, issuer text, "notBefore" bigint, "notAfter" bigint, "keyAlgo" text, "keyBits" integer, "sigAlgo" text, sans text, fingerprint text, "selfSigned" integer, flags text, "discoveredAt" bigint, cert bytea, ca_instance_id text);
create index if not exists disc_target_idx on discovered_certs(target);
create index if not exists disc_fp_idx on discovered_certs(fingerprint);
create index if not exists discovered_ca_idx on discovered_certs(ca_instance_id);
-- Signed audit checkpoints: CA signature over the audit head.
create table if not exists audit_checkpoints(id bigserial PRIMARY KEY, at bigint NOT NULL, head_seq bigint NOT NULL, head_hash text NOT NULL, signature text NOT NULL);
-- How far the audit-log shipper has got, per collector. Node-local like audit_log itself:
-- each node ships its own rows and keeps its own position, so this must never replicate.
create table if not exists audit_forward_state(target text PRIMARY KEY, last_seq bigint NOT NULL DEFAULT 0, updated bigint NOT NULL DEFAULT 0);
-- SCEP one-time/expiring challenge tokens.
create table if not exists scep_challenges(token text PRIMARY KEY, profile text, expires bigint NOT NULL, used integer NOT NULL DEFAULT 0, created bigint NOT NULL);
-- SCEP manual-approval (async) enrollment requests parked as PENDING.
-- status: 0 = pending, 1 = issued (serial set), 2 = rejected.
create table if not exists scep_pending(txid text PRIMARY KEY, subject text, csr bytea NOT NULL, status integer NOT NULL DEFAULT 0, serial text, created bigint NOT NULL);
create index if not exists scep_pending_status_idx on scep_pending(status);
create table if not exists nonces(nonce text PRIMARY KEY, ip text, expires integer);
create index if not exists ip_idx on nonces(ip);
create index if not exists expires_idx on nonces(expires);
create table if not exists accounts(id text PRIMARY KEY, status integer, "termsOfServiceAgreed" integer, jwk_hash text, kid text, jwk bytea, contacts bytea, "externalAccountBinding" bytea);
create index if not exists jwk_hash_idx on accounts(jwk_hash);
create index if not exists account_status_idx on accounts(status);
create index if not exists account_kid_idx on accounts(kid);
create table if not exists orders(id text PRIMARY KEY, status integer, expires integer, identifiers bytea, "notBefore" integer, "notAfter" integer, "certSerial" text, account text, ca_instance_id text, foreign key(account) references accounts(id) ON DELETE CASCADE);  -- ca_instance_id — the CA that authorized this order, checked at finalize
create index if not exists order_status_idx on orders(status);
create index if not exists order_expires_idx on orders(expires);
create index if not exists notBefore_idx on orders("notBefore");
create index if not exists notAfter_idx on orders("notAfter");
create table if not exists authorizations(id text PRIMARY KEY, identifier bytea, status integer, expires integer, wildcard integer, "order" text, account text, foreign key("order") references orders(id) ON DELETE CASCADE);
create index if not exists authorization_status_idx on authorizations(status);
create index if not exists authorization_expires_idx on authorizations(expires);
create index if not exists authorization_account_idx on authorizations(account);
create table if not exists challenges(id text PRIMARY KEY, type text, url text, status integer, token text, error text, validated integer, "authorization" text, foreign key("authorization") references authorizations(id) ON DELETE CASCADE);
create index if not exists type_idx on challenges(type);
create index if not exists challenge_status_idx on challenges(status);
create index if not exists token_idx on challenges(token);
create index if not exists validated_idx on challenges(validated);
-- ACME device attestation (device-attest-01): one-time tickets an administrator issues with
-- `fastpki-acme --issue-device-ticket`. A ticket is an Apple device's ClientIdentifier; it
-- names the CA, the owner the certificate is issued to and the profile, and it can back one
-- order only (order_id is set once, atomically). The attested serial, UDID and key are
-- recorded when the challenge verifies, the certificate serial at issuance — which is how a
-- device's next certificate finds and revokes its previous one. An order authorised by a
-- registered serial number (acme_device_serials) gets a ticket of its own, created already
-- claimed, with expected_serial set: the attestation must then prove exactly that serial.
create table if not exists acme_device_tickets(ticket text PRIMARY KEY, ca_instance_id text NOT NULL, owner text NOT NULL, profile text NOT NULL DEFAULT '', expires bigint NOT NULL, created bigint NOT NULL, order_id text, device_serial text, device_udid text, attested_spki bytea, cert_serial text, expected_serial text);
create index if not exists acme_device_tickets_order_idx on acme_device_tickets(order_id);
-- The devices an MDM fleet may enrol without a ticket: the profile's ClientIdentifier is the
-- device's serial number, and Apple attests it. Administrator-maintained, so it replicates
-- (last writer wins on `updated`), like the approved domains.
create table if not exists acme_device_serials(serial text NOT NULL, ca_instance_id text NOT NULL, owner text NOT NULL, profile text NOT NULL DEFAULT '', created bigint NOT NULL DEFAULT 0, updated bigint NOT NULL DEFAULT 0, PRIMARY KEY(serial, ca_instance_id));
create index if not exists acme_device_tickets_serial_idx on acme_device_tickets(device_serial);

-- MS-XCEP CA URI collection. Per xcep.xsd a CA carries {uris (1..n), certificate,
-- enrollPermission, cAReferenceID}. clientAuthentication / priority / renewalOnly are
-- per-URI attributes. uri='' = "this server's own WSTEP endpoint for this CA".
--   client_auth  1 anonymous | 2 Kerberos | 4 username+password | 8 X.509
--   priority     -1 emits xsi:nil (the element is nillable)
create table if not exists ca_xcep_uris(
  ca_instance_id text NOT NULL,
  seq int NOT NULL,
  uri text NOT NULL DEFAULT '',
  client_auth int NOT NULL DEFAULT 4,
  priority int NOT NULL DEFAULT 1,
  renewal_only boolean NOT NULL DEFAULT false,
  PRIMARY KEY(ca_instance_id, seq)
);

-- Dynamic configuration: a key/value overlay applied on top
-- of bootstrap.conf at server startup (DB wins). Keys are the uppercase bootstrap.conf names;
-- bootstrap keys (SQL_DB/PG_CONNINFO) live only in the file.
create table if not exists config(key text PRIMARY KEY, value text NOT NULL, updated bigint NOT NULL DEFAULT 0);

-- Console login users. This table is the ONLY user store —
-- the file backends were removed (WEB_USERS_FILE, then USERS_FILE).
-- hash is a pbkdf2$... string.
-- auth_provider: WHICH mechanism authenticates this identity — local | ldap |
-- saml | oidc | kerberos | dn. Recorded per row at onboarding, never derived from
-- AUTH_BACKEND, so it cannot mislabel SAML/OIDC nor change when that key changes.
-- email: where expiry emails for this account's certificates go when no directory says —
-- typed on the Users page, or filled from the email claim at each SSO sign-in.
create table if not exists web_users(username text NOT NULL PRIMARY KEY, role text NOT NULL, hash text NOT NULL, must_reset integer NOT NULL DEFAULT 0, created bigint NOT NULL DEFAULT 0, auth_provider text NOT NULL DEFAULT '', email text NOT NULL DEFAULT '');
-- ⚠️ THE LOOKUPS ARE CASE-INSENSITIVE, SO THE CONSTRAINT MUST BE TOO. get_web_user and
-- delete_web_user match on lower(username); the PRIMARY KEY above does not, so `Admin`
-- and `admin` were two rows, both matched the login query, and `ORDER BY username
-- LIMIT 1` picked the winner by collation — letting anyone who may create users shadow
-- an existing account. This index is what makes the second row impossible, and it is
-- what upsert_web_user infers its ON CONFLICT against.
create unique index if not exists web_users_lower_username_idx on web_users(lower(username));
create table if not exists allowed_domains(domain text PRIMARY KEY, created bigint NOT NULL DEFAULT 0);

-- selector_type is 'user' (auth username) or 'group' (a directory group).
-- There was a third type, 'dn', selecting on a client certificate's subject DN.
-- It is gone — it was written, replicated to every DC and read by nothing. Roles are
-- granted to rows in this database, never to anything a certificate carries.
-- The rule this follows: an x509 certificate is about authentication, not
-- authorization, so a role lives outside the DN in a table column and never becomes
-- part of the DN itself.
-- Console role assignments: a subject maps to one or MORE
-- console roles; effective permission is the UNION of the matched roles' grants.
create table if not exists subject_roles(selector_type text NOT NULL, selector_value text NOT NULL, role text NOT NULL, created bigint NOT NULL DEFAULT 0, PRIMARY KEY(selector_type, selector_value, role));

-- Console sessions: persisted so a restart or an LB failover to
-- another web instance on the same DB doesn't log everyone out. The PRIMARY KEY is the
-- SHA-256 of the session token, never the token itself, so a DB dump / backup can't hand
-- over a live session. Local per-DC (a session belongs to one instance's console).
-- `expires` is the absolute end (12 hours after sign-in); `last_seen` is when the session was
-- last used, for the idle timeout (15 minutes).
create table if not exists web_sessions(
  token_hash text PRIMARY KEY, username text NOT NULL, role text NOT NULL,
  must_reset integer NOT NULL DEFAULT 0, expires bigint NOT NULL, groups text,
  last_seen bigint NOT NULL DEFAULT 0);

-- The stored member list of every GRANTED directory group, refreshed on a timer
-- (DIRECTORY_GROUP_REFRESH_SEC, 12h) and on demand from the console. Two tables because
-- an empty group and an unrefreshed group are different facts: `directory_groups` records
-- that we asked and what came back, `directory_group_members` records who was in it. A
-- group with a state row and no member rows is genuinely empty; a group with neither has
-- never been resolved.
--
-- NODE-LOCAL, deliberately — not in fastpki_pub, same reasoning as web_sessions and
-- schema_version. This is a cache of an EXTERNAL authority that every DC can query for
-- itself, so each node stores what its own directory link can see. Replicating it would
-- mean a node that cannot reach the DC displays another node's answer as its own, and it
-- would need an `updated` LWW stamp and a trigger regeneration on every deploy (§5.0b)
-- to buy nothing.
create table if not exists directory_groups(
  grp       text PRIMARY KEY,
  refreshed bigint NOT NULL DEFAULT 0,   -- last refresh that REPLACED the member list
  attempted bigint NOT NULL DEFAULT 0,   -- last attempt, successful or not
  err       text NOT NULL DEFAULT '');   -- why the last attempt did not replace the list
create table if not exists directory_group_members(
  grp text NOT NULL, username text NOT NULL, display text NOT NULL DEFAULT '',
  PRIMARY KEY (grp, username));

-- Per-protocol client-config overrides: an admin-curated body that the
-- download endpoint serves (with {{TOKENS}} substituted from live settings) instead
-- of the generated default. One row per kind (cmp/acme/scep/ms). Replicated,
-- last-writer-wins on `updated`.
create table if not exists client_configs(
  kind text PRIMARY KEY, body text NOT NULL, updated bigint NOT NULL DEFAULT 0);

-- Certificate profiles: one row per profile, `definition` the JSON object the Profiles page
-- edits ({"allowed_ku":[…], "default_eku":[…], …}). A built-in (`admin`, `requester`) has a
-- row only once it is edited; without one the code default applies, so an improvement to
-- that default still reaches a deployment that never touched it.
-- REPLICATED, last-writer-wins, like ms_templates: the role grants that name a profile
-- replicate, so the definition they name has to arrive with them. It used to live in the
-- node-local `config` table, which is node-local for the identity keys beside it.
create table if not exists cert_profiles(
  name text PRIMARY KEY, definition text NOT NULL, updated bigint NOT NULL DEFAULT 0);

-- The expiry email's template, edited on the Notifications page: the subject, the line each
-- certificate gets, and the body the lines are placed in. No row means the built-in text.
-- REPLICATED, last-writer-wins, like cert_profiles: every data center emails the owners of
-- its own certificates, and they should all be told in the words an administrator chose.
create table if not exists notify_templates(
  name text PRIMARY KEY, subject text NOT NULL, line text NOT NULL, body text NOT NULL,
  updated bigint NOT NULL DEFAULT 0);

-- The tightest stage each certificate has been emailed at: a NOTIFY_DAYS window's days, or 0
-- once it has expired. A daily run emails only when a certificate reaches a tighter stage.
-- NODE-LOCAL: only the data center whose serial prefix a certificate carries emails about
-- it, so there is one writer per row and nothing for a peer to learn.
create table if not exists notify_sent(
  serial text PRIMARY KEY, stage integer NOT NULL, sent bigint NOT NULL DEFAULT 0);

-- MS certificate templates: AD-imported templates served by fastpki-ms.
create table if not exists ms_templates(
  name text PRIMARY KEY, oid text NOT NULL,
  -- schema 3 + key_spec 0 = a CNG template, matching the code's defaults and the built-ins.
  -- Schema 1/2 permit ONLY legacy CryptoAPI CSPs, so a row defaulted to 1 and then given a
  -- Key Storage Provider is a combination Windows will not use.
  schema integer NOT NULL DEFAULT 3, enroll integer NOT NULL DEFAULT 1, auto_enroll integer NOT NULL DEFAULT 0,
  validity_days integer NOT NULL DEFAULT 730, min_key_size integer NOT NULL DEFAULT 2048, key_spec integer NOT NULL DEFAULT 0,
  key_usage bigint NOT NULL DEFAULT 40960, major_rev integer NOT NULL DEFAULT 1, minor_rev integer NOT NULL DEFAULT 0,
  private_key_flags integer NOT NULL DEFAULT 16, subject_name_flags integer NOT NULL DEFAULT 9,
  enrollment_flags integer NOT NULL DEFAULT -1, general_flags integer NOT NULL DEFAULT -1,
  pk_oid text, pk_name text, hash_oid text, hash_name text,
  crypto_providers text, ekus text, enabled integer NOT NULL DEFAULT 1, updated bigint NOT NULL DEFAULT 0,
  -- msPKI-Private-Key-Security-Descriptor, emitted as XCEP
  -- <privateKeyAttributes><permissions>. SDDL, e.g. 'O:COG:CGD:(A;;GASDWOKA;;;CO)'.
  private_key_permissions text,
  -- pKIOverlapPeriod: the renewal OVERLAP in SECONDS — how long before expiry a client
  -- should begin renewing. -1 means the template does not carry one and the XCEP
  -- serializer derives a default; 0 is a real answer ("renew at expiry"). Seconds and not
  -- days because directory overlaps for short-lived templates are routinely sub-day.
  overlap_seconds bigint NOT NULL DEFAULT -1);

-- ── Schema version ──────────────────────────────────────────────
-- What version of the schema this database IS. Binaries read it at startup and
-- refuse to run against a database older than they require, instead of failing
-- later on an arbitrary missing column (`bfee7b4`'s certs.cert_id crash-looped
-- fastpki-cmp with nothing in the log pointing at the schema).
--
-- This file is the whole current schema, so a database created from it is already
-- at the version below and `deploy/schema-apply.sh` has nothing to do. The
-- `sql/steps/NNNN-*.sql` files exist to bring an EXISTING database up to it.
--
-- NODE-LOCAL, and deliberately NOT in the replication publication (see
-- src/tools/mesh.cpp): it describes the local database's own schema state. If it
-- replicated, DC1 applying a step would instantly claim DC2 was upgraded too, which
-- is the precise opposite of what the guard is for during a staggered rollout.
create table if not exists schema_version(
  version integer PRIMARY KEY,
  name    text    NOT NULL,
  applied bigint  NOT NULL DEFAULT 0);
-- Roles are DATA, not a C++ switch, and the CA scope is folded into the permission
-- rather than kept beside it — in_scope() only ever gated CA ids, so scope was the object
-- half of a permission whose verb half we wrote and whose object half we did not.
create table if not exists foreign_anchors(fingerprint text PRIMARY KEY, subject text NOT NULL, cert bytea NOT NULL, note text, registered_by text, registered bigint NOT NULL, updated bigint);

-- ── The directories and identity providers this deployment authenticates against ──────
--
-- A deployment may have SEVERAL. That is the whole point: `CORP\alice` and
-- `PARTNER\alice` are different people, and a flat key-value config (LDAP_URIS,
-- LDAP_BASE_DNS, ...) can only ever describe ONE directory. These rows are the source of
-- truth; nothing reads those keys any more.
--
-- Split in two because the SHARED half — is it on, which order is it tried in, what does
-- the console call it — is the same question for every kind of provider, while the
-- settings differ completely between a directory and a SAML or OIDC issuer. Adding
-- `saml_providers` later adds a table beside `ldap_providers` and changes nothing here.
create table if not exists auth_providers(
  -- The stable identifier a subject is qualified BY: a directory identity is authorized
  -- as `<id>\<user>`, and web_users.auth_provider stores this. It is part of the identity,
  -- so renaming one orphans every grant made against it — the console must refuse.
  id           text PRIMARY KEY,
  kind         text NOT NULL,                        -- 'ldap' today; 'saml' / 'oidc' next
  display_name text NOT NULL DEFAULT '',             -- what a domain selector shows
  enabled      boolean NOT NULL DEFAULT true,
  -- Display and probe order only. It NEVER picks an identity: a login that names no
  -- directory is a local web_users account and is not tried against any directory at all,
  -- with one configured or with ten. "Unqualified means local" is a rule about what the
  -- name means, so it has no "how many are configured" case.
  priority     integer NOT NULL DEFAULT 100,
  created      bigint NOT NULL DEFAULT 0,
  updated      bigint NOT NULL DEFAULT 0);

-- ⚠️ NO FOREIGN KEY TO auth_providers, DELIBERATELY. Both tables are published and applied
-- last-writer-wins, and replication delivers rows in whatever order they arrive — so a
-- child can land before its parent. With a FK that is a constraint violation inside the
-- apply worker, which then STOPS, and every later change on that node silently stops with
-- it while the publisher still looks healthy. A provider row with no settings row is a
-- provider that cannot bind, which the reader already treats as "not usable"; that is a far
-- cheaper failure than a jammed mesh.
create table if not exists ldap_providers(
  provider_id         text PRIMARY KEY,
  -- Replicas of THIS one directory (ldaps://dc1, ldaps://dc2), separated exactly as the
  -- old config key was, so an operator moving a value across does not have to respell it.
  uris                text NOT NULL DEFAULT '',
  base_dns            text NOT NULL DEFAULT '',
  bind_dn             text NOT NULL DEFAULT '',      -- this directory's own service account
  -- ⚠️ A SECRET, IN THE DATABASE ON PURPOSE. It is not a private key, so it does not
  -- belong in the HSM, and a file is the last resort rather than the default. The console
  -- must treat it as WRITE-ONLY: never return it in any JSON, or the Users page hands a
  -- directory service-account password to anyone who can read one screen.
  bind_pw             text NOT NULL DEFAULT '',
  group_filter        text NOT NULL DEFAULT '',
  group_attr          text NOT NULL DEFAULT '',
  ca_cert_file        text NOT NULL DEFAULT '',
  network_timeout_sec integer NOT NULL DEFAULT 3,
  -- This directory's own Kerberos keytab, uploaded through the console. One deployment-wide
  -- MS_KERBEROS_KEYTAB could hold the service key for exactly ONE domain, so a second
  -- directory's clients failed SPNEGO against a realm whose key the acceptor did not have.
  -- The realm and the KDCs are NOT stored beside it: the realm is upper(dns_root) and the
  -- KDCs are this row's own `uris`, so storing either again would be a second source that
  -- can disagree with the first.
  krb_keytab          text NOT NULL DEFAULT '',
  template_base       text NOT NULL DEFAULT '',
  -- The other two names this directory answers to. A Windows domain has a NetBIOS short
  -- name (`CORP`) and a DNS root (`corp.contoso.com`), and there is no string conversion
  -- between them — AD itself keeps a `crossRef` object mapping one to the other. The
  -- Kerberos realm is `upper(dns_root)` and is DERIVED rather than stored, because a
  -- stored copy is a second source that can disagree with the first.
  netbios_name        text NOT NULL DEFAULT '',
  dns_root            text NOT NULL DEFAULT '',
  -- ⚠️ DECLARED HERE, NOT LEFT TO THE TRIGGER GENERATOR. fastpki-mesh --triggers does
  -- `ALTER TABLE ... ADD COLUMN IF NOT EXISTS updated` for every last-writer-wins table,
  -- and for the BASELINE tables that is harmless: the generator runs at first mesh setup,
  -- before any row exists. A table created by a schema STEP appears after that, and each
  -- node runs the generator at a different moment during a rolling update — so the first
  -- node rolled starts PUBLISHING a row carrying `updated` while its peers' copy of the
  -- table still lacks the column. Measured on the lab: the apply worker died with
  -- "target relation is missing replicated column: updated", the subscription sat at 'd'
  -- (copy in progress) forever, and every health check stayed green.
  updated             bigint NOT NULL DEFAULT 0);
-- SAML and OIDC settings, one table per kind beside ldap_providers. Same rules as that
-- one: no foreign key to auth_providers (replication delivers rows in arbitrary order and
-- a child arriving first would stop the apply worker), and `updated` declared here rather
-- than left to the trigger generator.
create table if not exists saml_providers(
  provider_id     text PRIMARY KEY,
  idp_entity_id   text NOT NULL DEFAULT '',
  idp_sso_url     text NOT NULL DEFAULT '',
  idp_cert        text NOT NULL DEFAULT '',
  sp_entity_id    text NOT NULL DEFAULT '',
  -- No ACS URL column: each node uses its OWN console address (self_console_url), because a
  -- value in this replicated table would send every node's users to one node.
  username_attr   text NOT NULL DEFAULT '',
  groups_attr     text NOT NULL DEFAULT '',
  admin_group     text NOT NULL DEFAULT '',
  auditor_group   text NOT NULL DEFAULT '',
  require_local_user boolean NOT NULL DEFAULT false,
  clock_skew_sec  integer NOT NULL DEFAULT 120,
  updated         bigint NOT NULL DEFAULT 0);
create table if not exists oidc_providers(
  provider_id        text PRIMARY KEY,
  issuer             text NOT NULL DEFAULT '',
  client_id          text NOT NULL DEFAULT '',
  -- ⚠️ A SECRET. Write-only in the console, exactly like the directory bind password.
  client_secret      text NOT NULL DEFAULT '',
  -- No redirect URI column, for the reason given on saml_providers.
  scopes             text NOT NULL DEFAULT '',
  username_claim     text NOT NULL DEFAULT '',
  groups_claim       text NOT NULL DEFAULT '',
  admin_group        text NOT NULL DEFAULT '',
  auditor_group      text NOT NULL DEFAULT '',
  ca_cert            text NOT NULL DEFAULT '',
  require_local_user boolean NOT NULL DEFAULT false,
  updated            bigint NOT NULL DEFAULT 0);
create table if not exists roles(
  name        text PRIMARY KEY,
  description text NOT NULL DEFAULT '',
  -- A role that is part of the product: it may be edited but never deleted. Separately,
  -- the console refuses any change that would leave no role granting role:manage — a
  -- delete or a grant edit — which would leave the deployment unadministrable with no way
  -- back except SQL.
  builtin     boolean NOT NULL DEFAULT false,
  -- The per-REQUESTER issuance cap — how many active certificates a subject holding
  -- this role may hold. NULL (or 0) = this role sets no limit, which is what every role
  -- ships with. Read by pki::role_cert_cap(); the largest number wins where a subject
  -- holds several roles. A cap is a quantity, not a verb, so it belongs on the role rather
  -- than in the permission list.
  --
  -- ⚠️ Caps a HOLDER, not a name — and since MAX_CERTS_PER_CN was deleted it is the ONLY
  -- issuance quota. The old key capped a NAME ("at most N live certificates for
  -- this hostname") and stays a config key. This one caps a HOLDER, and it is here
  -- rather than on a profile because profiles live in the `config` blob, which is
  -- deliberately excluded from the publication — a profile-borne cap would differ per DC.
  max_certs   integer,
  -- The other two issuance limits, in the same shape as max_certs
  -- because a cap is a quantity and role_permissions.scope holds a NAME.
  --
  -- max_cn:  how many ACTIVE certificates may exist for the NAME this request asks for.
  --          This is the old MAX_CERTS_PER_CN — deleted for being a global, and
  --          for being read by `fastpki-est` alone. Back per-role, enforced everywhere.
  -- max_san: how many SubjectAltName entries ONE certificate may carry. Replaces the
  --          MAX_SAN config key (which defaulted to 50 whether anyone wanted it or not).
  --
  -- NULL/0 = this role sets no limit, on all three. Largest wins across several roles.
  max_cn      integer,
  max_san     integer,
  -- The last-writer-wins timestamp, declared here rather than left for
  -- `fastpki-mesh --triggers` to add: a replicated table has to carry it from the moment it
  -- exists, or a node that rolls first publishes a column its peers' copy has not got and
  -- the subscription stalls with "target relation is missing replicated column: updated".
  updated     bigint NOT NULL DEFAULT 0);

create table if not exists role_permissions(
  role       text NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
  permission text NOT NULL,
  -- What this permission is confined to, and WHICH KIND OF NAME that is depends on
  -- the VERB — pki::scope_kind(). enrol:*/ca:*/cert:* scope to a CA id; profile:ro/rw to a
  -- cert-profile name; template:ro/rw to an MS template name. It was called `ca_id` while a
  -- CA was the only thing a permission could be scoped to (step 0017 renamed it).
  --
  -- '*' = every name in that namespace. NOT a NULL, for two reasons. The practical one:
  -- this column is part of the key, and Postgres makes key columns NOT NULL, so NULL could
  -- not have been stored here at all — the first version of this table silently rejected
  -- every builtin grant. The better one: "no row" is denied and "everything" is allowed
  -- everywhere, and those two must not look alike, or someone eventually deletes the wrong
  -- one and widens access. A literal '*' is visible in a SELECT; a NULL reads like missing
  -- data. '*' cannot collide with a real name: a CA id is [A-Za-z0-9_.-]+ (the route
  -- regex) and profile/template names are validated the same way.
  scope      text NOT NULL DEFAULT '*',
  updated    bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (role, permission, scope));
create index if not exists role_permissions_role_idx on role_permissions(role);

-- The builtins, reproducing exactly what path_allowed() grants today. This is the schema
-- defining the product's roles, not a compat seed (§3f) — remove the rows and the console
-- has no roles at all, which is a different thing from having them hardcoded elsewhere.
insert into roles(name, description, builtin) values
  ('admin',           'Full access, including backup, updates and role management', true),
  ('auditor',         'Read the audit log and the dashboard summary',               true),
  ('requester',       'Self-service: request and manage your own certificates',     true),
  ('none',            'Onboarded but not yet granted access',                       true)
  on conflict (name) do nothing;

-- ca_id '*' throughout: a builtin is deployment-wide. A scoped admin is the same rows
-- with a real CA id in place of the star, written by the role editor in step 3.
insert into role_permissions(role, permission, scope) values
  ('admin','cert:read','*'),   ('admin','cert:request','*'),
  ('admin','cert:revoke','*'), ('admin','ca:read','*'),
  -- profile:manage and template:manage were the same permission as profile:rw and
  -- template:rw, which made ':manage' a redundant spelling of a permission that
  -- already existed, so they are gone.
  --
  -- ⚠️ template:rw|* is NOT optional here. `admin` held its template access ONLY through
  -- template:manage, so deleting that verb without this row leaves admin with no
  -- template permission at all and the Templates page unreachable for everyone.
  -- profile:rw needs no equivalent row: admin already holds profile:rw|admin, and
  -- the path gate matches on the VERB only (permissions_for_roles SELECTs DISTINCT
  -- permission), so that row already opens /api/profiles. Adding profile:rw|* instead
  -- would also widen admin's PROFILE UNION from {admin} to every profile, which is a
  -- different change than the one this ticket asks for.
  ('admin','ca:manage','*'),       ('admin','user:manage','*'),
  -- Templates are permissioned resources. The agreed design gives
  -- `requester` template:ro on the three built-ins and `admin` template:rw.
  --
  -- ⚠️ admin stays on `*` rather than the three NAMED scopes his sentence lists, and this
  -- is a deliberate departure: a template arrives by CSV import from AD, so an admin
  -- confined to GenericUser/Email/GenericComputer could not write a single imported row —
  -- the import refuses per-name. `*` is what admin means; the three named scopes are the
  -- illustration of the model, and `requester` below is where they belong.
  ('admin','template:use','*'), ('admin','template:edit','*'),
  ('requester','template:use','GenericUser'),
  ('requester','template:use','Email'),
  ('requester','template:use','GenericComputer'),
  ('admin','role:manage','*'),     ('admin','audit:read','*'),
  ('admin','backup:manage','*'),   ('admin','config:manage','*'),
  ('admin','est:enrol','*'),       ('admin','acme:enrol','*'),
  ('admin','cmp:enrol','*'),
  ('admin','ms:enrol','*'),
  -- Back after step 0009 removed it. SCEP has an identity now — a per-user
  -- challengePassword — so the permission is enforceable rather than decorative. It
  -- gates ONLY that path; a shared secret, a dynamic token or a renewal still has no
  -- user and stays ungated, which was the ruling and is still right.
  ('admin','scep:enrol','*'),
  -- A profile is a RESOURCE a role holds a permission on. `admin` may USE
  -- and MODIFY the permissive profile; `requester` may only USE the restricted one.
  --
  -- ⚠️ SCOPED, not '*'. A `*` grant means every profile that exists, which for `admin`
  -- would make the union ambiguous the moment a second profile is created — the case
  -- resolve_profile refuses. One named profile each is the agreed design.
  --
  -- ⚠️ AND these two rows are required — "admin user has the standard profile
  -- associated with it by default — I was surprised by that" — so they are a REQUIREMENT,
  -- not a convenience. Removing them was tried and reverted: it silently regressed that
  -- back to admin-gets-the-permissive-profile.
  --
  -- Slice 3 renamed the PROFILES to match the roles that hold them (`master` ->
  -- `admin`, `standard` -> `requester`), which is why each row now repeats its own name.
  --
  -- The consequence to know: a builtin role already puts one profile in its holders'
  -- union, so ADDING a second grant to such a user makes an unnamed request ambiguous.
  -- "This user uses THIS profile INSTEAD" is expressed by a role that carries the same
  -- console access WITHOUT the builtin's profile grant — see `restricted-admin` in
  -- ⚠️ TWO GRANTS, BECAUSE USE AND MANAGEMENT ARE DIFFERENT QUESTIONS.
  --
  -- profile:rw|admin is what admin ISSUES under, and it stays narrow deliberately:
  -- profiles_for_identity() counts profile:ro and profile:rw alike, so a wildcard here
  -- would let admin issue under EVERY profile — which tests/profile_choice.sh pins as
  -- forbidden ("naming an unassigned profile does not issue"). The note that used to sit
  -- here, warning that a star "would widen admin's PROFILE UNION from {admin} to every
  -- profile", was right, and measuring it proved so.
  --
  -- /api/profiles now enforces the grant's scope on write and delete — it previously
  -- ignored it, so profile:rw|tenant-a could rewrite the built-in tls-server to
  -- allow_ca=true for every tenant. With the scope enforced and profile:rw|admin alone,
  -- the built-in admin could no longer create a profile or edit a built-in, which is
  -- ordinary administration rather than a privilege. profile:manage|* authorises that
  -- WRITE and is not counted at issuance, which is exactly the split that was missing.
  ('admin','profile:use','admin'), ('admin','profile:edit','admin'),
  ('admin','profile:edit','*'),
  -- Minting a key INSIDE the token is its own capability, not a flavour of
  -- cert:request. The gate matches by prefix, so /api/certs/request-hsm used to inherit
  -- the self-service request permission — a `requester` could create a hardware-resident
  -- object nobody can enumerate from the console.
  ('admin','hsm:manage','*'),      ('admin','hsm:read','*'),
  ('auditor','audit:read','*'),
  -- Read what the token holds, and mint nothing — the worked example for this role.
  ('auditor','hsm:read','*'),
  -- Today a requester reaches the inventory (owner-scoped by the handlers), the
  -- read-only CA list behind the issue form's dropdown, and their own enrolment
  -- credentials. And every protocol — which is the thing we need to be able to
  -- narrow, so it starts as five separate rows rather than one "all".
  ('requester','cert:read','own'),   ('requester','cert:request','*'),
  ('requester','cert:revoke','own'), ('requester','ca:read','*'),
  ('requester','est:enrol','*'),       ('requester','acme:enrol','*'),
  ('requester','cmp:enrol','*'),
  ('requester','ms:enrol','*'),
  ('requester','scep:enrol','*'),   -- see the admin row above
  ('requester','profile:use','requester'),  -- see the admin row above
  -- self:manage — read your own session and change your own password. Not a floor: the
  -- floor is /api/me and /api/logout, which need no capability. `none` is omitted on
  -- purpose (an SSO user awaiting a role has no local password), and that omission is
  -- behaviour the table-driven gate must preserve.
  ('admin','*:*','*'),     ('admin','self:manage','*'),
  ('auditor','self:manage','*'),
  ('requester','self:manage','*')
  on conflict do nothing;
-- 'none' gets no rows on purpose: it may read its own session and log out, which is not a
-- permission but the floor every authenticated subject stands on.

-- A CRL this deployment did not sign — an offline root's, signed elsewhere and
-- imported here so the online nodes can publish it. Only the CURRENT one per (ca_id,
-- is_delta) is servable, so a write REPLACES. `updated` is the LWW stamp, and kMgmtTables
-- must name BOTH key columns because the primary key is composite.
--
-- Rows come from two places: `fastpki-ca import-crl` for an offline root this deployment
-- cannot sign for (imported_by = 'fastpki-ca'), and the CRL publication sweep, which stores
-- the CRL of every CA a node DOES hold the key for so peers can serve that CA's revocation
-- while the node is down (imported_by = 'generated[:<data center>]').
create table if not exists crls(
  ca_id        text NOT NULL,
  is_delta     boolean NOT NULL DEFAULT false,
  crl          bytea NOT NULL,
  crl_number   bigint,
  this_update  bigint NOT NULL,
  next_update  bigint,
  imported_by  text,
  updated      bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (ca_id, is_delta));

insert into schema_version(version, name, applied)
  values (3, 'baseline', 0) on conflict (version) do nothing;
