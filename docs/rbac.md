# Roles and permissions

Who may do what, and where. This describes what the code does today.

**Authentication** answers *who is this?* — `authentication.md` covers it. This page starts
after that question is answered, with a subject in hand.

## Contents

1. [The model in one page](#1-the-model-in-one-page)
2. [A permission is `resource:verb`, plus a scope](#2-a-permission-is-resourceverb-plus-a-scope)
3. [The vocabulary](#3-the-vocabulary)
4. [Scope](#4-scope)
5. [`use` and `edit` are different axes](#5-use-and-edit-are-different-axes)
6. [Granting a role is bounded by what the grantor holds](#6-granting-a-role-is-bounded-by-what-the-grantor-holds)
7. [The shipped roles](#7-the-shipped-roles)
8. [Recipes](#8-recipes)
9. [Rules for changing roles](#9-rules-for-changing-roles)

---

## 1. The model in one page

Three tables, and nothing else decides authorization:

| table | holds |
|---|---|
| `roles` | the role names, plus the per-role issuance limits `max_certs`, `max_cn`, `max_san` |
| `role_permissions` | `(role, permission, scope)` — one row per grant |
| `subject_roles` | `(selector_type, selector_value, role)` — extra roles bound to a user or a group |

A subject's **effective roles are the union** of the role on its `web_users` row and every
role bound to it through `subject_roles`. Selectors are `user` and `group`; a directory user
picks up group grants through the groups the directory reports. Nothing is inherited between
roles — a role holds exactly the grants written against its name.

The gates **fail closed**. A subject with no role, or a role that matches no row in `roles`,
is refused; a database that cannot be read is refused. There is no default that grants.

---

## 2. A permission is `resource:verb`, plus a scope

`role_permissions` holds one grant per row: a **resource**, a **verb**, and a **scope**.

```
resource : verb        scope
cert     : read        own | * | <ca-id>
ca       : manage      <ca-id> | *
est      : enrol       <ca-id> | *
profile  : use         <profile-name> | *
*        : *           *
```

The resource is also the **scope namespace** — it says what the scope value means, so a scope
can never be read as the wrong kind of name. `*:*` is the wildcard in every position and is
honoured by both gates:

* **The console** — `required_caps(path, method)` maps a route to a set of permissions and the
  caller passes by holding any one of them, or by holding `*:*`. A route nobody mapped falls
  to the default, `*:*`, so an unmapped route is admin-only rather than open.
* **Enrolment** — `may_enrol()` and `subject_holds()` read the same rows, and `*:*` satisfies
  any verb there too.

The handlers that check a permission again past the gate — `/api/users` deciding whether a
caller manages every account, the profile and template editors deciding which names a caller
may write — accept `*:*` too, but only at scope `*`: a `*:*` scoped to a CA names a CA, not a
profile or a template.

Every console page's routes are mapped to the permission its tab is shown for, and the console
decides its tabs and buttons from the same permissions (never from a role's name). Four actions
are gated at `*:*`: starting a discovery scan (the server connects to the addresses given),
issuing the PostgreSQL certificate (it issues from a CA and writes a private key to disk), and
registering or removing a foreign CA (cross-signing a registered one is `ca:manage`).

⚠️ **A stronger verb answers for a weaker one, but only within one resource, and only at a
gate.** Two resources order their verbs:

| resource | ordering |
|---|---|
| `ca` | `manage` > `read` |
| `hsm` | `manage` > `read` |

So a role granted only `ca:manage` can read the CA list and a CA certificate. Nothing else
orders: `cert`'s read/request/revoke are three separate acts, the five protocols are peers,
and `profile`/`template` are **not ordered at all** (§5).

**The ordering stops at the gate.** Granting a role to somebody else is a literal match:
holding `ca:manage` does not let you hand out `ca:read`. `*:*` remains a wildcard
everywhere, in a gate and in an assignment alike.

## 3. The vocabulary

Verbs are **per resource** — what you may do to a CA is not the same set as what you may do to
a profile. The console's role editor offers every `resource:verb` in one list, and the scope
list beside it follows the resource chosen.

| resource | verbs | scope value |
|---|---|---|
| `cert` | `read`, `request`, `revoke` | `own`, `*`, or a CA id |
| `ca` | `read`, `manage` | a CA id or `*` |
| `est` `acme` `cmp` `ms` `scep` | `enrol` | a CA id or `*` |
| `profile` | `use`, `edit` | a profile name or `*` |
| `template` | `use`, `edit` | a template name or `*` |
| `hsm` | `read`, `manage` | — |
| `user` `role` `config` `backup` `audit` | `manage` (`read` for audit) | — |
| `self` | `manage` | — |
| `*` | `*` | `*` |

What each confers:

* **`cert:read` / `cert:revoke`** — read or revoke certificates, including the compliance
  report and the dashboard's key-algorithm counts. Scope `own` restricts to the caller's own;
  `*` or a CA id does not.
* **`cert:request`** — request a certificate, and read the profiles you may issue under.
* **`ca:read`** — list CAs and read a CA certificate as PEM or text.
  **`ca:manage`** — create, renew, cross-sign, enable/disable, delete; edit the XCEP block;
  read the foreign-CA registry and the discovery inventory.
* **`<protocol>:enrol`** — enrol over that protocol against the CAs in scope. Five peers, no
  hierarchy: `est:enrol` says nothing about `acme:enrol`.
* **`profile:use` / `template:use`** — **issue under** that profile or template.
  **`profile:edit` / `template:edit`** — modify it, which is *not* issuance (§5).
* **`hsm:read`** — list token objects. **`hsm:manage`** — create and adopt keys in the token.
* **`user:manage`** — list, create, edit and delete accounts; bind roles to subjects; look up
  directory users and groups, and refresh a group's members.
* **`role:manage`** — create and edit roles and their grants.
* **`audit:read`** — the audit log, its signed export, the dashboard counters.
* **`config:manage`** — the config table, allowed domains, directories, the MS keytab, the
  client-config editor, the Endpoints page (switching protocols off and on, restarting them),
  the notifications preview, the expiry email template and test email, and the update check.
* **`backup:manage`** — configuration backup and restore, and a full database dump.
* **`self:manage`** — change your **own** password and email address, and read your own
  enrolment credentials.

## 4. Scope

`pki::scope_kind(permission)` derives the namespace from the **resource**:

| kind | resources | a scope value is |
|---|---|---|
| Ca | `ca`, `cert`, the five protocols, `*` | a CA id |
| Profile | `profile` | a certificate-profile name |
| Template | `template` | an MS template name |
| None | `self`, `user`, `role`, `audit`, `config`, `backup`, `hsm` | nothing — these have no instances |

Two scope values are **reserved** and name no instance: `*` is every member of the namespace,
and `own` restricts a `cert` verb to objects the caller owns. `pki::in_scope(grant, wanted)`
is the whole matching rule: a grant matches when its scope is `*` or equal to what is asked.

### 4.1 CA confinement composes

A role's CA confinement is the union of the scopes on its **Ca-namespace** grants. A resource
with no instances never contributes, so granting `self:manage` cannot widen anybody's reach
over CAs — the resource says its scope is not a CA id, and the scan skips it.

A role that holds **no** CA-namespace grant at all expresses no opinion about CAs and is
therefore not confined by one. That is not the same as being confined to none: a caller with
no roles at all is denied every object, and that case is decided before this one.

Ownership and CA confinement compose rather than being one value. `cert:read|own` says
"only my own"; the CAs those may be read from come from the role's CA-namespace grants. So
"my own certificates, within `issuing-ca`" is a role holding `cert:read|own` alongside its
`issuing-ca` grants — and "everyone's certificates in `issuing-ca`" is `cert:read|issuing-ca`.

## 5. `use` and `edit` are different axes

These are not "read" and "write". The difference is **issuance**:

| verb | may issue under it | may modify it |
|---|---|---|
| `profile:use` | yes | no |
| `profile:edit` | **no** | yes |

`profiles_for_identity()` counts `profile:use` as issuance entitlement and ignores
`profile:edit`. So an administrator may edit every profile without being entitled to issue
under every one: the builtin `admin` holds `profile:use` on **one** profile and
`profile:edit` on all of them.

`template:use` / `template:edit` follow the same split for MS templates: `use` is answered at
issuance, `edit` gates the management page.

## 6. Granting a role is bounded by what the grantor holds

`user:manage` is not a route to `admin`. Two rules keep it that way:

1. **A caller may only assign a role whose grants it already holds** — on both ways of
   handing somebody a role, `POST /api/users` and `POST /api/subject-roles`. Both halves of a
   grant bind, so a CA-scoped admin (`*:*|issuing-ca`) can hand out `*:*|issuing-ca` and not `*:*|*`.
2. **Nobody changes their own primary role**, administrators included — on `POST /api/users`.
   Ask another administrator.

`*:*` counts as a wildcard over verbs for the first test, so an administrator can assign
`requester` even though `requester`'s `profile:use|requester` is not among admin's own
grants. The scope half still binds.

⚠️ **The bound covers granting, not removing, and not the role editor.** Removing a role from
a subject or deleting an account checks no bound. The routes that create roles and set their
grants need only `role:manage`, so a holder of `role:manage` can add `*:*` to a role it holds.
Treat `role:manage` as an administrator's permission.

The open-mode bootstrap is exempt: with no users and no token there is no session and
therefore no grants to test against, so the request that creates the first administrator
passes.

---

## 7. The shipped roles

| role | for |
|---|---|
| `admin` | everything: `*:*` plus every explicit verb at `*`, except `profile:use`, which is scoped to the `admin` profile (§5) |
| `auditor` | `audit:read`, `hsm:read`, `self:manage` — reads the trail, issues nothing |
| `requester` | self-service: `cert:read\|own`, `cert:revoke\|own`, `cert:request`, `ca:read`, all five `<protocol>:enrol`, `profile:use` on the requester profile, `template:use` on the three built-ins, `self:manage` |
| `none` | the role an onboarded external identity holds until an administrator grants it something. No grants — not even `self:manage`. It can be an account's primary role but cannot be bound as an extra role |

---

## 8. Recipes

**A helpdesk that manages accounts but is not an administrator.** Grant `user:manage|*` and
`self:manage|*`. Section 6 stops it creating an `admin`: it may only hand out roles whose
grants it already holds.

**An administrator confined to one CA.** Copy the `admin` grant list and set the scope of its
**CA-namespace** rows — `*:*` itself, `ca:*`, `cert:*` and the protocol verbs — to that CA id.
A single `*:*|*` left behind makes the role unconfined, because `*:*` is a CA-namespace grant
too. Leave out `role:manage`, which would let the holder give its own role `*:*|*` again (§6).
The rows for resources with no instances (`self`, `user`, `audit`, `config`, `backup`, `hsm`)
can stay as they are: their scope is not a CA id and never widens CA reach.

**A read-only auditor.** The builtin `auditor`. Note `audit:read` is estate-wide: the audit
log is not partitioned per CA, so a CA-scoped caller is refused the log outright rather than
served a filtered view.

**Letting a directory group enrol.** Bind a role to a `group` selector whose value is the
group name the directory reports, and give that role `<protocol>:enrol` — `ms:enrol` for
Windows autoenrolment — scoped to the CA id in the enrolment URL. A machine account picks this up through its
primary group.

---

## 9. Rules for changing roles

These hold whichever door a change comes through; the console's Roles page is described in
[`admin-guide.md`](admin-guide.md) §6.11.

* **A refusal names what is missing:**
  `forbidden: roles [requester] lack audit:read for /api/audit`.
* **Built-in roles can be edited but not deleted.** Their names are used elsewhere, so
  `DELETE` on `admin`, `auditor`, `requester` or `none` is refused.
* **The console cannot lose its last administrator of roles.** A change that would leave no
  role granting `role:manage` — deleting it, or saving its grants without it — is refused
  with `this is the last role granting role:manage`.
* **Deleting a role removes its grants and every `subject_roles` binding to it.** An account
  whose *primary* role it was keeps that name on its `web_users` row, matches no role, and is
  refused everything until it is given another.
* **Saving grants replaces the whole list.** A grant scoped to a profile or a template must
  name one that exists, so a role still naming a deleted profile cannot be saved until that
  grant is taken out of the list. CA scopes are not checked.
* **The issuance limits** on a role are `max_certs` (valid certificates one subject may hold),
  `max_cn` (valid certificates for the one name a request asks for) and `max_san`
  (alternative names in one certificate). Empty or `0` means the role sets no limit. A subject
  holding several roles gets the **largest** number any of them sets; a role that sets none
  does not lift another role's limit.
