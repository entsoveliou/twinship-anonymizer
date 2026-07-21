# Twinship Anonymizer

## Table of Contents

- [Configuration](#configuration)
- [ABAC — Attribute-Based Access Control](#abac--attribute-based-access-control)
- [ABE — Attribute-Based Encryption](#abe--attribute-based-encryption)
- [Anonymizer](#anonymizer)

---

## Configuration

All deployment/partner-facing configuration lives in one place: **`.env`**, based on the **`.env.example`** template in the repo root.

```bash
cp .env.example .env
# edit .env: MinIO endpoint/creds, your Keycloak realm's RS256 public key, bucket names, etc.
docker-compose up --build
```

`docker-compose.yml` loads `.env` into the `app` container via `env_file` — nothing partner-specific is hardcoded in the compose file itself, so integrating just means filling in `.env`.

What's in it, by category:

| Category | Variables | Notes |
|----------|-----------|-------|
| MinIO | `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`, `SOURCE_BUCKET`, `DESTINATION_BUCKET`, `POLL_INTERVAL` | Where raw files are dropped and encrypted output is served from. If the partner has already provisioned these buckets, the app detects that and skips creation; otherwise it creates them automatically on first use. |
| Orphan cleanup | `POLICY_GRACE_SECONDS` | How long a file may sit in the source bucket with no matching policy before it's deleted |
| Auth | `JWT_PUBLIC_KEY` | Your Keycloak realm's RS256 public key (PEM). Leave blank to accept only locally-minted dev tokens (`/api/v1/dev/token`). PEM values need literal `\n` in place of real newlines (`.env.example` shows the format); `settings.py` unescapes this automatically. |

Two things deliberately **not** in `.env`:
- **MongoDB.** It's purely internal state (policies, role key material, wrapped dataset keys) — no partner system ever talks to it. Its credentials are fixed in `docker-compose.yml`/`mongo/Dockerfile` instead of exposed here.
- **`JWT_PRIVATE_KEY`.** This is this app's own local dev-token-signing key (`dev_keys/private.pem`, pre-generated and checked into the repo) — not partner config, so there's nothing to fill in for it. It has no bearing on production use: setting `JWT_PUBLIC_KEY` to a real Keycloak key doesn't require touching this at all, and dev-minted tokens keep verifying alongside real ones either way (see [Dual-key verification](#development-token-issuance-apiv1devtoken)).
- **Encryption key material.** There's no master key to configure — per-role keys are generated automatically the first time each role is used (see [ABE](#abe--attribute-based-encryption)).

---

## ABAC — Attribute-Based Access Control

Access control is enforced at the **dataset level**: every file in the encrypted bucket is associated with a policy that lists which roles may access it. Policies are stored in MongoDB and managed via REST API.

### Policy Structure

```json
{
  "dataset_name": "dataset1.pdf",
  "owner": "0f724f96-324d-4da7-8c4f-a3c19f0267f0",
  "created_at": "2026-07-13T00:00:00Z",
  "policy": {
    "roles": ["data-gr", "model-st"]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dataset_name` | string | Identifier — must match the object name in the encrypted bucket exactly |
| `owner` | string | Server-set to the creating caller's user id (JWT `sub`) — not caller-supplied, immutable across updates |
| `created_at` | datetime | Set automatically on creation, preserved across updates |
| `policy.roles` | list of strings | Which Keycloak realm roles are granted access — any one of them qualifies (any-of match) |

Roles are flat, resource-shaped Keycloak realm role names (e.g. `data-gr`, `model-st`, `apps`) — no organizations, no access tiers. The consortium also defines coarser "User-Role Type" names (e.g. `UserGR`, `UserSU`) as Keycloak **composite roles**: assigning one to a user auto-expands into the underlying resource roles in their token. Policies only ever reference the granular resource roles, never the composite type names — so adding or changing a user-type later never requires touching existing policies, only Keycloak's composite-role config.

### Policy Lookup — No Fallback

Every dataset must have its own exact-match policy, keyed on `dataset_name`. There is **no prefix matching and no default policy** — a dataset with no policy is a hard error (`404`). **Create the policy before dropping the file into the source bucket**; a file that arrives with no matching policy is skipped by the encryption monitor, not silently processed under a fallback.

### Access Check

Access is granted per-role: the caller's JWT carries a list of realm roles (`realm_access.roles`); the policy carries a list of roles that qualify for this dataset. The caller is granted access if **at least one of their roles appears in the policy's role list** — holding a role either qualifies you or it doesn't, there's no ranking or hierarchy between roles.

- Caller holds none of the policy's roles → denied, `403`.
- Dataset has no policy at all → `404`.
- Caller holds any one qualifying role → granted; that matched role is also what drives which wrapped key gets used to decrypt (see [ABE](#abe--attribute-based-encryption)).

This check is identical for every endpoint that enforces ABAC — `getEncryptedFile` requires exactly the same thing as `getUnencryptedFile` (it's a diagnostic view of the ciphertext, not a separate lower-bar grant), and `listFiles`/`listFilesByBucket` filter results with the same rule.

### MongoDB Collections

| Collection | Key field | Used for |
|------------|-----------|----------|
| `policies` | `dataset_name` | Dataset access policies |
| `role_secrets` | `role` | Auto-provisioned root secret per role, used directly as that role's encryption key |
| `dataset_keys` | `dataset_name` | Per-role wrapped data-encryption-keys for each encrypted dataset |
| `access_logs` | — | Audit log of every `getEncryptedFile`/`getUnencryptedFile` request, success or failure |

`role_secrets` and `dataset_keys` are populated automatically — there is no manual key-management step (see [ABE](#abe--attribute-based-encryption)).

### REST API — `/api/v1/policies`

| Method | Path | Description | Auth |
|--------|------|--------------|------|
| GET | `/api/v1/policies/` | List all policies | Valid JWT |
| GET | `/api/v1/policies/{dataset_name}` | Get a single policy | Valid JWT |
| POST | `/api/v1/policies/` | Create a policy | Caller must hold at least one of the roles being granted in the new policy |
| PUT | `/api/v1/policies/{dataset_name}` | Replace a policy entirely | Caller must hold at least one role the *existing* policy already grants |
| PATCH | `/api/v1/policies/{dataset_name}` | Partially update a policy | Caller must hold at least one role the *existing* policy already grants |
| DELETE | `/api/v1/policies/{dataset_name}` | Delete a policy | Caller must hold at least one role the *existing* policy already grants |

There's no dedicated platform-admin concept — any role holder on a dataset can manage its policy, not just whoever originally created it. Tighten this if that's too permissive.

---

## ABE — Attribute-Based Encryption

Files are encrypted with **envelope encryption**, with each role in a policy getting its own independently-wrapped copy of the file's key. Decryption isn't just an API-level check — it requires key material scoped to a specific role.

**How it works:**

1. Each file gets a random 256-bit Data Encryption Key (DEK). File content is encrypted once with it (AES-256-GCM).
2. The DEK is then **wrapped separately for each role** listed in the policy, using that role's own secret directly as the Key Encryption Key (KEK) — no tier hierarchy, each role's secret stands alone.
3. Role secrets are generated automatically the first time a role is encountered (atomic upsert into `role_secrets`) — no setup required.
4. Revoking a role's access to *all* data it was ever granted is done by deleting its `role_secrets` entry — every wrapped key issued under that role becomes permanently unrecoverable, even in the presence of an API-level authorization bug.

Wrapped keys live in the `dataset_keys` collection, one entry per role per dataset.

**Policy changes on an already-encrypted dataset trigger automatic re-encryption.** Updating a dataset's `policy.roles` (via `PUT`/`PATCH /api/v1/policies/{dataset_name}`) — adding a role, removing one — decrypts the file with any existing wrapped key, discards all old wrapped-key entries, and re-encrypts with a **brand-new DEK** wrapped fresh for every role in the updated policy. A fresh DEK on every policy change means old key material can never decrypt the new ciphertext, even in principle — not just "the API denies the request." If this can't complete (e.g. the existing wrapped key fails to decrypt), the policy change still saves, but the request returns `500` and the file is left needing a manual re-drop into the source bucket to resync.

> Existing files encrypted under a previous scheme (the original fixed-key scheme, or the earlier organization/tier model) are not decryptable under this scheme — key derivation is entirely different each time. Affected datasets need to be re-dropped into the source bucket for re-encryption once their policy exists under the current `{roles: [...]}` shape.

### Development Token Issuance (`/api/v1/dev/token`)

To interact with the encrypted files and test the ABE/ABAC flow, users must authenticate using a JWT. For development and testing purposes, a dedicated endpoint mints signed JWTs shaped exactly like a real Keycloak access token — same claim keys (`iss`, `aud`, `azp`, `sid`, `acr`, `allowed-origins`, `realm_access`, `resource_access`, `scope`, `email`, etc.) as a real partner-issued token, so dev tokens are structurally interchangeable with production ones. `realm_access.roles` is the only claim this app's authorization logic actually reads; everything else is cosmetic realism.

**Dual-key verification:** token signatures are checked against each configured public key in turn — the partner Keycloak key (`JWT_PUBLIC_KEY`, if configured) first, then the bundled dev key — so configuring a real Keycloak key does **not** stop locally-minted dev tokens from working. Both can be used side by side at any time.

**Method:** `POST`
**Endpoint:** `/api/v1/dev/token`

#### Query Parameters

| Name | Type | Description | Default Value |
|------|------|-------------|---------------|
| `sub` | string | Subject (User ID) | `dev-user` |
| `preferred_username` | string | Username | `developer` |
| `email` | string | Email claim | `developer@example.com` |
| `roles` | string | Comma-separated realm role names | `data-gr` |
| `realm` | string | Shapes the `iss` claim and default realm roles | `twinship` |
| `expires_in` | integer | Token lifetime in seconds | `3600` |

Example: `roles=data-gr,model-gr,apps` grants those three roles alongside Keycloak's standard boilerplate roles.

#### Example Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

## Anonymizer

The Anonymizer module acts as the core engine of the system. It runs continuous background tasks (cron-like functionalities) to automatically secure newly ingested data and enforce storage lifecycles. It also exposes the main APIs for clients to securely retrieve files based on their cryptographic attributes and access roles.

### Background Tasks (Cron-like Functionalities)

The module runs parallel asynchronous tasks in the background to manage the flow of data:

#### 1. Continuous Encryption Monitor
The anonymizer continuously monitors the designated source MinIO bucket for newly uploaded files.
- **Policy-driven:** the uploaded file's object name is looked up as a `dataset_name` in the `policies` collection. There is no fallback — if no policy exists yet, the file is left in place and retried automatically on every poll.
- **Automated Encryption:** once a policy is found, the system generates a fresh DEK, encrypts the file (AES-256-GCM), wraps the DEK for every role in the policy, and uploads the result to the encrypted destination bucket.
- **Source cleanup:** immediately after a file is successfully encrypted, its raw copy is deleted from the source bucket — the source bucket is a staging area, not storage. This also self-heals across restarts: if the app crashes between "encrypted copy uploaded" and "raw copy deleted," the next startup detects the encrypted copy already exists and finishes the cleanup without re-encrypting.

#### 2. Orphaned-Upload Cleanup
A separate background task deletes files from the source bucket that were **never** successfully encrypted — i.e. nobody ever created a policy for them. This is the only case the tool deletes raw data on its own initiative; anything with a valid policy is claimed and cleaned up by the encryption monitor above, not this task.

Configured via one environment variable:
- `POLICY_GRACE_SECONDS` *(default: `60`)*: how long a file may sit with no matching policy before it's deleted. Applies to every file in the source bucket — no prefix filtering.

> Create the policy before (or within `POLICY_GRACE_SECONDS` of) dropping the file in the source bucket. Once the grace period elapses with still no policy, the raw upload is gone for good.

---

### REST API Endpoints

The Anonymizer exposes the following protected APIs to interact with the encrypted data. All endpoints require a valid Bearer JWT.

| Method | Endpoint | Parameters | Description | ABAC Enforcement |
|--------|----------|------------|-------------|------------------|
| **GET** | `/api/v1/listFiles` | None | Returns a JSON array of file names in the encrypted bucket, filtered to what the caller qualifies for. | Filters via `check_dataset_access` (see [Access Check](#access-check)) — inaccessible files are omitted, not errored. |
| **GET** | `/api/v1/listFilesByBucket` | `?bucket=<string>` | Returns file names in the given bucket, filtered to those the caller's roles can access. | Filters via `check_dataset_access` — inaccessible files are omitted, not errored. |
| **GET** | `/api/v1/getUnencryptedFile` | `?filename=<string>` | Downloads the requested file, unwraps the caller's matched role's key, decrypts it, and returns the clean content. | **Strict.** 404 if no policy exists, 403 if the caller holds none of the policy's roles. Every attempt is written to the [audit log](#audit-log). |
| **GET** | `/api/v1/getEncryptedFile` | `?filename=<string>` | Downloads the requested file and returns it **AS IS** (still cryptographically scrambled). | **Strict.** Identical check to `getUnencryptedFile` — no lower bar; no crypto operations performed. Every attempt is written to the [audit log](#audit-log). |

---

### Audit Log

Every `getEncryptedFile` and `getUnencryptedFile` request — successful or not — is recorded in the `access_logs` collection: who (`user_id`, `username`, `roles`, from the JWT), what (`dataset_name`, `operation`), and the outcome (`status`: `"success"`/`"failure"`, plus a `reason` for failures — ABAC denial, no policy, decryption failure, not found, etc.). Other endpoints (listing, policy management) are not logged.

#### `GET /api/v1/audit-logs`

| Query param | Description |
|-------------|--------------|
| `user_id` | Filter to one user's requests (JWT `sub`) |
| `role` | Filter to requests from callers holding this role |
| `dataset_name` | Filter to requests for one dataset |
| `status` | `"success"` or `"failure"` |
| `limit` / `skip` | Pagination (default `limit=100`) |

No filters returns every request from everyone. **Currently requires only a valid JWT — no admin restriction yet.** Anyone with a token can query anyone else's access history; this is a deliberate temporary state, expected to be locked down later.

---

### API Documentation (Swagger UI)

The Anonymizer is built with FastAPI, providing interactive, auto-generated documentation.

For complete details on request parameters, expected responses, error codes, and to test the API endpoints interactively, please visit the Swagger UI at:
👉 **`http://<YOUR_SERVER_IP>:8000/docs#`**
