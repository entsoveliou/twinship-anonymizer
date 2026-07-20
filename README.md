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
| MinIO | `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`, `SOURCE_BUCKET`, `DESTINATION_BUCKET`, `POLL_INTERVAL` | Where raw files are dropped and encrypted output is served from |
| Orphan cleanup | `POLICY_GRACE_SECONDS` | How long a file may sit in the source bucket with no matching policy before it's deleted |
| Auth | `JWT_PUBLIC_KEY`, `JWT_PRIVATE_KEY` | `JWT_PUBLIC_KEY` is your Keycloak realm's RS256 public key (PEM). Leave both blank to use the bundled dev key + `/api/v1/dev/token` for local testing — **never set `JWT_PRIVATE_KEY` anywhere reachable by anyone but you.** PEM values need literal `\n` in place of real newlines (`.env.example` shows the format); `settings.py` unescapes this automatically. |

Two things deliberately **not** in `.env`:
- **MongoDB.** It's purely internal state (policies, org key material, wrapped dataset keys) — no partner system ever talks to it. Its credentials are fixed in `docker-compose.yml`/`mongo/Dockerfile` instead of exposed here.
- **Encryption key material.** There's no master key to configure — per-organization keys are generated automatically the first time each organization is used (see [ABE](#abe--attribute-based-encryption)).

---

## ABAC — Attribute-Based Access Control

Access control is enforced at the **dataset level**: every file in the encrypted bucket is associated with a policy that lists which organizations may access it and at what tier. Policies are stored in MongoDB and managed via REST API.

### Policy Structure

```json
{
  "dataset_name": "dataset1.pdf",
  "owner": "ICCS",
  "created_at": "2026-07-13T00:00:00Z",
  "policy": {
    "roles": [
      { "organizationId": "ICCS", "access": "admin" },
      { "organizationId": "UBI", "access": "c-ro" }
    ]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dataset_name` | string | Identifier — must match the object name in the encrypted bucket exactly |
| `owner` | string | Organization/user id that owns the dataset |
| `created_at` | datetime | Set automatically on creation, preserved across updates |
| `policy.roles` | list of `{organizationId, access}` | Which organizations are granted access, and at what tier |

`organizationId` is a short org code (e.g. `UBI`, `WAR`, `GRM`, `ICCS`). `access` is one of `admin`, `rw`, `ro`, `c-ro` (highest to lowest tier). The tier drives which key an organization gets when a file is encrypted (see [ABE](#abe--attribute-based-encryption)) **and** which endpoints a caller can use — see Access Check below.

### Policy Lookup — No Fallback

Every dataset must have its own exact-match policy, keyed on `dataset_name`. There is **no prefix matching and no default policy** — a dataset with no policy is a hard error (`404`). **Create the policy before dropping the file into the source bucket**; a file that arrives with no matching policy is skipped by the encryption monitor, not silently processed under a fallback.

### Access Check

Access is granted per-organization, tier-aware: the caller's JWT carries a per-org `access` claim (their own clearance within that org); the policy carries a per-org `access` grant (what tier that org is entitled to on this dataset). The caller qualifies for an org only if **their own claimed tier meets or exceeds what the policy granted that org** — `admin ≥ rw ≥ ro ≥ c-ro`. There's no separate hardcoded minimum anywhere; the required tier for a dataset is always exactly what its policy records.

- Claimed tier below the org's grant → denied, even though the org itself qualifies (a `c-ro`-clearance user can't exercise their org's `admin` grant).
- Claimed tier above the org's grant → allowed, but capped at the org's actual grant for key-derivation purposes.
- Org not listed in the policy at all → denied, regardless of tier.

This check is identical for every endpoint that enforces ABAC — `getEncryptedFile` requires exactly the same thing as `getUnencryptedFile` (it's a diagnostic view of the ciphertext, not a separate lower-tier grant), and `listFiles`/`listFilesByBucket` filter results with the same rule.

Organizations come from the JWT claim `organizations`: `[{ "organizationId": "...", "access": "..." }]`.

### MongoDB Collections

| Collection | Key field | Used for |
|------------|-----------|----------|
| `policies` | `dataset_name` | Dataset access policies |
| `org_secrets` | `organizationId` | Auto-provisioned root secret per organization, used to derive encryption keys |
| `dataset_keys` | `dataset_name` | Per-organization wrapped data-encryption-keys for each encrypted dataset |
| `access_logs` | — | Audit log of every `getEncryptedFile`/`getUnencryptedFile` request, success or failure |

`org_secrets` and `dataset_keys` are populated automatically — there is no manual key-management step (see [ABE](#abe--attribute-based-encryption)).

### REST API — `/api/v1/policies`

| Method | Path | Description | Auth |
|--------|------|--------------|------|
| GET | `/api/v1/policies/` | List all policies | Valid JWT |
| GET | `/api/v1/policies/{dataset_name}` | Get a single policy | Valid JWT |
| POST | `/api/v1/policies/` | Create a policy | Requires `access: "admin"` on any organization |
| PUT | `/api/v1/policies/{dataset_name}` | Replace a policy entirely | Requires `access: "admin"` on any organization |
| PATCH | `/api/v1/policies/{dataset_name}` | Partially update a policy | Requires `access: "admin"` on any organization |
| DELETE | `/api/v1/policies/{dataset_name}` | Delete a policy | Requires `access: "admin"` on any organization |

This is a coarse admin gate for now — any organization admin can manage any dataset's policy, not just their own. Tighten this once a dedicated platform-admin concept exists.

---

## ABE — Attribute-Based Encryption

Files are encrypted with **envelope encryption**, cryptographically bound to both attributes in each policy grant — `organizationId` *and* `access` — not just organization identity. Decryption isn't just an API-level check, it requires key material scoped to a specific organization at a specific tier.

**How it works:**

1. Each file gets a random 256-bit Data Encryption Key (DEK). File content is encrypted once with it (AES-256-GCM).
2. The DEK is then **wrapped separately for each `{organizationId, access}` grant** in the policy, using a Key Encryption Key (KEK) derived from that organization's root secret *and* its tier (see step 4).
3. Organization root secrets are generated automatically the first time an organization is encountered (atomic upsert into `org_secrets`) — no setup required.
4. KEKs are derived per access tier via a one-way hash chain: `admin → rw → ro → c-ro`. A key derived at a higher tier can recompute every tier below it; a lower-tier key can never derive a higher one.
5. Revoking an organization's access to *all* data is done by deleting its `org_secrets` entry — every wrapped key it ever received becomes permanently unrecoverable, even in the presence of an API-level authorization bug.

Wrapped keys live in the `dataset_keys` collection, one entry per organization per dataset.

**Policy changes on an already-encrypted dataset trigger automatic re-encryption.** Updating a dataset's `policy.roles` (via `PUT`/`PATCH /api/v1/policies/{dataset_name}`) — adding an org, removing one, or changing an existing org's tier — decrypts the file with any existing wrapped key, discards all old wrapped-key entries, and re-encrypts with a **brand-new DEK** wrapped fresh for every org in the updated policy. A fresh DEK on every policy change means old key material can never decrypt the new ciphertext, even in principle — not just "the API denies the request." If this can't complete (e.g. the existing wrapped key fails to decrypt), the policy change still saves, but the request returns `500` and the file is left needing a manual re-drop into the source bucket to resync.

> Existing files encrypted under the previous fixed-key scheme are not decryptable under this scheme — key derivation is entirely different. Affected datasets need to be re-dropped into the source bucket for re-encryption once their policy exists.

### Development Token Issuance (`/api/v1/dev/token`)

To interact with the encrypted files and test the ABE/ABAC flow, users must authenticate using a JWT. For development and testing purposes, a dedicated endpoint is provided to generate signed JWTs shaped like a real Keycloak access token — standard claims (`iss`, `aud`, `azp`, `session_state`, `realm_access`, `resource_access`, `scope`, `email`, etc.) plus the custom `organizations` claim. Everything except `organizations` is cosmetic realism; it's the only claim this app's authorization logic actually reads. In production, tokens are issued by a partner-operated Keycloak instead — only `JWT_PUBLIC_KEY` needs to change; the `organizations` claim shape stays the same.

**Method:** `POST`
**Endpoint:** `/api/v1/dev/token`

#### Query Parameters

| Name | Type | Description | Default Value |
|------|------|-------------|---------------|
| `sub` | string | Subject (User ID) | `dev-user` |
| `preferred_username` | string | Username | `developer` |
| `email` | string | Email claim | `developer@example.com` |
| `organizations` | string | Comma-separated `organizationId:access` pairs | `UBI:admin` |
| `realm` | string | Shapes the `iss` claim and default realm roles | `twinship` |
| `expires_in` | integer | Token lifetime in seconds | `3600` |

Example: `organizations=UBI:admin,WAR:c-ro` grants admin on `UBI` and client-read-only on `WAR`.

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
- **Automated Encryption:** once a policy is found, the system generates a fresh DEK, encrypts the file (AES-256-GCM), wraps the DEK for every organization in the policy, and uploads the result to the encrypted destination bucket.
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
| **GET** | `/api/v1/listFilesByBucket` | `?bucket=<string>` | Returns file names in the given bucket, filtered to those the caller's organizations can access. | Filters via `check_dataset_access` — inaccessible files are omitted, not errored. |
| **GET** | `/api/v1/getUnencryptedFile` | `?filename=<string>` | Downloads the requested file, unwraps the caller's organization-specific key, decrypts it, and returns the clean content. | **Strict.** 404 if no policy exists, 403 if the caller's claimed tier doesn't meet or exceed their org's policy grant. Every attempt is written to the [audit log](#audit-log). |
| **GET** | `/api/v1/getEncryptedFile` | `?filename=<string>` | Downloads the requested file and returns it **AS IS** (still cryptographically scrambled). | **Strict.** Identical check to `getUnencryptedFile` — no lower bar; no crypto operations performed. Every attempt is written to the [audit log](#audit-log). |

---

### Audit Log

Every `getEncryptedFile` and `getUnencryptedFile` request — successful or not — is recorded in the `access_logs` collection: who (`user_id`, `username`, `organizations`, from the JWT), what (`dataset_name`, `operation`), and the outcome (`status`: `"success"`/`"failure"`, plus a `reason` for failures — ABAC denial, no policy, decryption failure, not found, etc.). Other endpoints (listing, policy management) are not logged.

#### `GET /api/v1/audit-logs`

| Query param | Description |
|-------------|--------------|
| `user_id` | Filter to one user's requests (JWT `sub`) |
| `organization` | Filter to requests from callers holding this org |
| `dataset_name` | Filter to requests for one dataset |
| `status` | `"success"` or `"failure"` |
| `limit` / `skip` | Pagination (default `limit=100`) |

No filters returns every request from everyone. **Currently requires only a valid JWT — no admin restriction yet.** Anyone with a token can query anyone else's access history; this is a deliberate temporary state, expected to be locked down later.

---

### API Documentation (Swagger UI)

The Anonymizer is built with FastAPI, providing interactive, auto-generated documentation.

For complete details on request parameters, expected responses, error codes, and to test the API endpoints interactively, please visit the Swagger UI at:
👉 **`http://<YOUR_SERVER_IP>:8000/docs#`**
