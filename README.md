# Twinship Anonymizer

## Table of Contents

- [ABAC — Attribute-Based Access Control](#abac--attribute-based-access-control)
- [ABE — Attribute-Based Encryption](#abe--attribute-based-encryption)
- [Anonymizer](#anonymizer)

---

## ABAC — Attribute-Based Access Control

Access control is enforced at the **dataset level**: every file in the encrypted bucket is associated with a policy that defines which roles are required to access it and what encryption attributes were used when the file was encrypted.

Policies are stored in MongoDB and managed via REST API.

### Policy Structure

Both policy types share the same fields:

| Field | Type | Description |
|-------|------|-------------|
| `filename` / `prefix` | string | Identifier: exact filename or filename prefix |
| `required_roles` | list[string] | Roles required to access the file |
| `match` | `"any"` or `"all"` | Whether the user needs **any one** or **all** of the required roles |
| `encryption_attributes` | list[string] | Strings used as AAD during AES-256-GCM encryption |

### Policy Lookup (Three-Step Resolution)

When a file is accessed, `abac.py` resolves its policy in this order:

1. **Exact match** — looks up the filename in the `policies` collection
2. **Prefix match** — checks all entries in `prefix_policies`; the first matching prefix wins
3. **Default fallback** — uses the document with `filename: "default"` in `policies`

If no policy is found at all, the request returns `500`.

### Role Matching

- `"match": "any"` — the user must have **at least one** of the `required_roles`
- `"match": "all"` — the user must have **every** role in `required_roles`

Roles come from the JWT claim `realm_access.roles` (Keycloak format).

### Encryption Binding

The `encryption_attributes` list is used as **AAD (Additional Authenticated Data)** in AES-256-GCM. The AAD is the sorted JSON representation of this list. This means:

- Decryption will **cryptographically fail** if the wrong policy's attributes are used
- The file is bound to its policy at encryption time — changing `encryption_attributes` after the fact will make existing files permanently unreadable

### MongoDB Collections

| Collection | Key field | Used for |
|------------|-----------|----------|
| `policies` | `filename` | Exact-match policies and the `default` fallback |
| `prefix_policies` | `prefix` | Prefix-match policies |

The `default` policy (in `policies`) is protected — it cannot be deleted via the API.

### REST API

#### Exact-match Policies — `/api/v1/policies`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/policies/` | List all policies |
| GET | `/api/v1/policies/{filename}` | Get a single policy |
| POST | `/api/v1/policies/` | Create a policy |
| PUT | `/api/v1/policies/{filename}` | Replace a policy entirely |
| PATCH | `/api/v1/policies/{filename}` | Partially update a policy |
| DELETE | `/api/v1/policies/{filename}` | Delete a policy (`default` is protected) |

#### Prefix Policies — `/api/v1/prefix-policies`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/prefix-policies/` | List all prefix policies |
| GET | `/api/v1/prefix-policies/{prefix}` | Get a single prefix policy |
| POST | `/api/v1/prefix-policies/` | Create a prefix policy |
| PUT | `/api/v1/prefix-policies/{prefix}` | Replace a prefix policy entirely |
| PATCH | `/api/v1/prefix-policies/{prefix}` | Partially update a prefix policy |
| DELETE | `/api/v1/prefix-policies/{prefix}` | Delete a prefix policy |

#### Example Policy Document

```json
{
  "filename": "weather_2024.csv",
  "required_roles": ["operator", "analyst"],
  "match": "any",
  "encryption_attributes": ["attr1", "attr2"]
}
```

#### Example Prefix Policy Document

```json
{
  "prefix": "weather/",
  "required_roles": ["operator"],
  "match": "all",
  "encryption_attributes": ["attr1", "attr2"]
}
```

### Where ABAC Is Enforced

| Endpoint | Behavior |
|----------|----------|
| `GET /api/v1/getUnencryptedFile` | `require_dataset_access()` raises 403 if denied |
| `GET /api/v1/getEncryptedFile` | `require_dataset_access()` raises 403 if denied |
| `GET /api/v1/listFilesByBucket` | Files split into `accessible` / `inaccessible` lists |
| `GET /api/v1/listFiles` | JWT only — no per-file ABAC check |

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://root:rootpassword@localhost:27017` | MongoDB connection string |
| `MONGO_DB` | `datasetPolicies` | Database name |

---

## ABE — Attribute-Based Encryption

The Attribute-Based Encryption (ABE) module ensures that data is cryptographically bound to specific attributes. Instead of relying solely on API-level checks, the file's ciphertext is tied to `encryption_attributes` (acting as Associated Authenticated Data - AAD in AES-256-GCM). 

If a user does not possess the correct roles to retrieve a dataset's attributes, or if the attributes are tampered with, the decryption process will mathematically fail.

### Development Token Issuance (`/api/v1/dev/token`)

To interact with the encrypted files and test the ABE flow, users must authenticate using a JWT. For development and testing purposes, a dedicated endpoint is provided to easily generate signed JWTs with custom roles.

**Method:** `POST`  
**Endpoint:** `/api/v1/dev/token`

#### Query Parameters

| Name | Type | Description | Default Value |
|------|------|-------------|---------------|
| `sub` | string | Subject (User ID) | `dev-user` |
| `preferred_username` | string | Username | `developer` |
| `roles` | string | Comma-separated list of roles | `default-roles-twinship, offline_access, developer, uma_authorization, operator` |
| `expires_in` | integer | Token lifetime in seconds | `3600` |

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
- **Prefix Binding:** Files are expected to follow a specific naming convention using a prefix (e.g., `prefix_filename.csv`). 
- **Automated Encryption:** When a new file is detected, the system extracts its prefix. This prefix corresponds to specific encryption attributes, which are ultimately bound to user roles via the ABAC policy. The file is immediately encrypted using AES-256-GCM and safely transferred to the encrypted destination bucket. 

#### 2. Automated Retention Policy
To ensure that raw, unencrypted data does not sit indefinitely in the source bucket, a strict retention policy runs constantly. It evaluates files based on their last edited timestamp and their prefix.

This policy is configured upon startup using environment variables:
- `RETENTION_PREFIX` *(default: `"weather"`)*: The background task will only target files starting with this specific prefix.
- `RETENTION_SECONDS` *(default: `30`)*: The maximum amount of time (in seconds) a matching file is allowed to stay in the source bucket. Once the file's age exceeds this threshold, it is automatically and permanently deleted from the unencrypted bucket.

---

### REST API Endpoints

The Anonymizer exposes the following protected APIs to interact with the encrypted data. All endpoints require a valid Bearer JWT.

| Method | Endpoint | Parameters | Description | ABAC Enforcement |
|--------|----------|------------|-------------|------------------|
| **GET** | `/api/v1/listFiles` | None | Returns a JSON array of all file names currently stored in the encrypted bucket. | **None.** Requires a valid JWT, but no dataset-level policy check is performed to list the names. |
| **GET** | `/api/v1/getUnencryptedFile` | `?filename=<string>` | Downloads the requested file, decrypts it on the fly using ABE, and returns the clean, readable content. | **Strict.** Checks the user's roles against the dataset's specific ABAC policy before allowing decryption. |
| **GET** | `/api/v1/getEncryptedFile` | `?filename=<string>` | Downloads the requested file and returns it **AS IS** (still cryptographically scrambled). | **Strict.** Checks the user's roles against the dataset's specific ABAC policy before allowing the download. |

---

### API Documentation (Swagger UI)

The Anonymizer is built with FastAPI, providing interactive, auto-generated documentation.

For complete details on request parameters, expected responses, error codes, and to test the API endpoints interactively, please visit the Swagger UI at:  
👉 **`http://<YOUR_SERVER_IP>:8000/docs#`**
