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

_Documentation coming soon._

---

## Anonymizer

_Documentation coming soon._
