db = db.getSiblingDB('datasetPolicies');

// --- Scoped application user ---
// The app connects as this user, not the bootstrap root account created via
// MONGO_INITDB_ROOT_USERNAME/PASSWORD. readWrite on this one database only —
// no admin/root privileges, so a leaked MONGO_URI can't do anything outside
// datasetPolicies (create other users, touch other databases, etc.).
db.createUser({
    user: "app",
    pwd: "app_change_me_internal",
    roles: [{ role: "readWrite", db: "datasetPolicies" }]
});

// --- Dataset policies (one document per dataset, exact match) ---
db.createCollection('policies');
db.policies.createIndex({ dataset_name: 1 }, { unique: true });

// --- Predefined prefix policies (fallback tier, resource categories) ---
// Consulted only when a dataset has no exact 'policies' entry — see
// abac.py:_find_policy. Unlike 'policies', these are NOT managed through the
// API at all (no CRUD router): they're fixed, seeded here once, and only
// ever change via a fresh migration to this file. The role lists below are
// each a single granular resource role, derived from the consortium's
// User-Role Type -> granular-role composite mapping (policies_router.py:
// USER_ROLE_TYPE_ROLES) so that exactly the right User-Role Types qualify
// for each resource category.
db.createCollection('prefix_policies');
db.prefix_policies.createIndex({ prefix: 1 }, { unique: true });

var _now = new Date();
db.prefix_policies.insertMany([
    { prefix: 'grimaldi-data-',  policy: { roles: ['data-gr'] },  created_at: _now },
    { prefix: 'stena-tk-data-',  policy: { roles: ['data-st'] },  created_at: _now },
    { prefix: 'stena-li-data-',  policy: { roles: ['data-sl'] },  created_at: _now },
    { prefix: 'grimaldi-model-', policy: { roles: ['model-gr'] }, created_at: _now },
    { prefix: 'stena-tk-model-', policy: { roles: ['model-st'] }, created_at: _now },
    { prefix: 'stena-li-model-', policy: { roles: ['model-sl'] }, created_at: _now },
    { prefix: 'weather-router-', policy: { roles: ['apps'] },     created_at: _now },
    { prefix: 'lcca-',           policy: { roles: ['apps'] },     created_at: _now },
    { prefix: 'iea-',            policy: { roles: ['apps'] },     created_at: _now },
]);

// --- Auto-provisioned per-role root secrets ---
db.createCollection('role_secrets');
db.role_secrets.createIndex({ role: 1 }, { unique: true });

// --- Per-dataset wrapped DEKs (one entry per granted role) ---
db.createCollection('dataset_keys');
db.dataset_keys.createIndex({ dataset_name: 1 }, { unique: true });

// --- Access audit log (getEncryptedFile / getUnencryptedFile attempts) ---
db.createCollection('access_logs');
db.access_logs.createIndex({ user_id: 1 });
db.access_logs.createIndex({ roles: 1 });
db.access_logs.createIndex({ dataset_name: 1 });
db.access_logs.createIndex({ timestamp: -1 });

// NOTE: docker-entrypoint-initdb.d scripts (including this one) only run
// against an EMPTY data directory. An existing deployment created before
// the org_secrets -> role_secrets rename needs `docker compose down -v`
// (destroys all existing policies/keys/audit log) to pick this up.

// No seed EXACT policies on purpose: a dataset with no exact policy and no
// matching prefix still needs POST /api/v1/policies before its file is
// uploaded/read. There is still no catch-all "default" policy — only the
// two tiers above (exact, then prefix).
