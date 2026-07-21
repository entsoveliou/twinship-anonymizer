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

// --- Dataset policies (one document per dataset, no fallback) ---
db.createCollection('policies');
db.policies.createIndex({ dataset_name: 1 }, { unique: true });

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

// No seed policies on purpose: every dataset needs an explicit policy
// created via POST /api/v1/policies before its file is uploaded. There is
// no fallback/default policy in this system.
