# backup.py
#
# Local-disk backup of the Mongo collections that hold irreplaceable key
# material (role_secrets, dataset_keys) plus the two policy collections
# (policies, prefix_policies). role_secrets in particular has no derivation
# chain — each secret is a standalone os.urandom(32) — so if it's ever lost
# with nothing to restore from, every wrapped DEK in dataset_keys becomes
# permanently unwrappable and every file in the encrypted bucket is inert
# ciphertext forever. This writes plain JSON snapshots to BACKUP_DIR (a
# local directory/volume — no external service involved) on an interval;
# see main.py's backup_loop for the scheduling side, restore.py for the
# manual recovery side.
import os

from bson import json_util
from pymongo import MongoClient

import settings

_client = MongoClient(settings.MONGO_URI)
_db = _client[settings.MONGO_DB]

# Order is irrelevant for backup/restore (each document upserts by its own
# business key, see KEY_FIELDS) — listed roughly in order of "how bad is it
# to lose this".
COLLECTIONS = ["role_secrets", "dataset_keys", "policies", "prefix_policies"]

# The real uniqueness constraint for each collection (matches the unique
# indexes in mongo/init/01-init.js) — NOT '_id'. restore.py matches on these
# rather than the backed-up '_id' because re-running 01-init.js on a fresh
# volume already re-seeds prefix_policies with brand-new '_id's; matching by
# '_id' would try to insert a second document with the same business key and
# hit the unique index instead of overwriting the reseeded one in place.
KEY_FIELDS = {
    "role_secrets": "role",
    "dataset_keys": "dataset_name",
    "policies": "dataset_name",
    "prefix_policies": "prefix",
}


def backup_once() -> dict:
    """
    Dumps every document in each collection in COLLECTIONS to
    '<BACKUP_DIR>/<collection>.json', overwriting the previous snapshot.
    Writes to a temp file first and atomically renames it into place
    (os.replace, same-filesystem rename) so a crash mid-write can never
    leave a half-written, corrupt snapshot on disk — the prior snapshot
    stays intact and valid until the new one is fully flushed.

    Uses bson.json_util so BSON-only types (ObjectId, Binary — role secrets
    and wrapped DEKs are stored as Binary) round-trip exactly through JSON,
    not just plain fields.

    Returns {collection_name: document_count} for logging/visibility.
    """
    os.makedirs(settings.BACKUP_DIR, exist_ok=True)
    counts = {}
    for name in COLLECTIONS:
        docs = list(_db[name].find())
        path = os.path.join(settings.BACKUP_DIR, f"{name}.json")
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            f.write(json_util.dumps(docs))
        os.replace(tmp_path, path)
        counts[name] = len(docs)
    return counts
