# restore.py
#
# Standalone manual disaster-recovery script (not wired into the app, not
# run automatically anywhere) — reverses backup.py: reads the JSON
# snapshots under BACKUP_DIR and upserts their documents back into Mongo,
# matched by each collection's real business key (see backup.KEY_FIELDS —
# role/dataset_name/prefix, NOT '_id'). Safe to run against a
# freshly-recreated database (e.g. after mongo-data was destroyed by disk
# failure / accidental `docker compose down -v` outside a deliberate
# migration) even if mongo/init/01-init.js already re-seeded some
# collections (e.g. prefix_policies) with different '_id's — matching by
# business key overwrites those in place instead of colliding with their
# unique index.
#
# ⚠️ Do NOT run this after an intentional `docker compose down -v` done for
# a schema migration (see CLAUDE.md's "Migration note"). A backup snapshot
# reflects whatever document shape was current when it was written — if
# that shape predates a breaking schema change, restoring it reintroduces
# documents the new code can't read correctly, exactly the problem the
# migration's fresh-volume step was meant to avoid. Restoring is only for
# "we lost data we didn't mean to lose", never for "we want the old data
# back on new code".
#
# Usage: python restore.py [-y]
#   -y / --yes   skip the confirmation prompt (for scripted use)
import argparse
import os

from bson import json_util
from pymongo import MongoClient

import settings
from backup import COLLECTIONS, KEY_FIELDS

_db = MongoClient(settings.MONGO_URI)[settings.MONGO_DB]


def _load(name: str):
    path = os.path.join(settings.BACKUP_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json_util.loads(f.read())


def restore_once() -> dict:
    """
    Upserts each snapshot's documents back into Mongo, matched by that
    collection's real business key (KEY_FIELDS), not by the backed-up '_id'.
    The '_id' is dropped before writing: if the target collection was
    already re-seeded (e.g. mongo/init/01-init.js ran on a fresh volume and
    re-inserted prefix_policies with new '_id's), matching on the old '_id'
    would try to insert a second document with the same business key and
    hit the unique index instead of overwriting the reseeded one in place.
    Dropping '_id' lets Mongo keep the existing one on a match, or generate
    a fresh one on insert — either way, no collision.
    """
    counts = {}
    for name in COLLECTIONS:
        docs = _load(name)
        if docs is None:
            continue
        key_field = KEY_FIELDS[name]
        for doc in docs:
            doc.pop("_id", None)
            _db[name].replace_one({key_field: doc[key_field]}, doc, upsert=True)
        counts[name] = len(docs)
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompt")
    args = parser.parse_args()

    print(f"This will restore snapshots from '{settings.BACKUP_DIR}' into Mongo DB "
          f"'{settings.MONGO_DB}' at '{settings.MONGO_URI}', upserting by each collection's business key.")
    print("Do NOT do this after an intentional schema-migration wipe — see the warning in this file's header.")

    if not args.yes:
        confirm = input("Type 'yes' to proceed: ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            raise SystemExit(1)

    counts = restore_once()
    if not counts:
        print(f"No snapshot files found under '{settings.BACKUP_DIR}' — nothing to restore.")
    else:
        print(f"Restored: {counts}")
