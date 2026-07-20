# audit.py
from datetime import datetime, timezone
from typing import Optional

from pymongo import MongoClient, DESCENDING

import settings

_client = MongoClient(settings.MONGO_URI)
_access_logs = _client[settings.MONGO_DB]["access_logs"]


def log_access(
    user_id: str,
    username: str,
    organizations: list[str],
    dataset_name: str,
    operation: str,
    status: str,
    reason: Optional[str] = None,
):
    """
    Records one access attempt: who (user_id/username/organizations), what
    (dataset_name/operation), and the outcome (status: "success"/"failure",
    with an optional reason for failures).
    """
    doc = {
        "timestamp": datetime.now(timezone.utc),
        "user_id": user_id,
        "username": username,
        "organizations": organizations,
        "dataset_name": dataset_name,
        "operation": operation,
        "status": status,
    }
    if reason:
        doc["reason"] = reason
    _access_logs.insert_one(doc)


def query_access_logs(
    user_id: Optional[str] = None,
    organization: Optional[str] = None,
    dataset_name: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
) -> list[dict]:
    query = {}
    if user_id:
        query["user_id"] = user_id
    if organization:
        # organizations is stored as an array; this matches if the value is a member
        query["organizations"] = organization
    if dataset_name:
        query["dataset_name"] = dataset_name
    if status:
        query["status"] = status

    cursor = (
        _access_logs.find(query, {"_id": 0})
        .sort("timestamp", DESCENDING)
        .skip(skip)
        .limit(limit)
    )
    return list(cursor)
