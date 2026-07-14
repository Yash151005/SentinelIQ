"""
SentinelIQ — MongoDB Client
============================
Connection management, CRUD helpers, and aggregation pipelines
for all 5 collections: users, sessions, alerts, audit_logs, behaviours.

Falls back to in-memory storage if MongoDB is unavailable.
"""

import os
import datetime
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "sentineliq")

# ---------------------------------------------------------------------------
# In-memory fallback storage (used when MongoDB is unavailable)
# ---------------------------------------------------------------------------
_inmemory_db: Dict[str, List[Dict]] = {
    "users": [],
    "sessions": [],
    "alerts": [],
    "audit_logs": [],
    "behaviours": [],
    "pqc_checklist": [],
}

_mongo_available = False
_db = None


def _get_db():
    """Get MongoDB database connection (singleton)."""
    global _mongo_available, _db
    if _db is not None:
        return _db
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        # Test connection
        client.admin.command('ping')
        _db = client[MONGO_DB_NAME]
        _mongo_available = True
        return _db
    except Exception:
        _mongo_available = False
        _db = None
        return None


def is_mongo_available() -> bool:
    """Check if MongoDB is connected."""
    _get_db()
    return _mongo_available


# ---------------------------------------------------------------------------
# Generic CRUD helpers (work with both MongoDB and in-memory fallback)
# ---------------------------------------------------------------------------

def insert_one(collection: str, document: Dict) -> str:
    """Insert a single document. Returns inserted_id as string."""
    db = _get_db()
    if db is not None:
        result = db[collection].insert_one(document)
        return str(result.inserted_id)
    else:
        import uuid
        if "_id" not in document:
            document["_id"] = str(uuid.uuid4())
        _inmemory_db.setdefault(collection, []).append(document)
        return str(document["_id"])


def insert_many(collection: str, documents: List[Dict]) -> List[str]:
    """Insert multiple documents. Returns list of inserted_ids."""
    db = _get_db()
    if db is not None:
        result = db[collection].insert_many(documents)
        return [str(i) for i in result.inserted_ids]
    else:
        import uuid
        ids = []
        for doc in documents:
            if "_id" not in doc:
                doc["_id"] = str(uuid.uuid4())
            _inmemory_db.setdefault(collection, []).append(doc)
            ids.append(str(doc["_id"]))
        return ids


def find(collection: str, query: Optional[Dict] = None, sort: Optional[List] = None,
         limit: int = 0) -> List[Dict]:
    """Find documents matching query."""
    db = _get_db()
    if db is not None:
        cursor = db[collection].find(query or {})
        if sort:
            cursor = cursor.sort(sort)
        if limit > 0:
            cursor = cursor.limit(limit)
        return list(cursor)
    else:
        results = _inmemory_db.get(collection, [])
        if query:
            results = [doc for doc in results if _match_query(doc, query)]
        if sort:
            for key, direction in reversed(sort):
                results.sort(key=lambda x: x.get(key, ""), reverse=(direction == -1))
        if limit > 0:
            results = results[:limit]
        return results


def find_one(collection: str, query: Optional[Dict] = None) -> Optional[Dict]:
    """Find a single document matching query."""
    db = _get_db()
    if db is not None:
        return db[collection].find_one(query or {})
    else:
        results = _inmemory_db.get(collection, [])
        if query:
            for doc in results:
                if _match_query(doc, query):
                    return doc
            return None
        return results[0] if results else None


def update_one(collection: str, query: Dict, update: Dict) -> int:
    """Update a single document. Returns modified count."""
    db = _get_db()
    if db is not None:
        result = db[collection].update_one(query, update)
        return result.modified_count
    else:
        docs = _inmemory_db.get(collection, [])
        for doc in docs:
            if _match_query(doc, query):
                if "$set" in update:
                    doc.update(update["$set"])
                if "$push" in update:
                    for k, v in update["$push"].items():
                        doc.setdefault(k, []).append(v)
                return 1
        return 0


def count_documents(collection: str, query: Optional[Dict] = None) -> int:
    """Count documents matching query."""
    db = _get_db()
    if db is not None:
        return db[collection].count_documents(query or {})
    else:
        if not query:
            return len(_inmemory_db.get(collection, []))
        return len([d for d in _inmemory_db.get(collection, []) if _match_query(d, query)])


def delete_many(collection: str, query: Optional[Dict] = None) -> int:
    """Delete documents matching query."""
    db = _get_db()
    if db is not None:
        result = db[collection].delete_many(query or {})
        return result.deleted_count
    else:
        before = len(_inmemory_db.get(collection, []))
        if query:
            _inmemory_db[collection] = [
                d for d in _inmemory_db.get(collection, []) if not _match_query(d, query)
            ]
        else:
            _inmemory_db[collection] = []
        return before - len(_inmemory_db.get(collection, []))


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def get_rolling_risk_scores(days: int = 30) -> List[Dict]:
    """Get cumulative risk scores for all users over rolling window."""
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    db = _get_db()
    if db is not None:
        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff}}},
            {"$group": {
                "_id": "$user_id",
                "total_risk": {"$sum": "$isolation_score"},
                "avg_risk": {"$avg": "$isolation_score"},
                "max_risk": {"$max": "$isolation_score"},
                "session_count": {"$sum": 1},
            }},
            {"$sort": {"total_risk": -1}},
        ]
        return list(db["behaviours"].aggregate(pipeline))
    else:
        from collections import defaultdict
        user_risks = defaultdict(lambda: {"scores": [], "count": 0})
        for b in _inmemory_db.get("behaviours", []):
            ts = b.get("timestamp", datetime.datetime.now(datetime.timezone.utc))
            if isinstance(ts, datetime.datetime):
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
                if ts >= cutoff:
                    uid = b.get("user_id", "unknown")
                    user_risks[uid]["scores"].append(b.get("isolation_score", 0))
                    user_risks[uid]["count"] += 1
        results = []
        for uid, data in user_risks.items():
            scores = data["scores"]
            results.append({
                "_id": uid,
                "total_risk": sum(scores),
                "avg_risk": sum(scores) / len(scores) if scores else 0,
                "max_risk": max(scores) if scores else 0,
                "session_count": data["count"],
            })
        results.sort(key=lambda x: x["total_risk"], reverse=True)
        return results


def get_user_risk_percentile(user_id: str) -> float:
    """Get a user's risk percentile rank (0-100)."""
    all_risks = get_rolling_risk_scores()
    if not all_risks:
        return 0.0
    total_users = len(all_risks)
    for i, r in enumerate(all_risks):
        if r["_id"] == user_id:
            return round(((total_users - i) / total_users) * 100, 1)
    return 0.0


def get_user_sessions(user_id: str, limit: int = 50) -> List[Dict]:
    """Get recent sessions for a specific user."""
    return find("sessions", {"user_id": user_id}, sort=[("start_time", -1)], limit=limit)


def get_user_alerts(user_id: str, limit: int = 50) -> List[Dict]:
    """Get recent alerts for a specific user."""
    return find("alerts", {"user_id": user_id}, sort=[("timestamp", -1)], limit=limit)


def get_audit_trail(user_id: Optional[str] = None, event_type: Optional[str] = None,
                    limit: int = 200) -> List[Dict]:
    """Get audit trail with optional filters."""
    query = {}
    if user_id:
        query["actor"] = user_id
    if event_type:
        query["event_type"] = event_type
    return find("audit_logs", query, sort=[("timestamp", -1)], limit=limit)


def log_audit_event(actor: str, action: str, target: str, rbac_decision: str = "",
                    rationale: str = "", event_type: str = "system") -> str:
    """Log an audit event."""
    doc = {
        "actor": actor,
        "action": action,
        "target": target,
        "rbac_decision": rbac_decision,
        "rationale": rationale,
        "timestamp": datetime.datetime.now(datetime.timezone.utc),
        "event_type": event_type,
    }
    return insert_one("audit_logs", doc)


# ---------------------------------------------------------------------------
# In-memory query matcher (simple implementation for fallback)
# ---------------------------------------------------------------------------

def _safe_compare(v1, v2, op) -> bool:
    """Safe comparison handling potential datetime offset conflicts."""
    try:
        import datetime
        if isinstance(v1, datetime.datetime) and isinstance(v2, datetime.datetime):
            if v1.tzinfo is None and v2.tzinfo is not None:
                v1 = v1.replace(tzinfo=datetime.timezone.utc)
            elif v1.tzinfo is not None and v2.tzinfo is None:
                v2 = v2.replace(tzinfo=datetime.timezone.utc)
        if op == "$gte": return v1 >= v2
        if op == "$lte": return v1 <= v2
        if op == "$gt": return v1 > v2
        if op == "$lt": return v1 < v2
    except Exception:
        pass
    return False


def _match_query(doc: Dict, query: Dict) -> bool:
    """Simple query matcher for in-memory fallback."""
    for key, value in query.items():
        if key.startswith("$"):
            continue
        doc_val = doc.get(key)
        if isinstance(value, dict):
            for op, op_val in value.items():
                if op in ["$gte", "$lte", "$gt", "$lt"]:
                    if doc_val is None or not _safe_compare(doc_val, op_val, op):
                        return False
                elif op == "$ne" and doc_val == op_val:
                    return False
                elif op == "$in" and doc_val not in op_val:
                    return False
        else:
            if doc_val != value:
                return False
    return True


def get_inmemory_db() -> Dict[str, List[Dict]]:
    """Expose in-memory db for debugging/testing."""
    return _inmemory_db


def clear_collection(collection: str):
    """Clear all documents in a collection."""
    db = _get_db()
    if db is not None:
        db[collection].delete_many({})
    _inmemory_db[collection] = []
