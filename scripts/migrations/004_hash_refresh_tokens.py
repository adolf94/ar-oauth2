import os
import re
import hashlib
import datetime
from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError
import urllib3

# Disable insecure request warnings for local emulator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONNECTION_STRING = os.environ.get("COSMOS_CONNECTION_STRING") or "AccountEndpoint=https://localhost:8081/;AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==;"
DATABASE_NAME = os.environ.get("COSMOS_DATABASE_NAME") or "ArAuth"

# Matches EF-written DateTime values, e.g. "2026-11-22T10:00:00.1234567Z"
_DT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_cosmos_datetime(value):
    """Best-effort parse of a Cosmos DateTime string; returns aware datetime or None."""
    if not isinstance(value, str):
        return None
    m = _DT_RE.match(value)
    if not m:
        return None
    base, frac, tz = m.group(1), m.group(2) or "", m.group(3)
    micros = int((frac + "000000")[:6])
    dt = datetime.datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(microsecond=micros)
    if tz in (None, "Z"):
        return dt.replace(tzinfo=datetime.timezone.utc)
    tz = tz.replace(":", "")
    sign = 1 if tz[0] == "+" else -1
    offset = datetime.timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
    return dt.replace(tzinfo=datetime.timezone(offset))


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def migrate():
    print("Connecting to Cosmos DB...")
    client = CosmosClient.from_connection_string(conn_str=CONNECTION_STRING, connection_verify=False)
    database = client.get_database_client(DATABASE_NAME)

    try:
        container = database.get_container_client("Tokens")
        docs = list(container.query_items(query="SELECT * FROM c", enable_cross_partition_query=True))
    except CosmosResourceNotFoundError:
        print("Tokens container does not exist yet — nothing to migrate.")
        docs = []

    hashed = 0
    expired_dropped = 0
    skipped = 0

    now = datetime.datetime.now(datetime.timezone.utc)

    for doc in docs:
        old_id = doc.get("id")
        if not old_id:
            continue

        # Defensive: a 64-char hex id is already a SHA-256 hash (migrated or
        # written by the new code). Never double-hash.
        if len(old_id) == 64:
            skipped += 1
            continue

        # Opportunistic cleanup: nothing ever deleted expired rows, and a
        # dead token needs no re-key. Drop it instead of migrating it.
        expires = parse_cosmos_datetime(doc.get("ExpiresAt"))
        if expires is not None and expires < now:
            try:
                container.delete_item(item=old_id, partition_key=old_id)
                expired_dropped += 1
            except CosmosResourceNotFoundError:
                pass
            continue

        # The client holds "{old_id}.{sid}"; the new lookup key must be
        # SHA-256(old_id) so those tokens keep validating after deployment.
        new_id = hashlib.sha256(old_id.encode("utf-8")).hexdigest()

        # Stamp the absolute-lifetime clock for pre-CreatedAt rows.
        if not doc.get("CreatedAt"):
            doc["CreatedAt"] = now_iso()

        # Pre-feature rows are live tokens: no tombstone flag.
        doc.pop("RotatedAt", None)
        doc["id"] = new_id

        try:
            container.delete_item(item=old_id, partition_key=old_id)
        except CosmosResourceNotFoundError:
            pass
        container.upsert_item(body=doc, partition_key=new_id)
        hashed += 1

    print(f"Refresh tokens re-keyed to SHA-256 ids: {hashed}")
    print(f"Expired refresh tokens dropped:         {expired_dropped}")
    print(f"Already-hashed rows skipped:            {skipped}")

    # Record the migration execution
    migrations_container = database.get_container_client("__PyMigrations")
    migration_record = {
        "id": "004_hash_refresh_tokens",
        "applied_at": now_iso()
    }
    migrations_container.upsert_item(migration_record)
    print("Migration '004_hash_refresh_tokens' recorded in '__PyMigrations'.")

if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"Error during migration: {e}")
