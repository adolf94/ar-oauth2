import os
from azure.cosmos import CosmosClient, PartitionKey
import urllib3
import datetime

# Disable insecure request warnings for local emulator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONNECTION_STRING = os.environ.get("COSMOS_CONNECTION_STRING") or "AccountEndpoint=https://localhost:8081/;AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==;"
DATABASE_NAME = os.environ.get("COSMOS_DATABASE_NAME") or "ArAuth"

def migrate():
    print("Connecting to Cosmos DB...")
    client = CosmosClient.from_connection_string(conn_str=CONNECTION_STRING, connection_verify=False)
    database = client.get_database_client(DATABASE_NAME)
    
    # 1. Create TokenRequestLogs container
    container_name = "TokenRequestLogs"
    partition_key_path = "/id"
    database.create_container_if_not_exists(
        id=container_name,
        partition_key=PartitionKey(path=partition_key_path)
    )
    print(f"Container '{container_name}' with partition key '{partition_key_path}' ensured.")
    
    # Record the migration execution
    migrations_container = database.get_container_client("__PyMigrations")
    migration_record = {
        "id": "003_add_token_request_logs",
        "applied_at": datetime.datetime.utcnow().isoformat()
    }
    migrations_container.upsert_item(migration_record)
    print("Migration '003_add_token_request_logs' recorded in '__PyMigrations'.")

if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"Error during migration: {e}")
