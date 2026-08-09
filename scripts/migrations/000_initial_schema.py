import os
from azure.cosmos import CosmosClient, PartitionKey
import urllib3
import datetime

# Disable insecure request warnings for local emulator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Values default to the local Cosmos DB emulator settings from local.settings.json
CONNECTION_STRING = os.environ.get("COSMOS_CONNECTION_STRING") or "AccountEndpoint=https://localhost:8081/;AccountKey=C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==;"
DATABASE_NAME = os.environ.get("COSMOS_DATABASE_NAME") or "ArAuth"

def migrate():
    print("Connecting to Cosmos DB...")
    
    # Connection policy to bypass SSL verification for local emulator
    client = CosmosClient.from_connection_string(conn_str=CONNECTION_STRING, connection_verify=False)
    
    # Create the database if it doesn't exist
    database = client.create_database_if_not_exists(id=DATABASE_NAME)
    print(f"Database '{DATABASE_NAME}' ensured.")

    # Define the schema based on AppDbContext.cs
    schema = [
        ("Clients", "/id"),
        ("Users", "/id"),
        ("Tokens", "/id"),
        ("RoleDefinitions", "/ClientId"),
        ("AuthCodes", "/id"),
        ("ApplicationScopes", "/ClientId"),
        ("UserClientScopes", "/UserId"),
        ("CrossAppTrusts", "/RequestingClientId"),
        ("Logs", "/id"),
        ("__PyMigrations", "/id")
    ]

    for container_name, partition_key_path in schema:
        # Create container with the specified partition key
        container = database.create_container_if_not_exists(
            id=container_name,
            partition_key=PartitionKey(path=partition_key_path)
        )
        print(f"Container '{container_name}' with partition key '{partition_key_path}' ensured.")

    # Record the migration execution
    migrations_container = database.get_container_client("__PyMigrations")
    migration_record = {
        "id": "000_initial_schema",
        "applied_at": datetime.datetime.utcnow().isoformat()
    }
    migrations_container.upsert_item(migration_record)
    print("Migration '000_initial_schema' recorded in '__PyMigrations'.")

if __name__ == "__main__":
    try:
        migrate()
        print("Schema migration completed successfully.")
    except Exception as e:
        print(f"Error during migration: {e}")
        print("Tip: Make sure you have installed the required package: pip install -r requirements.txt")
