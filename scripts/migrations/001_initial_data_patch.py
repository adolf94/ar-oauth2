import os
from azure.cosmos import CosmosClient, PartitionKey
import urllib3
import datetime

# Disable insecure request warnings for local emulator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Values default to the local Cosmos DB emulator settings from local.settings.json
ENDPOINT = os.environ.get("COSMOS_ENDPOINT", "https://localhost:8081/")
KEY = os.environ.get("COSMOS_KEY", "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==")
DATABASE_NAME = os.environ.get("COSMOS_DATABASE_NAME", "ArAuth")

def migrate():
    print(f"Connecting to Cosmos DB at {ENDPOINT}...")
    
    # Connection policy to bypass SSL verification for local emulator
    client = CosmosClient(ENDPOINT, KEY, connection_verify=False)
    
    # Create the database if it doesn't exist
    database = client.create_database_if_not_exists(id=DATABASE_NAME)
    print(f"Database '{DATABASE_NAME}' ensured.")

    # We will migrate the 'Clients' container to ensure the Telegram bot properties exist
    container_name = "Clients"
    
    # EF Core partition key for Clients is typically /id
    container = database.create_container_if_not_exists(
        id=container_name,
        partition_key=PartitionKey(path="/id")
    )
    
    print(f"Container '{container_name}' ensured. Starting data patch...")
    
    # Query all clients to apply a data patch
    query = "SELECT * FROM c"
    items = list(container.query_items(query=query, enable_cross_partition_query=True))
    
    migrated_count = 0
    for item in items:
        updated = False
        
        # Initialize Telegram properties if they do not exist
        if 'TelegramBotClientId' not in item:
            item['TelegramBotClientId'] = None
            updated = True
            
        if 'TelegramBotClientSecret' not in item:
            item['TelegramBotClientSecret'] = None
            updated = True
            
        if updated:
            # Replace the document in Cosmos DB with the new properties
            container.replace_item(item=item['id'], body=item)
            migrated_count += 1
            print(f"Migrated Client ID: {item.get('id')}")

    print(f"Migration completed successfully. Updated {migrated_count} client records.")
    
    # Record the migration execution
    migrations_container = database.get_container_client("__PyMigrations")
    migration_record = {
        "id": "001_initial_data_patch",
        "applied_at": datetime.datetime.utcnow().isoformat()
    }
    migrations_container.upsert_item(migration_record)
    print("Migration '001_initial_data_patch' recorded in '__PyMigrations'.")

if __name__ == "__main__":
    try:
        migrate()
    except Exception as e:
        print(f"Error during migration: {e}")
        print("Tip: Make sure you have installed the required package: pip install -r requirements.txt")
