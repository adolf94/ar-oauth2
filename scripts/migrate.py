import os
import sys
import glob
import importlib.util
from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError
import urllib3

# Disable insecure request warnings for local emulator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ENDPOINT = os.environ.get("COSMOS_ENDPOINT", "https://localhost:8081/")
KEY = os.environ.get("COSMOS_KEY", "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==")
DATABASE_NAME = os.environ.get("COSMOS_DATABASE_NAME", "ArAuth")

def get_applied_migrations():
    client = CosmosClient(ENDPOINT, KEY, connection_verify=False)
    try:
        database = client.get_database_client(DATABASE_NAME)
        container = database.get_container_client("__PyMigrations")
        # Query all applied migrations
        query = "SELECT c.id FROM c"
        items = list(container.query_items(query=query, enable_cross_partition_query=True))
        return set([item['id'] for item in items])
    except CosmosResourceNotFoundError:
        # Database or container doesn't exist yet, meaning no migrations have run
        return set()
    except Exception as e:
        print(f"Warning: Could not fetch applied migrations: {e}")
        return set()

def main():
    print("--- Atlas Rig Migration Runner ---")
    
    # Pre-check for dependencies
    try:
        import azure.cosmos
    except ImportError:
        print("Error: azure-cosmos package is missing. Please run: pip install -r scripts/migrations/requirements.txt")
        sys.exit(1)
        
    applied_migrations = get_applied_migrations()
    print(f"Found {len(applied_migrations)} applied migration(s).")
    
    migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
    if not os.path.isdir(migrations_dir):
        print(f"Error: Migrations directory not found at {migrations_dir}")
        sys.exit(1)
        
    migration_files = sorted(glob.glob(os.path.join(migrations_dir, "*.py")))
    
    pending_migrations = []
    for filepath in migration_files:
        filename = os.path.basename(filepath)
        migration_id = os.path.splitext(filename)[0]
        if migration_id not in applied_migrations and not filename.startswith("__"):
            pending_migrations.append((migration_id, filepath))
            
    if not pending_migrations:
        print("No pending migrations to run.")
        return
        
    print(f"Found {len(pending_migrations)} pending migration(s). Running them now...")
    
    for migration_id, filepath in pending_migrations:
        print(f"\n>>> Running {migration_id}...")
        
        # Dynamically import the migration script
        spec = importlib.util.spec_from_file_location(migration_id, filepath)
        module = importlib.util.module_from_spec(spec)
        sys.modules[migration_id] = module
        
        try:
            spec.loader.exec_module(module)
            if hasattr(module, 'migrate'):
                module.migrate()
                print(f"<<< {migration_id} completed.")
            else:
                print(f"Error: {migration_id} does not have a migrate() function.")
                sys.exit(1)
        except Exception as e:
            print(f"Error running migration {migration_id}: {e}")
            sys.exit(1)
            
    print("\nAll pending migrations executed successfully.")

if __name__ == "__main__":
    main()
