import models
import sync

def init():
    print("Initializing Database...")
    models.init_db()
    print("Importing data from JSON...")
    sync.import_from_json()
    print("Done.")

if __name__ == "__main__":
    init()
