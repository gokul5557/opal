
import json

DATA_FILE = "data.json"

def cleanup():
    with open(DATA_FILE, "r") as f:
        data = json.load(f)

    # Clean Org_1 groups
    org = data["organizations"].get("Org_1")
    if not org:
        print("Org_1 not found")
        return

    groups_to_delete = []
    for gname in org.get("groups", {}).keys():
        if gname.startswith("Plan_") or gname.startswith("Role_"):
            groups_to_delete.append(gname)

    for g in groups_to_delete:
        del org["groups"][g]
        print(f"Deleted Legacy Group: {g}")

    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print("Cleanup Complete. Legacy Groups Removed.")

if __name__ == "__main__":
    cleanup()
