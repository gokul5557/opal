import sys
import os
sys.path.append(os.path.join(os.getcwd(), "policy_manager"))
from data_access import rename_org, load_data

def test_rename():
    print("Testing Rename Org logic...")
    
    # 1. Rename Org_1 -> Org_Renamed
    success, msg = rename_org("Org_1", "Org_Renamed")
    print(f"Rename Org_1 -> Org_Renamed: {success} ({msg})")
    
    if not success:
        print("Failed to rename! Check data.json state.")
        return

    data = load_data()
    if "Org_Renamed" in data["organizations"] and "Org_1" not in data["organizations"]:
        print("PASS: Org key updated.")
    else:
        print("FAIL: Org key not updated properly.")

    # 2. Rename Back
    success, msg = rename_org("Org_Renamed", "Org_1")
    print(f"Rename Org_Renamed -> Org_1: {success} ({msg})")
    
    data = load_data()
    if "Org_1" in data["organizations"] and "Org_Renamed" not in data["organizations"]:
        print("PASS: Reverted successfully.")
    else:
        print("FAIL: Revert failed.")

if __name__ == "__main__":
    test_rename()
