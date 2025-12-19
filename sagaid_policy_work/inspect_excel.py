import pandas as pd
import os

file_path = "/home/gokul/oidc+apisix/python/opal_testing/sagaid_roles.xlsx"

if not os.path.exists(file_path):
    print(f"Error: File not found at {file_path}")
    exit(1)

try:
    df = pd.read_excel(file_path)
    print("--- COLUMNS ---")
    for col in df.columns:
        print(f"'{col}'")
    print("\n--- ROW 0 (Potential Headers) ---")
    print(df.iloc[0].tolist())
    
    print("\n--- ROW SAMPLE ---")
    print(df.iloc[0:5, 0:2].to_string()) # Print first 2 columns of first 5 rows to see Feature names

except Exception as e:
    print(f"Error reading Excel: {e}")
