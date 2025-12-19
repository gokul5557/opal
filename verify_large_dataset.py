
import subprocess
import json
import sys

# Testing user_1 in Org_1 (who we forced to be msp_admin or admin in generation script)
USER_EMAIL = "user_1@org_1.com"
TEST_PATH = "/api/billing" 
# Assuming 'msp_admin' or 'admin' or 'billing_admin' has access to this.
# Note: In generator, user_1 is assigned 'msp_admin' or 'admin'.
# 'msp_admin' has access to /api/org_administrators, /api/organization ... but maybe NOT /api/billing?
# Let's check sagaid_data.json: msp_admin prefixes: ["/api/org_administrators", ..., "/api/email_client"]
# Does it have billing?
# 'access_role_org_admin' has '/api/billing'.
# 'access_role_billing_admin' has '/api/billing'.
# 'access_role_msp_admin' DOES NOT seem to have '/api/billing' in the list I saw earlier.
# So let's test a path generic to admins, like '/api/organization'.

TEST_PATH_GENERIC = "/api/organization"

def run_opa_eval(expression):
    cmd = [
        "opa", "eval",
        "-d", "policies",
        "-d", "policy_data/global.json",
        "-d", "policy_data/organizations",
        "-I", # input from stdin
        expression
    ]
    return cmd

def verify_access():
    print(f"Verifying access for {USER_EMAIL} to {TEST_PATH_GENERIC}...")
    
    input_data = {
        "input": {
            "user": USER_EMAIL,
            "path": TEST_PATH_GENERIC,
            "method": "read"
        }
    }
    
    cmd = run_opa_eval("data.policies.apisix.policy.allow")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input=json.dumps(input_data))
        
        if process.returncode != 0:
            print(f"OPA Error: {stderr}")
            return
            
        result = json.loads(stdout)
        # OPA eval returns {"result": [{"expressions": [{"value": true/false}] }]}
        
        if not result.get("result"):
             print("No result from OPA")
             return

        allowed = result["result"][0]["expressions"][0]["value"]
        
        print(f"Access Allowed: {allowed}")
        
        if allowed:
            print("[PASS] User has access.")
        else:
            print("[FAIL] User denied access.")
            # Debug: check config
            verify_config()
            
    except Exception as e:
        print(f"Execution Error: {e}")

def verify_config():
    print("debugging config...")
    # Use escaped double quotes for Rego strings
    cmd = run_opa_eval("data.policies.common.inheritance.get_effective_config_merged_with_user(\"access\", input.user)")
    input_data = {"input": {"user": USER_EMAIL}}

    
    process = subprocess.run(cmd, input=json.dumps(input_data), text=True, capture_output=True)
    print(process.stdout)

if __name__ == "__main__":
    verify_access()
