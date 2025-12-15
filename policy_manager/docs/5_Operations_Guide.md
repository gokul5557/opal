# 05. Operations & Testing Guide

## 5.1 Starting the Stack

The system runs via Docker Compose in the `opal_testing` directory.

```bash
cd ~/oidc+apisix/python/opal_testing
docker-compose up -d
```

**Services**:
*   `opal_server`: Port 7002. Syncs policy/data.
*   `opal_client`: Port 8181 (OPA) & 7000 (Callbacks).
*   `broadcast_channel`: Postgres (for OPAL sync).

**Policy Manager UI**:
Run locally:
```bash
cd policy_poc
python3 policy_manager/app.py
```
Access at `http://localhost:8182`.

## 5.2 Verification & Testing

### A. The "Test Policy" UI
1.  Go to the Policy Manager Dashboard (`/org/gokul`).
2.  Click **Test Policy**.
3.  Enter User: `gokul@sagasoft.io`.
4.  Enter Path: `/mail/inbox`.
5.  Click **Run Test**.
    *   **Result**: Displays Allow/Deny.
    *   **Trace**: Shows exactly which policy layer granted the permission.

### B. Command Line Testing (Local Script)
We provided `verify_all_policies.py` for comprehensive regression testing of the Python App's logic.

```bash
python3 verify_all_policies.py
```

### C. Direct Container Testing (Integration Test)
To verify the **Live OPA Container** (ensuring OPAL Sync worked):

```bash
python3 test_opal_container.py
```
This sends a request to `localhost:8181` (The Docker Container). If this passes, your Production environment is ready.

## 5.3 Troubleshooting

### Issue: "500 Internal Server Error" during Test
*   **Cause**: Likely a **Recursion Error** in Rego.
*   **Diagnosis**: Check the console output of the Python app. OPA will print a JSON error with `code: rego_recursion_error`.
*   **Fix**: Ensure `inheritance.rego` imports specific data keys (`import data.global_policies`) rather than using `object.get(data, ...)` on the root.

### Issue: "Test Policy" button blurs screen but shows nothing
*   **Cause**: UI Z-Index issue.
*   **Fix**: Refresh the page. We updated the template to force Modals to the top layer.

### Issue: Updates to data.json not showing in UI
*   **Cause**: The Python app reads `data.json` from disk. Ensure you saved the file.
*   **Note**: The Python App and the Running OPA Container might be slightly out of sync if OPAL hasn't pushed the update to the container yet (usually takes <1 sec).

## 5.4 Recreating the Environment
To reset everything to a clean state:
1.  Delete `data.json` (or revert to factory default).
2.  Restart containers: `docker-compose restart`.
3.  The OPAL Server will pull the latest fresh state from the Git Repo defined in `docker-compose.yml`.
