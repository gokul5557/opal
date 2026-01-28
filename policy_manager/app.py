from flask import Flask, render_template, request, redirect, url_for, flash
import models
import sync
import os
import json
import subprocess

app = Flask(__name__)
app.secret_key = "supersecret"

@app.before_first_request
def setup():
    models.init_db()
    # Check if we need to seed
    conn = models.get_db_connection()
    count = conn.execute("SELECT count(*) FROM organization").fetchone()[0]
    conn.close()
    if count == 0:
        sync.import_from_json()

@app.route("/")
def index():
    conn = models.get_db_connection()
    rows = conn.execute("SELECT * FROM organization").fetchall()
    orgs = [models.DBObject(r) for r in rows]
    # Fetch user count for each org
    for org in orgs:
        org.user_count = conn.execute("SELECT count(*) FROM user WHERE org_id=?", (org.org_id,)).fetchone()[0]
    conn.close()
    return render_template("index.html", orgs=orgs)

@app.route("/org/<org_id>")
def org_details(org_id):
    conn = models.get_db_connection()
    row = conn.execute("SELECT * FROM organization WHERE org_id=?", (org_id,)).fetchone()
    if not row:
        conn.close()
        return "Not Found", 404
    org = models.DBObject(row)
    
    user_rows = conn.execute("SELECT * FROM user WHERE org_id=?", (org_id,)).fetchall()
    users = [models.DBObject(r) for r in user_rows]
    conn.close()
    return render_template("org_details.html", org=org, users=users)

@app.route("/user/edit/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    conn = models.get_db_connection()
    roles = request.form.get("roles")
    status = request.form.get("status")
    
    # Get org_id for redirect
    user_row = conn.execute("SELECT org_id, email FROM user WHERE id=?", (user_id,)).fetchone()
    if not user_row:
        conn.close()
        return "User not found", 404
    
    conn.execute("UPDATE user SET roles=?, status=? WHERE id=?", (roles, status, user_id))
    conn.commit()
    conn.close()
    
    flash(f"Updated user {user_row['email']}", "success")
    return redirect(url_for('org_details', org_id=user_row['org_id']))

@app.route("/user/add/<org_id>", methods=["POST"])
def add_user(org_id):
    conn = models.get_db_connection()
    email = request.form.get("email")
    name = request.form.get("name")
    roles = request.form.get("roles")
    status = request.form.get("status", "active")
    
    if not email:
        conn.close()
        flash("Email is required", "warning")
        return redirect(url_for('org_details', org_id=org_id))
        
    try:
        meta = json.dumps({"name": name, "aliases": []})
        conn.execute("INSERT INTO user (email, org_id, roles, status, meta_json) VALUES (?, ?, ?, ?, ?)",
                    (email, org_id, roles, status, meta))
        conn.commit()
        flash(f"User {email} added successfully", "success")
    except Exception as e:
        flash(f"Error adding user: {str(e)}", "warning")
    finally:
        conn.close()
        
    return redirect(url_for('org_details', org_id=org_id))

@app.route("/sync/import")
def run_import():
    sync.import_from_json()
    flash("Successfully imported all policies from JSON files", "success")
    return redirect(url_for('index'))

@app.route("/sync/export", methods=["POST"])
def run_export():
    sync.export_to_json()
    
    # Git Push
    try:
        # Check if it's a git repo
        if os.path.exists(os.path.join(sync.POLICY_DATA_DIR, "../.git")):
            subprocess.run(["git", "add", "."], cwd=sync.POLICY_DATA_DIR, check=True)
            subprocess.run(["git", "commit", "-m", "Policy update from Dashboard"], cwd=sync.POLICY_DATA_DIR, check=True)
            subprocess.run(["git", "push"], cwd=sync.POLICY_DATA_DIR, check=True)
            flash("Successfully exported to JSON and pushed to Git!", "success")
        else:
            flash("Export successful to JSON (No Git repository found in mail_service)", "warning")
    except Exception as e:
        flash(f"Export successful, but Git Push failed: {str(e)}", "warning")
        
    return redirect(url_for('index'))

@app.route("/org/test/<org_id>")
def test_org_policy(org_id):
    import tester
    results = tester.run_tests_for_org(org_id)
    if isinstance(results, dict) and "error" in results:
        flash(f"Test failed: {results['error']}", "warning")
        return redirect(url_for('org_details', org_id=org_id))
    
    # Calculate stats
    passed = sum(1 for r in results if r['passed'])
    total = len(results)
    
    return render_template("test_results.html", org_id=org_id, results=results, passed=passed, total=total)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
