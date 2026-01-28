import sqlite3
import json
import os

DB_PATH = 'policies.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Organization Table
    c.execute('''CREATE TABLE IF NOT EXISTS organization
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  org_id TEXT UNIQUE NOT NULL,
                  name TEXT,
                  config_json TEXT DEFAULT '{}')''')
    
    # User Table
    c.execute('''CREATE TABLE IF NOT EXISTS user
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  org_id TEXT NOT NULL,
                  roles TEXT,
                  status TEXT DEFAULT 'active',
                  meta_json TEXT DEFAULT '{}',
                  FOREIGN KEY(org_id) REFERENCES organization(org_id))''')
    
    # Global Policy Table
    c.execute('''CREATE TABLE IF NOT EXISTS global_policy
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  category TEXT NOT NULL,
                  name TEXT NOT NULL,
                  definition_json TEXT NOT NULL)''')
    
    # Global Role Table
    c.execute('''CREATE TABLE IF NOT EXISTS global_role
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  role_name TEXT UNIQUE NOT NULL,
                  assigned_policies_json TEXT NOT NULL)''')
    
    conn.commit()
    conn.close()

class DBObject:
    """Helper to convert sqlite3.Row to dot-accessible object for templates."""
    def __init__(self, row):
        for key in row.keys():
            setattr(self, key, row[key])
        # Special logic for roles (comma-separated string to list)
        if hasattr(self, 'roles') and self.roles:
            self.role_list = self.roles.split(",")
        else:
            self.role_list = []
            
        # Parse JSON fields
        if hasattr(self, 'config_json'):
            self.config = json.loads(self.config_json)
        if hasattr(self, 'meta_json'):
            self.meta = json.loads(self.meta_json)
