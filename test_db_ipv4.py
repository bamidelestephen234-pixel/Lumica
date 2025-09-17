import os
import sys
from datetime import datetime
import psycopg2
from urllib.parse import urlparse

# Get DB URL from streamlit secrets
db_url = "postgresql://postgres.hiijvgzblottszoulseh:UClfhRuXQr0h8S6c@aws-1-eu-west-2.pooler.supabase.com:5432/postgres?sslmode=require"

# Parse the database URL to extract host
parsed = urlparse(db_url)
db_params = {
    'dbname': parsed.path[1:],
    'user': parsed.username,
    'password': parsed.password,
    'host': parsed.hostname,
    'port': parsed.port,
    # Force IPv4
    'hostaddr': None,  # Will be set after DNS lookup
}

print(f"Testing connection to {parsed.hostname}...")

# Try to resolve the hostname to IPv4
import socket
try:
    # Force IPv4 by setting family=socket.AF_INET
    addrinfo = socket.getaddrinfo(parsed.hostname, parsed.port, family=socket.AF_INET)
    if addrinfo:
        db_params['hostaddr'] = addrinfo[0][4][0]
        print(f"Resolved {parsed.hostname} to IPv4 address: {db_params['hostaddr']}")
except socket.gaierror as e:
    print(f"Failed to resolve hostname: {e}")
    sys.exit(1)

try:
    print("\nTrying to connect to database...")
    conn = psycopg2.connect(**db_params)
    print("✅ Successfully connected to database!")
    
    # Test a simple query
    cur = conn.cursor()
    cur.execute("SELECT version();")
    version = cur.fetchone()
    print(f"\nDatabase version: {version[0]}")
    
    cur.close()
    conn.close()
    
except Exception as e:
    print("❌ Failed to connect to database:")
    print(str(e))
    sys.exit(1)