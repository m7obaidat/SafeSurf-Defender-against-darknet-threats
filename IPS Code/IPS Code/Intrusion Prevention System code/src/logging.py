import redis 
import json
import time
import os 
from datetime import datetime
r = redis.Redis(
    host= '128.85.32.123',
    port =6379,
    username='safesurf',
    password='MIAY$003',
    decode_responses=True
)
# JSON Stats
def load_or_initialize_stats():
    stats_file = 'current_ID.json'
    if os.path.exists(stats_file):
        with open(stats_file, 'r') as f:
            return json.load(f)
    else:
        stats = {'ID':1}
        with open(stats_file, 'w') as f:
            json.dump(stats, f)
        return stats
        
# Check connection
try:
    pong = r.ping()
    print("Connected to Redis:", pong)
except redis.exceptions.ConnectionError as e:
    print("Failed to connect to Redis:", e)
    exit(1)

stats = load_or_initialize_stats()
ID = stats.get('ID')

def Log_Traffic(data):
    global ID, stats
    
    flow_json = json.dumps(data)
    key = f"{data['Src IP']}:{data['Src Port']}->{data['Dst IP']}:{data['Dst Port']}@{data['Timestamp']}"
    r.set(key, flow_json)
    r.publish('traffic_updates', flow_json)
    ID +=1
    stats['ID'] = ID
    with open('current_ID.json', 'w') as f:
        json.dump(stats, f)
        

def get_whitelist(ip):
    # Get whitelist data from Redis and parse it
    whitelist_data = r.get("whitelist")
    if not whitelist_data:
        return False

    whitelist = json.loads(whitelist_data)

    # Check if the IP exists in the whitelist
    if ip in whitelist:
        expiry_date_str = whitelist[ip].get('expiry_date')
        description = whitelist[ip].get('description', 'No description')

        # Convert expiry_date string to datetime object
        expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d")
        current_date = datetime.now()

        # Check if current date is before expiry date
        if current_date <= expiry_date:
           
            return True
        else:
            return False
    else:
        return False

def get_blacklist(ip=None, port=None):
    # Get blacklist data from Redis and parse it
    blacklist_data = r.get("blacklist")
    if not blacklist_data:
        print("Blacklist not found in Redis.")
        return False

    blacklist = json.loads(blacklist_data)

    # Check for IP blacklisting
    if ip:
        ip_entry = blacklist.get("ips", {}).get(ip)
        if ip_entry:
            expiry_date_str = ip_entry.get('expiry_date')
            if expiry_date_str:  # If expiry_date is set
                expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d")
                if datetime.now() > expiry_date:
                    return False
            return True

    # Check for Port blacklisting
    if port:
        port_str = str(port)
        port_entry = blacklist.get("ports", {}).get(port_str)
        if port_entry:
            expiry_date_str = port_entry.get('expiry_date')
            if expiry_date_str:  # If expiry_date is set
                expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d")
                if datetime.now() > expiry_date:
                    return False
            return True

    # If no IP or port is given, check ICMP block status
    if ip is None and port is None:
        return blacklist.get("block_icmp", False)

    return False
