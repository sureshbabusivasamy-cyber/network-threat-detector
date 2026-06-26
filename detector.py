PROGRAM_NAME = "Network Threat Detector"
BRUTE_FORCE_LIMIT = 5
PORT_SCAN_LIMIT = 15
KNOWN_BAD_IPS = [
    "192.168.1.666",
    "10.0.0.254",
    "203.0.113.99"
]

SENSITIVE_PORTS = [22,23,3389,3306,5432]

failed_attempts = {}

critical_count = 0
warning_count = 0

def check_ip(ip):
    global critical_count
    if ip in KNOWN_BAD_IPS:
        print("ALEART ! BAD IP DETECTED",ip)
        critical_count= critical_count + 1
def check_port(ip,port,action):
    global warning_count
    if port in SENSITIVE_PORTS and action == "ALLOW":
        print("WARNING sensiiveport accessed:",port,"by",ip)
        warning_count = warning_count + 1
def check_brute_force(ip,action):
    global critical_count
    if action == "FAILED":
        if ip in failed_attempts:
            failed_attempts[ip]=failed_attempts[ip] + 1
        else:
            failed_attempts[ip]=1
        
        if failed_attempts[ip] >= BRUTE_FORCE_LIMIT:
            print("CRITCAL! Brute force attack from",ip,
            "| Failed attemps:", failed_attempts[ip])
            critical_count = critical_count + 1



def print_summary():
    total = critical_count + warning_count
    print("="*40)
    print(PROGRAM_NAME)
    print("="*40)
    print("Total alearts :",total)
    print("Critical alearts:",critical_count)
    print("Warnings :",warning_count)
    print("="*40)
    if total == 0:
        print("No threats detected!")
    else:
        print("Action required! Review alearts above")
    print("="*40)

def scan_log_file(filename):
    print("="*40)
    print(PROGRAM_NAME)
    print("=" * 40)
    print("Scanning file:", filename)
    print("=" * 40)
    with open(filename) as file:
        for line in file:
            line = line.strip()
            parts=line.split(",")

            ip=parts[0]
            port=int(parts[1])
            action=parts[2]

            check_ip(ip)
            check_port(ip,port,action)
            check_brute_force(ip,action)

    print("=" * 40)
    print("scan completed")
    print_summary()

scan_log_file("traffic.log")