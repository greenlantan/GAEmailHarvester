#!/usr/bin/env python3

import re
import requests
import argparse
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import os
import sys
import random
import socket
import dns.resolver
from colorama import Fore, Style, init

# Initialize colorama
init()

# Banner
BANNER = f"""
{Fore.RED}
   ▄████  ▄▄▄       ███▄ ▄███▓ ▄▄▄▄    ▒█████   ██▓███  
  ██▒ ▀█▒▒████▄    ▓██▒▀█▀ ██▒▓█████▄ ▒██▒  ██▒▓██░  ██▒
 ▒██░▄▄▄░▒██  ▀█▄  ▓██    ▓██░▒██▒ ▄██▒██░  ██▒▓██░ ██▓▒
 ░▓█  ██▓░██▄▄▄▄██ ▒██    ▒██ ▒██░█▀  ▒██   ██░▒██▄█▓▒ ▒
 ░▒▓███▀▒ ▓█   ▓██▒▒██▒   ░██▒░▓█  ▀█▓░ ████▓▒░▒██▒ ░  ░
  ░▒   ▒  ▒▒   ▓▒█░░ ▒░   ░  ░░▒▓███▀▒░ ▒░▒░▒░ ▒▓▒░ ░  ░
   ░   ░   ▒   ▒▒ ░░  ░      ░▒░▒   ░   ░ ▒ ▒░ ░▒ ░     
 ░ ░   ░   ░   ▒   ░      ░    ░    ░ ░ ░ ░ ▒  ░░       
       ░       ░  ░       ░    ░          ░ ░           
{Style.RESET_ALL}
{Fore.YELLOW}GA Email-Harvester v2.0 | Advanced Email Scraping Tool{Style.RESET_ALL}
{Fore.CYAN}Developed for Kali Linux | Use Responsibly{Style.RESET_ALL}
"""

class EmailHarvester:
    def __init__(self):
        self.found_emails = set()
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        })
        self.proxies = None
        self.timeout = 10
        self.max_depth = 2
        self.threads = 5
        self.verbose = False

    def load_proxies(self, proxy_file):
        if proxy_file and os.path.exists(proxy_file):
            with open(proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            self.proxies = random.choice(proxies) if proxies else None
            if self.verbose:
                print(f"{Fore.GREEN}[+] Loaded {len(proxies)} proxies{Style.RESET_ALL}")

    def extract_emails(self, text):
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return set(re.findall(email_pattern, text))

    def get_page_content(self, url):
        try:
            if self.proxies:
                response = self.session.get(url, proxies={'http': self.proxies, 'https': self.proxies}, timeout=self.timeout)
            else:
                response = self.session.get(url, timeout=self.timeout)
            return response.text
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[-] Error fetching {url}: {e}{Style.RESET_ALL}")
            return None

    def scrape_page(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        if self.verbose:
            print(f"{Fore.BLUE}[*] Scraping {url}{Style.RESET_ALL}")

        content = self.get_page_content(url)
        if not content:
            return

        # Extract emails from page content
        emails = self.extract_emails(content)
        if emails:
            for email in emails:
                if email not in self.found_emails:
                    self.found_emails.add(email)
                    print(f"{Fore.GREEN}[+] Found email: {email}{Style.RESET_ALL}")

        # Parse links for further scraping
        soup = BeautifulSoup(content, 'html.parser')
        for link in soup.find_all('a', href=True):
            next_url = urljoin(url, link['href'])
            if self.is_valid_url(next_url, url):
                self.scrape_page(next_url)

    def is_valid_url(self, url, base_url):
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        
        # Skip non-http(s) URLs
        if parsed_url.scheme not in ('http', 'https'):
            return False
            
        # Skip URLs that go too deep
        if url.count('/') - 2 > self.max_depth + base_url.count('/') - 2:
            return False
            
        # Stay on the same domain
        if parsed_url.netloc != parsed_base.netloc:
            return False
            
        # Skip common non-html resources
        if any(parsed_url.path.endswith(ext) for ext in ('.pdf', '.jpg', '.png', '.js', '.css')):
            return False
            
        return True

    def guess_emails(self, domain):
        common_formats = [
            'first.last@{domain}',
            'firstl@{domain}',
            'flast@{domain}',
            'first@{domain}',
            'last@{domain}',
            'f.last@{domain}',
            'first_l@{domain}',
            'lastf@{domain}',
            'support@{domain}',
            'info@{domain}',
            'contact@{domain}',
            'admin@{domain}',
            'webmaster@{domain}'
        ]
        
        # Try to find names from website
        content = self.get_page_content(f"https://{domain}/about")
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            text = soup.get_text().lower()
            possible_names = re.findall(r'\b([a-z]{3,})\b', text)
            common_names = set(name for name in possible_names if len(name) > 3 and not name.isdigit())
            
            for name in common_names:
                common_formats.extend([
                    f'{name}@{domain}',
                    f'{name[0]}.{name}@{domain}',
                    f'{name}.{name[0]}@{domain}'
                ])
        
        # Generate possible emails
        possible_emails = [fmt.format(domain=domain) for fmt in common_formats]
        
        # Verify emails via SMTP/MX check
        verified_emails = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(self.verify_email, possible_emails))
            verified_emails = [email for email, valid in zip(possible_emails, results) if valid]
        
        return verified_emails

    def verify_email(self, email):
        if not email or '@' not in email:
            return False
            
        domain = email.split('@')[1]
        
        try:
            # Check MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            if not mx_records:
                return False
                
            # Try SMTP verification (without sending email)
            mx_record = str(mx_records[0].exchange)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((mx_record, 25))
                s.sendall(b"HELO example.com\r\n")
                response = s.recv(1024)
                if b"220" not in response:
                    return False
                    
                s.sendall(f"MAIL FROM: <test@example.com>\r\n".encode())
                response = s.recv(1024)
                if b"250" not in response:
                    return False
                    
                s.sendall(f"RCPT TO: <{email}>\r\n".encode())
                response = s.recv(1024)
                return b"250" in response
                
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Verification error for {email}: {e}{Style.RESET_ALL}")
            return False

    def save_results(self, output_file):
        if not self.found_emails:
            print(f"{Fore.RED}[-] No emails found to save{Style.RESET_ALL}")
            return
            
        with open(output_file, 'w') as f:
            for email in sorted(self.found_emails):
                f.write(email + '\n')
        print(f"{Fore.GREEN}[+] Saved {len(self.found_emails)} emails to {output_file}{Style.RESET_ALL}")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="GA Email-Harvester - Advanced Email Scraping Tool")
    parser.add_argument("-u", "--url", help="Target URL to scrape")
    parser.add_argument("-d", "--domain", help="Domain for email guessing")
    parser.add_argument("-o", "--output", default="emails.txt", help="Output file (default: emails.txt)")
    parser.add_argument("-p", "--proxy", help="Proxy file (one proxy per line)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("-m", "--max-depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    if not args.url and not args.domain:
        parser.print_help()
        sys.exit(1)
    
    harvester = EmailHarvester()
    harvester.verbose = args.verbose
    harvester.threads = args.threads
    harvester.max_depth = args.max_depth
    
    if args.proxy:
        harvester.load_proxies(args.proxy)
    
    if args.url:
        print(f"{Fore.CYAN}[*] Starting website scraping...{Style.RESET_ALL}")
        harvester.scrape_page(args.url)
    
    if args.domain:
        print(f"{Fore.CYAN}[*] Starting email guessing...{Style.RESET_ALL}")
        guessed_emails = harvester.guess_emails(args.domain)
        for email in guessed_emails:
            harvester.found_emails.add(email)
            print(f"{Fore.GREEN}[+] Guessed email: {email}{Style.RESET_ALL}")
    
    if harvester.found_emails:
        harvester.save_results(args.output)
    else:
        print(f"{Fore.RED}[-] No emails found{Style.RESET_ALL}")

if __name__ == "__main__":
    main()