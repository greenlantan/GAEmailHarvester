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
import threading

# Initialize colorama
init()

# Thread lock for thread-safe operations
email_lock = threading.Lock()
visited_urls_lock = threading.Lock()  # Added lock for visited_urls

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
{Fore.YELLOW}GAEmailHarvester v2.1 | Robust Email Scraping Tool{Style.RESET_ALL}
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
        self.proxy_list = []
        self.timeout = 10
        self.max_depth = 2
        self.threads = 5
        self.verbose = False

    def load_proxies(self, proxy_file):
        # ...existing code...

    def get_random_proxy(self):
        return random.choice(self.proxy_list) if self.proxy_list else None

    def extract_emails(self, text):
        # ...existing code...

    def get_page_content(self, url):
        # ...existing code...

    def scrape_page(self, url, current_depth=0):
        with visited_urls_lock:  # Ensure thread-safe access to visited_urls
            if url in self.visited_urls or current_depth > self.max_depth:
                return
            self.visited_urls.add(url)

        if self.verbose:
            print(f"{Fore.BLUE}[*] Scraping {url} (Depth: {current_depth}){Style.RESET_ALL}")

        content = self.get_page_content(url)
        if not content:
            return

        # Extract emails
        emails = self.extract_emails(content)
        with email_lock:
            for email in emails:
                if email not in self.found_emails:
                    self.found_emails.add(email)
                    print(f"{Fore.GREEN}[+] Found email: {email}{Style.RESET_ALL}")

        # Crawl links if not at max depth
        if current_depth < self.max_depth:
            soup = BeautifulSoup(content, 'html.parser')
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if self.is_valid_url(next_url, url):
                        executor.submit(self.scrape_page, next_url, current_depth + 1)

    def is_valid_url(self, url, base_url):
        # ...existing code...

    def verify_email(self, email):
        if not email or '@' not in email:
            return False
            
        domain = email.split('@')[1]
        
        try:
            # Check MX records
            mx_records = dns.resolver.resolve(domain, 'MX', lifetime=self.timeout)  # Added timeout
            if not mx_records:
                return False
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return False
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] DNS error for {email}: {e}{Style.RESET_ALL}")
            return False

    def save_results(self, output_file):
        if not self.found_emails:
            if self.verbose:
                print(f"{Fore.RED}[-] No emails found to save{Style.RESET_ALL}")
            return
            
        try:
            with open(output_file, 'w') as f:
                for email in sorted(self.found_emails):
                    f.write(email + '\n')
            if self.verbose:
                print(f"{Fore.GREEN}[+] Saved {len(self.found_emails)} emails to {output_file}{Style.RESET_ALL}")
        except IOError as e:
            print(f"{Fore.RED}[-] File save error: {e}{Style.RESET_ALL}")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="GAEmailHarvester - Robust Email Scraping Tool")
    # ...existing code...

    if args.domain:
        print(f"{Fore.CYAN}[*] Starting email verification...{Style.RESET_ALL}")
        # Implement email guessing logic here (currently missing)

    harvester.save_results(args.output)

if __name__ == "__main__":
    main()
