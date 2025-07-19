# PhishEye - Phishing Email Analyzer (Linux + Python Version)

import os
import re
import sys
import tldextract
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import argparse
import hashlib

# ----------------------
# Load & Parse Email
# ----------------------
def parse_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

# ----------------------
# Extract Headers
# ----------------------
def extract_headers(msg):
    headers = {
        'From': msg['From'],
        'To': msg['To'],
        'Subject': msg['Subject'],
        'Reply-To': msg['Reply-To'],
        'Return-Path': msg['Return-Path'],
        'Authentication-Results': msg['Authentication-Results'],
        'Received': msg.get_all('Received', [])
    }
    return headers

# ----------------------
# Extract Links from HTML
# ----------------------
def extract_links(msg):
    links = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html = part.get_content()
                soup = BeautifulSoup(html, 'html.parser')
                for a in soup.find_all('a', href=True):
                    links.append((a.text.strip(), a['href']))
    return links

# ----------------------
# Analyze Link Mismatch
# ----------------------
def detect_link_mismatch(links):
    mismatches = []
    for text, href in links:
        if text and href:
            text_domain = tldextract.extract(text).domain
            href_domain = tldextract.extract(href).domain
            if text_domain and href_domain and text_domain != href_domain:
                mismatches.append((text, href))
    return mismatches

# ----------------------
# Check Attachments
# ----------------------
def detect_suspicious_attachments(msg):
    flagged = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if filename and filename.lower().endswith(('.exe', '.scr', '.js', '.vbs', '.bat', '.zip', '.rar')):
                flagged.append(filename)
    return flagged

# ----------------------
# Save Report
# ----------------------
def save_report(headers, links, mismatches, attachments, out_file):
    with open(out_file, 'w') as f:
        f.write("===== PhishEye Report =====\n\n")
        f.write("[Headers]\n")
        for k, v in headers.items():
            if isinstance(v, list):
                for item in v:
                    f.write(f"{k}: {item}\n")
            else:
                f.write(f"{k}: {v}\n")

        f.write("\n[Links]\n")
        for text, href in links:
            f.write(f"Text: {text} | URL: {href}\n")

        f.write("\n[Mismatched Links]\n")
        for text, href in mismatches:
            f.write(f"MISMATCH: Text: {text} → Href: {href}\n")

        f.write("\n[Flagged Attachments]\n")
        for att in attachments:
            f.write(f"Suspicious File: {att}\n")

        f.write("\n===== End of Report =====\n")

# ----------------------
# Main Execution
# ----------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PhishEye - Email Phishing Analyzer")
    parser.add_argument('-i', '--input', required=True, help="Path to .eml file")
    parser.add_argument('-o', '--output', default="report.txt", help="Output report file")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print("[!] File not found.")
        sys.exit(1)

    print("[*] Analyzing email...")
    msg = parse_email(args.input)
    headers = extract_headers(msg)
    links = extract_links(msg)
    mismatches = detect_link_mismatch(links)
    attachments = detect_suspicious_attachments(msg)

    print("[*] Saving report...")
    save_report(headers, links, mismatches, attachments, args.output)
    print(f"[+] Report saved as {args.output}")
