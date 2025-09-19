#!/usr/bin/env python3
"""
analyse_auth.py
Analyse simple des tentatives SSH échouées dans auth.log.

Fonctions :
 - lit un fichier de log (par défaut /var/log/auth.log)
 - détecte les lignes "Failed password" ou "Invalid user"
 - compte les IPs les plus actives
 - extrait un CSV résumé (ip, count, first_seen, last_seen)

Usage :
    python3 analyse_auth.py                 # utilise /var/log/auth.log
    python3 analyse_auth.py --file my.log   # utilise my.log
    python3 analyse_auth.py --top 20        # affiche top 20 ips
    python3 analyse_auth.py --out result.csv

Important :
 - Utilise ce script uniquement sur des logs dont tu as la permission.
 - Le format des logs peut varier selon la distro; adapte la regex si nécessaire.
"""
from collections import defaultdict, Counter
import re
import argparse
import csv
from datetime import datetime

# Pattern basique pour capturer IPs dans les lignes d'échec SSH
# Exemples de lignes ciblées :
# "Apr 10 12:34:56 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2"
# "Apr 10 12:35:01 host sshd[1234]: Failed password for user root from 5.6.7.8 port 2222 ssh2"
PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd.*(?:Failed password|Invalid user).*from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def parse_line(line, year=None):
    m = PATTERN.search(line)
    if not m:
        return None
    month = MONTHS.get(m.group('month'), 0)
    day = int(m.group('day'))
    timestr = m.group('time')
    ip = m.group('ip')
    # build a datetime for ordering (year needed; assume current year if not given)
    if year is None:
        year = datetime.now().year
    try:
        dt = datetime(year, month, day, *map(int, timestr.split(':')))
    except Exception:
        dt = None
    return ip, dt

def analyze_log(path, top_n=10):
    counts = Counter()
    first_seen = {}
    last_seen = {}
    total_lines = 0
    matched_lines = 0

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1
            res = parse_line(line)
            if res:
                matched_lines += 1
                ip, dt = res
                counts[ip] += 1
                if ip not in first_seen or (dt and dt < first_seen[ip]):
                    first_seen[ip] = dt
                if ip not in last_seen or (dt and dt > last_seen[ip]):
                    last_seen[ip] = dt

    return {
        'total_lines': total_lines,
        'matched_lines': matched_lines,
        'counts': counts,
        'first_seen': first_seen,
        'last_seen': last_seen
    }

def save_csv(path, counts, first_seen, last_seen):
    with open(path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ip','count','first_seen','last_seen'])
        for ip, cnt in counts.most_common():
            fs = first_seen.get(ip)
            ls = last_seen.get(ip)
            writer.writerow([ip, cnt, fs.isoformat() if fs else '', ls.isoformat() if ls else ''])
    print(f"[+] CSV saved to {path}")

def pretty_print_summary(result, top_n=10):
    print("=== Log analysis summary ===")
    print(f"Total lines scanned: {result['total_lines']}")
    print(f"Lines matched (SSH failures): {result['matched_lines']}")
    print("\nTop IPs by failed attempts:")
    for ip, cnt in result['counts'].most_common(top_n):
        fs = result['first_seen'].get(ip)
        ls = result['last_seen'].get(ip)
        print(f" - {ip:15} | attempts: {cnt:4} | first: {fs} | last: {ls}")
    print("============================")

def main():
    parser = argparse.ArgumentParser(description='Analyse basique des échecs SSH dans auth.log')
    parser.add_argument('--file', '-f', default='/var/log/auth.log', help='Fichier de log à analyser')
    parser.add_argument('--top', '-t', type=int, default=10, help='Nombre d\'IPs à afficher')
    parser.add_argument('--out', '-o', default=None, help='Exporter un CSV résumé')
    args = parser.parse_args()

    try:
        res = analyze_log(args.file, top_n=args.top)
    except FileNotFoundError:
        print(f"Fichier introuvable : {args.file}")
        return

    pretty_print_summary(res, top_n=args.top)

    if args.out:
        save_csv(args.out, res['counts'], res['first_seen'], res['last_seen'])

if __name__ == '__main__':
    main()
