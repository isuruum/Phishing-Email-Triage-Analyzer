import werkzeug
from flask_wtf.csrf import CSRFProtect
import sqlite3
import json
import os
import hashlib
import re
import time
import requests
import base64
import io
import threading
import atexit
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, g, request, redirect, url_for, render_template, jsonify, flash, send_from_directory, Response
import bleach
from defusedxml import ElementTree as ET  # XXE protection
from datetime import datetime
from werkzeug.utils import secure_filename
from email import parser as email_parser
from email.header import decode_header, make_header
from bs4 import BeautifulSoup
from urllib.parse import quote, unquote
from dotenv import load_dotenv


def configure():
    load_dotenv()


configure()

# -----------------------------------------------------------------------------
# Program: Phishing Email Triage Analyzer
# Version: 8.1 (Stable) (Supports .eml & .msg files)
# Description: A Python Flask-based web app to analyze email files for threats using VirusTotal
# Author: Isuru Madurapperuma
# -----------------------------------------------------------------------------

# --- Configuration ---
DATABASE = 'database.db'
ALLOWED_EXTENSIONS = {'eml', 'msg'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB maximum file size
ALLOWED_HTML_TAGS = ['p', 'br', 'div', 'span', 'a', 'strong', 'em', 'u', 'font', 'img', 'table', 'tr', 'td', 'th', 'tbody', 'thead', 'tfoot', 'li', 'ul', 'ol', 'pre', 'code']
ALLOWED_HTML_ATTRIBUTES = {'*': ['class', 'id', 'style'], 'a': ['href', 'title'], 'img': ['src', 'alt', 'width', 'height'], 'font': ['color', 'face', 'size']}
ANALYSIS_LOCK = threading.Lock()  # Lock for race condition prevention


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['VIRUSTOTAL_API_KEY'] = os.getenv('VIRUSTOTAL_API_KEY')
app.config['GEMINI_API_KEY'] = os.getenv('GEMINI_API_KEY')

csrf = CSRFProtect(app)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https: http: data: blob:;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    if 'Server' in response.headers:
        del response.headers['Server']
    response.headers['Server'] = ''
    return response


GEMINI_MODEL = "gemini-2.5-flash" #You can change this to any other Gemini model if needed
vt_api_lock = threading.Lock()
# Initialize a ThreadPoolExecutor to limit concurrent analysis threads
analysis_executor = ThreadPoolExecutor(max_workers=5)
atexit.register(lambda: analysis_executor.shutdown(
    wait=False, cancel_futures=True))

# --- Database Management ---


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=60)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Creates the new normalized table structure."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 1. Master Session Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_time TEXT NOT NULL,
                uploaded_filename TEXT,
                subject TEXT,
                sender TEXT,
                receiver TEXT,
                vt_score TEXT, -- Stores overall counts {"url_flags": 0, ...}
                status TEXT NOT NULL DEFAULT 'PENDING'
            )
        """)

        # 2. Artifacts Table (URLs, Hashes, IPs)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                type TEXT, -- 'url', 'file_hash', 'ip'
                value TEXT,
                filename TEXT, -- Only for attachments
                vt_result TEXT,
                vt_info TEXT, -- Detailed JSON from VT
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE
            )
        """)

        # 3. Headers Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_headers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                header_key TEXT,
                header_value TEXT,
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE
            )
        """)

        # 4. Content Table (HTML Body)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_content (
                session_id INTEGER PRIMARY KEY,
                body_html TEXT,
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE
            )
        """)

        # 5. VT Report Cache Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vt_report_cache (
                resource_id TEXT PRIMARY KEY,
                resource_type TEXT,
                report_json TEXT,
                cached_at TEXT
            )
        """)

        # 6. VT API Logs Table (Local Tracking)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vt_api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                endpoint TEXT,
                resource TEXT
            )
        """)
        db.commit()

# --- Helper Functions ---


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def decode_mime_header(header_val):
    if not header_val:
        return "N/A"
    try:
        return str(make_header(decode_header(header_val)))
    except:
        return str(header_val)


def validate_ipv4(ip_string):
    """Validates IPv4 address format with proper range checking."""
    try:
        parts = ip_string.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except:
        return False


def sanitize_html_content(html_content):
    """Sanitizes HTML content to prevent XSS attacks."""
    if not html_content:
        return ""
    return bleach.clean(
        html_content,
        tags=ALLOWED_HTML_TAGS,
        attributes=ALLOWED_HTML_ATTRIBUTES,
        strip=True
    )


def sanitize_error_message(error_str):
    """Sanitizes error messages to prevent information disclosure."""
    # Return generic message without exposing internal details
    if isinstance(error_str, str) and len(error_str) > 100:
        return "An error occurred during analysis. Please check the submission status."
    return "An error occurred during analysis."


def parse_msg_safely(file_bytes):
    """Safely parses MSG files with XXE protection.
    
    Uses defusedxml to prevent XXE attacks. Note: extract-msg library
    may use XML internally for OLE2 parsing, so defusedxml is imported
    as a defense-in-depth measure.
    """
    try:
        import extract_msg
        # Parse from BytesIO with size limit to prevent DoS
        msg = extract_msg.openMsg(io.BytesIO(file_bytes))
        return msg
    except ImportError:
        raise Exception("extract-msg library missing. Run: pip install extract-msg")
    except Exception as e:
        raise Exception(f"MSG parsing error: Invalid or corrupted MSG file")

# --- VirusTotal Functions---


def log_vt_request(endpoint, resource):
    """Logs outgoing VT API requests to local DB for usage tracking."""
    try:
        db = get_db()
        db.execute("INSERT INTO vt_api_logs (timestamp, endpoint, resource) VALUES (?, ?, ?)",
                   (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), endpoint, str(resource)[:255]))
        db.commit()
    except Exception:
        pass


def check_vt_url(url):
    log_vt_request('url_check', url)
    vt_result = {"flags": 0, "first_seen": "N/A",
                 "category": "N/A", "reputation": "N/A"}
    try:
        url_id = base64.urlsafe_b64encode(
            url.strip().encode()).decode().strip("=")
        headers = {
            'x-apikey': app.config['VIRUSTOTAL_API_KEY'], 'Accept': 'application/json'}
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            attr = data.get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            vt_result["flags"] = stats.get('malicious', 0)
            vt_result["reputation"] = attr.get('reputation', 0)
            if attr.get('first_submission_date'):
                vt_result["first_seen"] = datetime.fromtimestamp(
                    attr['first_submission_date']).strftime('%Y-%m-%d')
            cats = [res.get('category', 'N/A')
                    for res in attr.get('last_analysis_results', {}).values()]
            if 'malicious' in cats:
                vt_result["category"] = "Malicious/Phishing"
            elif 'suspicious' in cats:
                vt_result["category"] = "Suspicious"
            else:
                vt_result["category"] = "Clean/Harmless"
        elif response.status_code == 404:
            # URL not found, submit for scanning (No scans were done for the URL, our scan will be first scan, the First and last seen will be our scanned date)
            scan_url = "https://www.virustotal.com/api/v3/urls"
            scan_resp = requests.post(scan_url, headers=headers, data={
                                      'url': url}, timeout=10)
            if scan_resp.status_code == 200:
                vt_result["category"] = "Analysis Queued"
                # Poll for analysis completion to get immediate results for fresh URLs
                try:
                    analysis_id = scan_resp.json()['data']['id']
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    # Poll up to 12 times (60 seconds)
                    for _ in range(12):
                        time.sleep(5)
                        an_resp = requests.get(
                            analysis_url, headers=headers, timeout=10)
                        if an_resp.status_code == 200:
                            an_attr = an_resp.json().get('data', {}).get('attributes', {})
                            if an_attr.get('status') == 'completed':
                                vt_result["flags"] = an_attr.get(
                                    'stats', {}).get('malicious', 0)
                                vt_result["category"] = "Scanned (Fresh)"
                                vt_result["first_seen"] = datetime.now().strftime(
                                    '%Y-%m-%d')
                                vt_result["reputation"] = 0
                                break
                except Exception:
                    pass
        return vt_result
    except:
        return vt_result


def check_vt_hash(hash_value):
    log_vt_request('file_check', hash_value)
    headers = {
        'x-apikey': app.config['VIRUSTOTAL_API_KEY'], 'Accept': 'application/json'}
    api_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        if response.status_code == 404:
            return None
        return 0
    except:
        return 0


def check_vt_ip(ip):
    log_vt_request('ip_check', ip)
    headers = {
        'x-apikey': app.config['VIRUSTOTAL_API_KEY'], 'Accept': 'application/json'}
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        if response.status_code == 404:
            return None
        return 0
    except:
        return 0


def fetch_full_vt_report(resource_type, resource_id):
    log_vt_request(f'report_{resource_type}', resource_id)
    headers = {
        'x-apikey': app.config['VIRUSTOTAL_API_KEY'], 'Accept': 'application/json'}

    if resource_type == 'file':
        api_url = f"https://www.virustotal.com/api/v3/files/{resource_id}"
    elif resource_type == 'url':
        url_id = base64.urlsafe_b64encode(
            resource_id.strip().encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif resource_type == 'ip_address':
        api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{resource_id}"
    else:
        return {"error": "Invalid resource type."}, 400

    try:
        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 200 and resource_type == 'file':
            data = response.json()
            try:
                # Fetch Behavior Reports
                log_vt_request('report_behavior', resource_id)
                beh_url = f"https://www.virustotal.com/api/v3/files/{resource_id}/behaviours"
                beh_resp = requests.get(beh_url, headers=headers, timeout=15)
                if beh_resp.status_code == 200:
                    data['behavior'] = beh_resp.json().get('data', [])
            except Exception:
                pass  # Fail silently on behavior if main report is ok
            return data, 200

        if response.status_code == 404 and resource_type == 'url':
            scan_url = "https://www.virustotal.com/api/v3/urls"
            scan_resp = requests.post(scan_url, headers=headers, data={
                                      'url': resource_id}, timeout=15)
            if scan_resp.status_code == 200:
                return {"data": {"type": "analysis_queued", "id": scan_resp.json()['data']['id']}}, 202

        if response.status_code == 404:
            return {"error": f"{resource_type.replace('_', ' ').title()} not found in VirusTotal database."}, 404

        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}, 500

# --- Core Logic: RAM-Based Analysis ---


def start_analysis_in_memory(file_bytes, filename, submission_id):
    """Parses email from RAM bytes and populates relational tables."""
    db = get_db()

    # Initialize lists for VT analysis
    url_list = []
    hash_list = []
    ip_list = []

    try:
        # --- MSG Handling ---
        if filename.lower().endswith('.msg'):
            # Use safe MSG parser with XXE protection
            msg = parse_msg_safely(file_bytes)
            try:
                subject = msg.subject if msg.subject else "N/A"
                sender = msg.sender if msg.sender else "N/A"
                receiver = msg.to if msg.to else "N/A"

                db.execute("UPDATE analysis_sessions SET subject = ?, sender = ?, receiver = ?, status = 'ANALYZING_VT' WHERE id = ?",
                           (subject, sender, receiver, submission_id))

                # Headers
                if hasattr(msg, 'header') and msg.header:
                    target_headers = ["Received-SPF", "Authentication-Results", "DKIM-Signature",
                                      "Authentication-Results-Original", "Return-Path", "MIME-Version",
                                      "DMARC-Filter", "X-DMARC-Policy", "ARC-Authentication-Results"]
                    for key in target_headers:
                        values = msg.header.get_all(key)
                        if values:
                            for val in values:
                                db.execute("INSERT INTO email_headers (session_id, header_key, header_value) VALUES (?, ?, ?)",
                                           (submission_id, key, str(val)))

                    # IPs
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    if msg.header.get_all('Received'):
                        for header in msg.header.get_all('Received'):
                            for ip in re.findall(ip_pattern, str(header)):
                                # Validate IP range (0-255 for each octet)
                                if validate_ipv4(ip):
                                    exists = db.execute(
                                        "SELECT 1 FROM email_artifacts WHERE session_id=? AND type='ip' AND value=?", (submission_id, ip)).fetchone()
                                    if not exists:
                                        db.execute("INSERT INTO email_artifacts (session_id, type, value, vt_result) VALUES (?, 'ip', ?, 'PENDING')",
                                                   (submission_id, ip))

                # Attachments
                if hasattr(msg, 'attachments'):
                    for att in msg.attachments:
                        fname = att.getFilename()
                        payload = att.data
                        if payload:
                            sha256 = hashlib.sha256(payload).hexdigest()
                            db.execute("INSERT INTO email_artifacts (session_id, type, value, filename, vt_result) VALUES (?, 'file_hash', ?, ?, 'PENDING')",
                                       (submission_id, sha256, fname))
                            hash_list.append(sha256)

                # Body
                found_html_body = False
                plain_text_body = msg.body

                html_content = None
                if hasattr(msg, 'htmlBody') and msg.htmlBody:
                    if isinstance(msg.htmlBody, bytes):
                        try:
                            html_content = msg.htmlBody.decode(
                                'utf-8', errors='ignore')
                        except:
                            html_content = str(msg.htmlBody)
                    else:
                        html_content = msg.htmlBody

                if html_content:
                    sanitized_html = sanitize_html_content(html_content)
                    db.execute("INSERT OR REPLACE INTO email_content (session_id, body_html) VALUES (?, ?)",
                               (submission_id, sanitized_html))
                    found_html_body = True

                    soup = BeautifulSoup(sanitized_html, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        link = a['href'].strip()
                        if link.startswith('http'):
                            with ANALYSIS_LOCK:
                                exists = db.execute(
                                    "SELECT 1 FROM email_artifacts WHERE session_id=? AND type='url' AND value=?", (submission_id, link)).fetchone()
                                if not exists:
                                    db.execute("INSERT INTO email_artifacts (session_id, type, value, vt_result) VALUES (?, 'url', ?, 'PENDING')",
                                               (submission_id, link))
                                    url_list.append(link)

                if not found_html_body and plain_text_body:
                    text_urls = re.findall(
                        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', plain_text_body)
                    for link in text_urls:
                        link = link.rstrip('.,;)>]')
                        with ANALYSIS_LOCK:
                            exists = db.execute(
                                "SELECT 1 FROM email_artifacts WHERE session_id=? AND type='url' AND value=?", (submission_id, link)).fetchone()
                            if not exists:
                                db.execute("INSERT INTO email_artifacts (session_id, type, value, vt_result) VALUES (?, 'url', ?, 'PENDING')",
                                           (submission_id, link))
                                url_list.append(link)

                    safe_body = plain_text_body.replace('&', '&amp;').replace(
                        '<', '&lt;').replace('>', '&gt;')
                    wrapped_body = f"<html><body style='font-family: monospace; white-space: pre-wrap;'>{safe_body}</body></html>"
                    db.execute("INSERT OR REPLACE INTO email_content (session_id, body_html) VALUES (?, ?)",
                               (submission_id, wrapped_body))
            finally:
                msg.close()

        # --- EML Handling ---
        else:
            msg = email_parser.BytesParser().parsebytes(file_bytes)

            # 2. Extract Basic Info
            subject = decode_mime_header(msg.get('Subject', 'N/A'))
            sender = decode_mime_header(msg.get('From', 'N/A'))
            receiver = decode_mime_header(msg.get('To', 'N/A'))

            # 3. Update Session Info
            db.execute("UPDATE analysis_sessions SET subject = ?, sender = ?, receiver = ?, status = 'ANALYZING_VT' WHERE id = ?",
                       (subject, sender, receiver, submission_id))
            db.commit()

            # 4. Extract & Save Headers
            target_headers = ["Received-SPF", "Authentication-Results", "DKIM-Signature",
                              "Authentication-Results-Original", "Return-Path", "MIME-Version",
                              "DMARC-Filter", "X-DMARC-Policy", "ARC-Authentication-Results"]
            for key in target_headers:
                values = msg.get_all(key)
                if values:
                    for val in values:
                        db.execute("INSERT INTO email_headers (session_id, header_key, header_value) VALUES (?, ?, ?)",
                                   (submission_id, key, str(val)))

            # 5. Extract IPs (Regex on Received Header)
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            if msg.get_all('Received'):
                for header in msg.get_all('Received'):
                    for ip in re.findall(ip_pattern, str(header)):
                        # Validate IP range (0-255 for each octet)
                        if validate_ipv4(ip):
                            exists = db.execute(
                                "SELECT 1 FROM email_artifacts WHERE session_id=? AND type='ip' AND value=?", (submission_id, ip)).fetchone()
                            if not exists:
                                db.execute("INSERT INTO email_artifacts (session_id, type, value, vt_result) VALUES (?, 'ip', ?, 'PENDING')",
                                           (submission_id, ip))

            # 6. Extract Content & Attachments
            found_html_body = False
            plain_text_body = None

            for part in msg.walk():
                # A. Attachments
                fname = part.get_filename()
                if fname:
                    payload = part.get_payload(decode=True)
                    if payload:
                        sha256 = hashlib.sha256(payload).hexdigest()
                        db.execute("INSERT INTO email_artifacts (session_id, type, value, filename, vt_result) VALUES (?, 'file_hash', ?, ?, 'PENDING')",
                                   (submission_id, sha256, fname))
                        hash_list.append(sha256)

                # B. HTML Body & URLs
                if part.get_content_type() == 'text/html':
                    try:
                        html_bytes = part.get_payload(decode=True)
                        html_content = html_bytes.decode(
                            part.get_content_charset() or 'utf-8', errors='ignore')

                        sanitized_html = sanitize_html_content(html_content)
                        db.execute("INSERT OR REPLACE INTO email_content (session_id, body_html) VALUES (?, ?)",
                                   (submission_id, sanitized_html))
                        found_html_body = True

                        soup = BeautifulSoup(sanitized_html, 'html.parser')
                        for a in soup.find_all('a', href=True):
                            link = a['href'].strip()
                            if link.startswith('http'):
                                with ANALYSIS_LOCK:
                                    exists = db.execute(
                                        "SELECT 1 FROM email_artifacts WHERE session_id=? AND type='url' AND value=?", (submission_id, link)).fetchone()
                                    if not exists:
                                        db.execute("INSERT INTO email_artifacts (session_id, type, value, vt_result) VALUES (?, 'url', ?, 'PENDING')",
                                                   (submission_id, link))
                                        url_list.append(link)
                    except Exception as e:
                        print(f"HTML Error: {e}")

                # C. Plain Text Fallback
                if part.get_content_type() == 'text/plain' and not fname:
                    try:
                        text_bytes = part.get_payload(decode=True)
                        if text_bytes:
                            plain_text_body = text_bytes.decode(
                                part.get_content_charset() or 'utf-8', errors='ignore')
                    except Exception as e:
                        print(f"Text Error: {e}")

            if not found_html_body and plain_text_body:
                text_urls = re.findall(
                    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', plain_text_body)
                for link in text_urls:
                    link = link.rstrip('.,;)>]')
                    with ANALYSIS_LOCK:
                        exists = db.execute(
                            "SELECT 1 FROM email_artifacts WHERE session_id=? AND type='url' AND value=?", (submission_id, link)).fetchone()
                        if not exists:
                            db.execute("INSERT INTO email_artifacts (session_id, type, value, vt_result) VALUES (?, 'url', ?, 'PENDING')",
                                       (submission_id, link))
                            url_list.append(link)

                safe_body = plain_text_body.replace('&', '&amp;').replace(
                    '<', '&lt;').replace('>', '&gt;')
                wrapped_body = f"<html><body style='font-family: monospace; white-space: pre-wrap;'>{safe_body}</body></html>"
                db.execute("INSERT OR REPLACE INTO email_content (session_id, body_html) VALUES (?, ?)",
                           (submission_id, wrapped_body))

        # Populate ip_list from DB to ensure we analyze what we saved
        ip_rows = db.execute(
            "SELECT value FROM email_artifacts WHERE session_id=? AND type='ip'", (submission_id,)).fetchall()
        for row in ip_rows:
            ip_list.append(row['value'])

        db.commit()

        # --- VT ANALYSIS (Loop through DB artifacts) ---
        url_flags = 0
        file_flags = 0
        ip_flags = 0

        # Process URLs
        for url in url_list:
            with vt_api_lock:
                vt = check_vt_url(url)
                time.sleep(15)  # Rate Limit while holding the lock

            flags = vt['flags']
            if flags > 0:
                url_flags += 1

            db.execute("UPDATE email_artifacts SET vt_result = ?, vt_info = ? WHERE session_id=? AND type='url' AND value=?",
                       (f"{flags} flag(s)", json.dumps(vt), submission_id, url))
            db.commit()

        # Process Hashes
        for h in hash_list:
            with vt_api_lock:
                flags = check_vt_hash(h)
                time.sleep(15)  # Rate Limit while holding the lock

            if flags is None:
                vt_result_str = "Not Found"
                flags = 0
            else:
                vt_result_str = f"{flags} flag(s)"
                if flags > 0:
                    file_flags += 1

            db.execute("UPDATE email_artifacts SET vt_result = ? WHERE session_id=? AND type='file_hash' AND value=?",
                       (vt_result_str, submission_id, h))
            db.commit()

        # Process IPs
        for ip in ip_list:
            with vt_api_lock:
                flags = check_vt_ip(ip)
                time.sleep(15)  # Rate Limit while holding the lock

            if flags is None:
                vt_result_str = "Not Found"
                flags = 0
            else:
                vt_result_str = f"{flags} flag(s)"
                if flags > 0:
                    ip_flags += 1

            db.execute("UPDATE email_artifacts SET vt_result = ? WHERE session_id=? AND type='ip' AND value=?",
                       (vt_result_str, submission_id, ip))
            db.commit()

        # Final Status Update
        status = 'CLEAN_NO_IOCS'
        if url_flags > 0 or file_flags > 0 or ip_flags > 0:
            status = 'MALICIOUS_DETECTED'
        elif url_list or hash_list or ip_list:
            status = 'CLEAN_ANALYZED'

        db.execute("UPDATE analysis_sessions SET vt_score = ?, status = ? WHERE id = ?",
                   (json.dumps({"url_flags": url_flags, "file_flags": file_flags, "ip_flags": ip_flags}), status, submission_id))
        db.commit()

    except Exception as e:
        print(f"Analysis Failed: {e}")
        sanitized_error = sanitize_error_message(str(e))
        db.execute("UPDATE analysis_sessions SET status = 'FAILED', subject = ? WHERE id = ?",
                   (sanitized_error, submission_id))
        db.commit()


def background_analysis(app_instance, file_bytes, filename, sid):
    with app_instance.app_context():
        start_analysis_in_memory(file_bytes, filename, sid)

# --- Routes ---


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        files = request.files.getlist('email_file')
        if not files or files[0].filename == '':
            flash('No files selected', 'error')
            return redirect(url_for('index'))

        processed_ids = []

        for file in files:
            if file and allowed_file(file.filename):
                # Check file size before reading
                file_size = len(file.read())
                file.seek(0)  # Reset file pointer
                
                if file_size > MAX_FILE_SIZE:
                    flash(f'File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024):.0f} MB', 'error')
                    continue
                
                # 1. Read file into RAM immediately
                file_bytes = file.read()
                filename = secure_filename(file.filename)

                # 2. Create DB Entry with lock to prevent race conditions
                with ANALYSIS_LOCK:
                    db = get_db()
                    cur = db.cursor()
                    cur.execute("INSERT INTO analysis_sessions (submission_time, uploaded_filename, status) VALUES (?, ?, ?)",
                                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), filename, 'ANALYZING_VT'))
                    sid = cur.lastrowid
                    db.commit()
                    processed_ids.append(sid)

                # 3. Analyze from RAM (No saving to disk!) :-)
                analysis_executor.submit(
                    background_analysis, app, file_bytes, filename, sid)

        if processed_ids:
            flash(
                f"Analysis started for {len(processed_ids)} files.", 'success')
            return redirect(url_for('table_view'))

    return render_template('index.html')


@app.route('/table_view')
def table_view():
    db = get_db()
    # Fetch all submission records, ordered by latest first
    emails = db.execute(
        "SELECT * FROM analysis_sessions ORDER BY id DESC").fetchall()

    formatted_emails = []
    for row in emails:
        r = dict(row)

        # 1. Safely Parse JSON
        score_data = {}
        try:
            if r['vt_score']:
                score_data = json.loads(r['vt_score'])
        except:
            pass

        # 2. Force Default Values (Fixes missing scores)
        # If analysis is PENDING, these will simply show 0
        r['vt_score'] = {
            'url_flags': score_data.get('url_flags', 0),
            'file_flags': score_data.get('file_flags', 0),
            'ip_flags': score_data.get('ip_flags', 0)
        }
        r['total_flags'] = r['vt_score']['url_flags'] + \
            r['vt_score']['file_flags'] + r['vt_score']['ip_flags']

        formatted_emails.append(r)

    return render_template('table_view.jinja', emails=formatted_emails)


@app.route('/detail/<int:email_id>')
def detail(email_id):
    db = get_db()

    # 1. Fetch Session Info
    session = db.execute(
        "SELECT * FROM analysis_sessions WHERE id = ?", (email_id,)).fetchone()
    if not session:
        return "Not Found", 404

    data = dict(session)

    # 2. Reconstruct Data Structures for Template Compatibility

    # Headers: Group by key
    headers_raw = db.execute(
        "SELECT header_key, header_value FROM email_headers WHERE session_id=?", (email_id,)).fetchall()
    data['headers'] = {}
    for h in headers_raw:
        k, v = h['header_key'], h['header_value']
        if k not in data['headers']:
            data['headers'][k] = []
        data['headers'][k].append(v)

    # Artifacts: URLs
    urls_raw = db.execute(
        "SELECT value as url, vt_result, vt_info FROM email_artifacts WHERE session_id=? AND type='url'", (email_id,)).fetchall()
    data['malicious_urls'] = []
    for u in urls_raw:
        u_dict = dict(u)
        try:
            u_dict['vt_info'] = json.loads(
                u_dict['vt_info']) if u_dict['vt_info'] else {}
        except:
            u_dict['vt_info'] = {}
        data['malicious_urls'].append(u_dict)

    # Artifacts: Files
    files_raw = db.execute(
        "SELECT filename, value as hash, vt_result FROM email_artifacts WHERE session_id=? AND type='file_hash'", (email_id,)).fetchall()
    data['attachment_hashes'] = [dict(f) for f in files_raw]

    # Artifacts: IPs
    ips_raw = db.execute(
        "SELECT value, vt_result FROM email_artifacts WHERE session_id=? AND type='ip'", (email_id,)).fetchall()
    data['received_ips'] = [dict(i) for i in ips_raw]

    # VT Score
    try:
        score_dict = json.loads(data['vt_score']) if data['vt_score'] else {}
    except:
        score_dict = {}

    # Ensure keys exist (defaults to 0 for backward compatibility)
    data['vt_score'] = {
        'url_flags': score_dict.get('url_flags', 0),
        'file_flags': score_dict.get('file_flags', 0),
        'ip_flags': score_dict.get('ip_flags', 0)
    }

    # Check for HTML content presence
    has_html = db.execute(
        "SELECT 1 FROM email_content WHERE session_id=?", (email_id,)).fetchone()
    data['body_html'] = True if has_html else False

    return render_template('detail.html', data=data)


@app.route('/api/detail_data/<int:email_id>')
def api_detail_data(email_id):
    db = get_db()
    session = db.execute(
        "SELECT * FROM analysis_sessions WHERE id = ?", (email_id,)).fetchone()
    if not session:
        return jsonify({"error": "Not found"}), 404

    data = dict(session)

    # URLs
    urls_raw = db.execute(
        "SELECT value as url, vt_result, vt_info FROM email_artifacts WHERE session_id=? AND type='url'", (email_id,)).fetchall()
    data['malicious_urls'] = []
    for u in urls_raw:
        u_dict = dict(u)
        try:
            u_dict['vt_info'] = json.loads(
                u_dict['vt_info']) if u_dict['vt_info'] else {}
        except:
            u_dict['vt_info'] = {}
        data['malicious_urls'].append(u_dict)

    # Files
    files_raw = db.execute(
        "SELECT filename, value as hash, vt_result FROM email_artifacts WHERE session_id=? AND type='file_hash'", (email_id,)).fetchall()
    data['attachment_hashes'] = [dict(f) for f in files_raw]

    # IPs
    ips_raw = db.execute(
        "SELECT value, vt_result FROM email_artifacts WHERE session_id=? AND type='ip'", (email_id,)).fetchall()
    data['received_ips'] = [dict(i) for i in ips_raw]

    # Score
    try:
        score_dict = json.loads(data['vt_score']) if data['vt_score'] else {}
    except:
        score_dict = {}

    data['vt_score'] = {
        'url_flags': score_dict.get('url_flags', 0),
        'file_flags': score_dict.get('file_flags', 0),
        'ip_flags': score_dict.get('ip_flags', 0)
    }

    # Calculate totals for convenience
    data['total_flags'] = data['vt_score']['url_flags'] + \
        data['vt_score']['file_flags'] + data['vt_score']['ip_flags']

    return jsonify(data)


@app.route('/render_email/<int:email_id>')
def render_email(email_id):
    db = get_db()
    row = db.execute(
        "SELECT body_html FROM email_content WHERE session_id = ?", (email_id,)).fetchone()
    if row and row['body_html']:
        # Sanitize before rendering (defense in depth)
        sanitized = sanitize_html_content(row['body_html'])
        return Response(sanitized, mimetype='text/html; charset=utf-8')
    return Response("<div style='text-align:center; padding:20px; color:#666;'>No HTML content found.</div>", 
                   mimetype='text/html; charset=utf-8')


@app.route('/full_vt_report/<resource_type>/<path:resource_id>')
def full_vt_report(resource_type, resource_id):
    # Render immediately, let client fetch data via API
    return render_template('vt_report_viewer.jinja', report_data=None, resource_id=resource_id, resource_type=resource_type)


@app.route('/api/fetch_vt_report/<resource_type>/<path:resource_id>', methods=['GET', 'POST'])
def api_fetch_vt_report(resource_type, resource_id):
    from urllib.parse import unquote

    decoded_id = unquote(resource_id)
    force_refresh = request.args.get('force', 'false').lower() == 'true'
    db = get_db()

    # 1. Check Cache (if not forcing refresh)
    if not force_refresh:
        cached = db.execute(
            "SELECT report_json, cached_at FROM vt_report_cache WHERE resource_id = ?", (decoded_id,)).fetchone()
        if cached:
            try:
                data = json.loads(cached['report_json'])
                data['_cache_metadata'] = {
                    'cached': True, 'cached_at': cached['cached_at']}
                return jsonify(data)
            except json.JSONDecodeError:
                pass 

    # 2. Fetch Fresh Data
    time.sleep(15)  # Rate limit delay
    report, status = fetch_full_vt_report(resource_type, decoded_id)

    if status == 200:
        # 3. Update Cache
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute("INSERT OR REPLACE INTO vt_report_cache (resource_id, resource_type, report_json, cached_at) VALUES (?, ?, ?, ?)",
                   (decoded_id, resource_type, json.dumps(report), now_str))
        db.commit()
        report['_cache_metadata'] = {'cached': False, 'cached_at': now_str}
        return jsonify(report)

    if status == 202:
        return jsonify(report), 202

    return jsonify({"error": report.get('error')}), status


@app.route('/api/fetch_vt_relations/<resource_type>/<path:resource_id>', methods=['GET'])
def api_fetch_vt_relations(resource_type, resource_id):
    """Fetch relationship data for IP addresses from VirusTotal"""
    from urllib.parse import unquote

    if resource_type != 'ip_address':
        return jsonify({"error": "Relations are only available for IP addresses"}), 400

    decoded_id = unquote(resource_id)
    headers = {
        'x-apikey': app.config['VIRUSTOTAL_API_KEY'], 'Accept': 'application/json'}

    relations = {
        'resolutions': [],
        'communicating_files': [],
        'referrer_files': [],
        'historical_whois': []
    }

    # Relationship types to fetch
    relationship_types = {
        'resolutions': 'resolutions',
        'communicating_files': 'communicating_files',
        'referrer_files': 'referrer_files',
        'historical_whois': 'historical_whois'
    }

    try:
        for key, rel_type in relationship_types.items():
            api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{decoded_id}/{rel_type}"
            log_vt_request(f'relation_{rel_type}', decoded_id)

            # Add rate limiting between requests
            time.sleep(1)

            try:
                response = requests.get(api_url, headers=headers, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    relations[key] = data.get('data', [])
                elif response.status_code == 429:
                    # Rate limit hit, wait and retry once
                    time.sleep(5)
                    response = requests.get(
                        api_url, headers=headers, timeout=15)
                    if response.status_code == 200:
                        data = response.json()
                        relations[key] = data.get('data', [])
            except requests.exceptions.RequestException as e:
                print(f"Error fetching {rel_type}: {e}")
                continue

        return jsonify(relations)

    except Exception as e:
        return jsonify({"error": f"Failed to fetch relations: {str(e)}"}), 500


@app.route('/delete/<int:email_id>', methods=['POST'])
def delete_record(email_id):
    try:
        db = get_db()
        # Cascade delete will handle artifacts, headers, and content automatically
        db.execute("DELETE FROM analysis_sessions WHERE id = ?", (email_id,))
        db.commit()
        flash(f"ID: {email_id} deleted successfully.", 'success')
    except Exception as e:
        print(e)
        flash("Delete failed.", 'error')
    return redirect(url_for('table_view'))

# --- Visualizations & API ---


@app.template_filter('format_time')
def format_time_filter(value):
    if not value:
        return ""
    try:
        date_obj = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        return date_obj.strftime('%I:%M %p')
    except:
        return value


@app.template_filter('from_json')
def from_json_filter(s):
    if s is None:
        return {}
    try:
        return json.loads(s)
    except:
        return {}


@app.route('/api/gemini-proxy', methods=['POST'])
def gemini_proxy():
    api_key = app.config['GEMINI_API_KEY']
    if not api_key:
        return jsonify({"error": "API Key missing"}), 500

    data = request.get_json()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"
    payload = {"contents": [{"parts": [{"text": data.get('query')}]}]}
    if data.get('systemPrompt'):
        payload["systemInstruction"] = {
            "parts": [{"text": data.get('systemPrompt')}]}

    try:
        resp = requests.post(url, json=payload, headers={
                             'Content-Type': 'application/json'})
        resp.raise_for_status()
        return jsonify(resp.json()), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/analyze_dashboard')
def analyze_dashboard(): return render_template('analyze.html')


@app.route('/api/analysis_data')
def get_analysis_data():
    db = get_db()
    sessions = db.execute(
        "SELECT * FROM analysis_sessions ORDER BY submission_time ASC").fetchall()

    ip_artifacts = db.execute(
        "SELECT session_id, value FROM email_artifacts WHERE type='ip'").fetchall()
    ip_map = {}
    for row in ip_artifacts:
        sid = row['session_id']
        if sid not in ip_map:
            ip_map[sid] = []
        ip_map[sid].append(row['value'])

    data = []
    for s in sessions:
        r = dict(s)
        try:
            r['vt_score'] = json.loads(r['vt_score']) if r['vt_score'] else {}
        except:
            r['vt_score'] = {}

        # Calculate totals
        u = r['vt_score'].get('url_flags', 0)
        f = r['vt_score'].get('file_flags', 0)
        i = r['vt_score'].get('ip_flags', 0)
        r['total_flags'] = u + f + i
        r['received_ips'] = ip_map.get(r['id'], [])
        data.append(r)
    return jsonify(data)


@app.route('/api/analysis_status')
def analysis_status():
    db = get_db()

    # Auto-cleanup: Mark sessions stuck in 'ANALYZING_VT' for > 160 minutes as FAILED
    try:
        stuck = db.execute(
            "SELECT id, submission_time FROM analysis_sessions WHERE status = 'ANALYZING_VT'").fetchall()
        for s in stuck:
            try:
                sub_time = datetime.strptime(
                    s['submission_time'], '%Y-%m-%d %H:%M:%S')
                if (datetime.now() - sub_time).total_seconds() > 9600:  # 160 minutes timeout
                    db.execute(
                        "UPDATE analysis_sessions SET status = 'FAILED' WHERE id = ?", (s['id'],))
                    db.commit()
            except:
                pass
    except:
        pass

    sessions = db.execute(
        "SELECT id, status, vt_score, subject, sender, receiver FROM analysis_sessions ORDER BY id DESC").fetchall()

    data = []
    for row in sessions:
        r = dict(row)
        try:
            r['vt_score'] = json.loads(r['vt_score']) if r['vt_score'] else {}
        except (json.JSONDecodeError, TypeError):
            r['vt_score'] = {}
        r['total_flags'] = int(r['vt_score'].get('url_flags', 0)) + int(
            r['vt_score'].get('file_flags', 0)) + int(r['vt_score'].get('ip_flags', 0))
        data.append(r)

    return jsonify(data)


@app.route('/analyze')
def analyze():
    db = get_db()
    rows = db.execute(
        "SELECT value FROM email_artifacts WHERE type='ip'").fetchall()
    ips = [r['value'] for r in rows]

    from collections import Counter
    top_ips_raw = Counter(ips).most_common(5)

    top_ips = []
    for ip, count in top_ips_raw:
        country = "Unknown"
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country", timeout=2)
            if resp.status_code == 200:
                country = resp.json().get('country', 'Unknown')
        except:
            pass
        top_ips.append({'ip': ip, 'count': count, 'country': country})

    return render_template('analyze.html', top_ips=top_ips)


@app.route('/api/matches')
def api_matches():
    resource_type = request.args.get('type')
    value = request.args.get('value')

    if not resource_type or not value:
        return jsonify([])

    db_type = resource_type
    if resource_type == 'file':
        db_type = 'file_hash'
    elif resource_type == 'ip_address':
        db_type = 'ip'

    db = get_db()
    query = """
        SELECT DISTINCT s.id, s.subject, s.sender, s.submission_time
        FROM analysis_sessions s
        JOIN email_artifacts a ON s.id = a.session_id
        WHERE a.type = ? AND a.value = ?
        ORDER BY s.id DESC
    """

    rows = db.execute(query, (db_type, value)).fetchall()
    results = [{"id": r['id'], "subject": r['subject'],
                "sender": r['sender'], "date": r['submission_time']} for r in rows]
    return jsonify(results)


@app.route('/bgimages/<path:filename>')
def serve_bg_image(filename):
    return send_from_directory('bgimages', filename)


@app.route('/info')
def info():
    return render_template('info.html')


@app.route('/api/vt_usage')
def vt_usage():
    db = get_db()
    today = datetime.now().strftime('%Y-%m-%d')

    # Query for today's usage from local logs
    query = """
        SELECT endpoint, COUNT(*) as count 
        FROM vt_api_logs 
        WHERE date(timestamp) = ? 
        GROUP BY endpoint
    """
    rows = db.execute(query, (today,)).fetchall()

    usage = {row['endpoint']: row['count'] for row in rows}

    return jsonify({"date": today, "usage": usage})


if __name__ == '__main__':
    init_db()
    print("Database Initialized. In-Memory Analysis Ready.")
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    try:
        app.run(host='0.0.0.0', port=5000, debug=debug_mode)
    except KeyboardInterrupt:
        pass
werkzeug.serving.WSGIRequestHandler.server_version = ""
werkzeug.serving.WSGIRequestHandler.sys_version = ""
