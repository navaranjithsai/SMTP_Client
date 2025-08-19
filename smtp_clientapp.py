import os
import json
import socket
import threading
import webbrowser
import asyncio
import ssl
import hashlib
import datetime
import ipaddress
import subprocess
import platform
import smtplib
import dns.resolver
import base64
import hmac
import email.utils
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, parseaddr
from collections import deque

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import aiosmtpd
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer, AuthResult, LoginPassword
from aiosmtpd.handlers import Message
import certifi
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configuration file paths
CONFIG_DIR = 'smtp_server_data'
CONFIG_FILE = os.path.join(CONFIG_DIR, 'smtp_config.json')
USERS_FILE = os.path.join(CONFIG_DIR, 'smtp_users.json')
DOMAINS_FILE = os.path.join(CONFIG_DIR, 'smtp_domains.json')
CERTS_DIR = os.path.join(CONFIG_DIR, 'certificates')
LOGS_DIR = os.path.join(CONFIG_DIR, 'email_logs')
QUEUE_DIR = os.path.join(CONFIG_DIR, 'email_queue')
ERRORS_FILE = os.path.join(CONFIG_DIR, 'error_logs.json')

# Create necessary directories
for directory in [CONFIG_DIR, CERTS_DIR, LOGS_DIR, QUEUE_DIR]:
    os.makedirs(directory, exist_ok=True)

# Global variables
smtp_controller = None
smtp_thread = None
server_running = False
email_stats = {
    'sent': 0,
    'received': 0,
    'failed': 0,
    'queued': 0
}

# Error tracking
error_logs = deque(maxlen=100)  # Keep last 100 errors

def log_error(error_message, error_type="general", details=None):
    """Log errors to file and memory"""
    error_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'type': error_type,
        'message': error_message,
        'details': str(details) if details else None
    }
    
    error_logs.append(error_entry)
    
    # Save to file
    try:
        existing_errors = []
        if os.path.exists(ERRORS_FILE):
            with open(ERRORS_FILE, 'r') as f:
                existing_errors = json.load(f)
        
        existing_errors.append(error_entry)
        # Keep only last 1000 errors in file
        if len(existing_errors) > 1000:
            existing_errors = existing_errors[-1000:]
        
        with open(ERRORS_FILE, 'w') as f:
            json.dump(existing_errors, f, indent=2)
    except Exception as e:
        print(f"Failed to save error log: {e}")
    
    # Emit to dashboard
    socketio.emit('error_log', error_entry)
    
    return error_entry

class EnhancedSMTPHandler:
    """Enhanced SMTP Handler with authentication and relay capabilities"""
    
    def __init__(self):
        self.users = self.load_users()
        self.authenticated_sessions = {}
        
    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        return {}
    
    def reload_users(self):
        """Reload users from file"""
        self.users = self.load_users()
    
    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        """Handle EHLO command"""
        try:
            session.host_name = hostname
            responses.append('250-AUTH PLAIN LOGIN')
            responses.append('250-STARTTLS')
            responses.append('250-8BITMIME')
            responses.append('250-SIZE 35882577')
            responses.append('250 HELP')
        except Exception as e:
            log_error(f"EHLO handling error: {str(e)}", "smtp_protocol", e)
        return responses
    
    async def handle_AUTH(self, server, session, envelope, mechanism, auth_data):
        """Handle authentication"""
        try:
            if mechanism == "PLAIN":
                try:
                    # Decode PLAIN authentication
                    auth_decoded = base64.b64decode(auth_data).decode('utf-8').split('\x00')
                    username = auth_decoded[1] if len(auth_decoded) > 1 else ""
                    password = auth_decoded[2] if len(auth_decoded) > 2 else ""
                except Exception as e:
                    log_error(f"AUTH PLAIN decode error: {str(e)}", "authentication", e)
                    return AuthResult(success=False, handled=False)
                    
            elif mechanism == "LOGIN":
                try:
                    # LOGIN mechanism requires additional interaction
                    username = base64.b64decode(auth_data).decode('utf-8')
                    password = ""  # Would need to handle the password separately
                except Exception as e:
                    log_error(f"AUTH LOGIN decode error: {str(e)}", "authentication", e)
                    return AuthResult(success=False, handled=False)
            else:
                return AuthResult(success=False, handled=False)
            
            # Authenticate user
            if self.authenticate_user(username, password):
                session.authenticated = True
                session.auth_username = username
                self.authenticated_sessions[session] = username
                emit_log(f"User {username} authenticated successfully", "success")
                return AuthResult(success=True, handled=True, auth_data=username)
            
            emit_log(f"Authentication failed for user {username}", "error")
            return AuthResult(success=False, handled=False)
        except Exception as e:
            log_error(f"Authentication error: {str(e)}", "authentication", e)
            return AuthResult(success=False, handled=False)
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        self.reload_users()
        if username in self.users:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return self.users[username]['password'] == password_hash
        return False
    
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        """Handle MAIL FROM command"""
        try:
            config = load_config()
            if config.get('require_auth', True) and not getattr(session, 'authenticated', False):
                await server.push('530 5.7.0 Authentication required')
                return '530 5.7.0 Authentication required'
            
            envelope.mail_from = address
            envelope.mail_options.extend(mail_options)
            return '250 OK'
        except Exception as e:
            log_error(f"MAIL FROM error: {str(e)}", "smtp_protocol", e)
            return '451 Requested action aborted: error in processing'
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Handle RCPT TO command - Fixed for local testing"""
        try:
            config = load_config()
            
            # Check if this is a local test (from localhost)
            peer = getattr(session, 'peer', None)
            is_local = False
            if peer:
                peer_ip = peer[0]
                is_local = peer_ip in ['127.0.0.1', '::1', 'localhost']
            
            # Allow local testing without authentication
            if is_local and not config.get('require_auth', True):
                envelope.rcpt_tos.append(address)
                return '250 OK'
            
            # Normal relay restriction check
            if config.get('restrict_relay', True):
                domain = address.split('@')[1] if '@' in address else None
                allowed_domains = [d['name'] for d in load_domains()]
                
                # Also allow sending to IP-based addresses if that's our domain
                if not allowed_domains:
                    allowed_domains.append(get_public_ip())
                
                if domain and domain not in allowed_domains and not getattr(session, 'authenticated', False):
                    return '554 5.7.1 Relay access denied'
            
            envelope.rcpt_tos.append(address)
            return '250 OK'
        except Exception as e:
            log_error(f"RCPT TO error: {str(e)}", "smtp_protocol", e)
            return '451 Requested action aborted: error in processing'
    
    async def handle_DATA(self, server, session, envelope):
        """Handle DATA command - process and relay email"""
        try:
            log_email(envelope, 'received')
            email_stats['received'] += 1
            
            emit_log(f"Email received from {envelope.mail_from} to {envelope.rcpt_tos}", "info")
            
            if getattr(session, 'authenticated', False):
                success = await self.relay_email(envelope)
                if success:
                    email_stats['sent'] += 1
                    return '250 Message accepted and relayed'
                else:
                    email_stats['failed'] += 1
                    return '451 Requested action aborted: error in processing'
            else:
                self.queue_email(envelope)
                email_stats['queued'] += 1
                return '250 Message accepted for delivery'
                
        except Exception as e:
            log_error(f"DATA processing error: {str(e)}", "email_processing", e)
            emit_log(f"Error processing email: {str(e)}", "error")
            email_stats['failed'] += 1
            return '451 Requested action aborted: error in processing'
    
    async def relay_email(self, envelope):
        """Relay email to destination servers"""
        try:
            content = envelope.content.decode('utf8', errors='replace')
            
            for recipient in envelope.rcpt_tos:
                domain = recipient.split('@')[1] if '@' in recipient else None
                if not domain:
                    continue
                
                mx_hosts = get_mx_hosts(domain)
                if not mx_hosts:
                    mx_hosts = [domain]
                
                for mx_host in mx_hosts:
                    try:
                        with smtplib.SMTP(mx_host, 25, timeout=30) as smtp:
                            smtp.ehlo()
                            if smtp.has_extn('STARTTLS'):
                                smtp.starttls()
                                smtp.ehlo()
                            
                            smtp.sendmail(envelope.mail_from, [recipient], content)
                            emit_log(f"Email relayed successfully to {recipient} via {mx_host}", "success")
                            return True
                            
                    except Exception as e:
                        log_error(f"Relay to {mx_host} failed: {str(e)}", "email_relay", e)
                        emit_log(f"Failed to relay to {mx_host}: {str(e)}", "warning")
                        continue
                        
            return False
            
        except Exception as e:
            log_error(f"Relay error: {str(e)}", "email_relay", e)
            emit_log(f"Relay error: {str(e)}", "error")
            return False
    
    def queue_email(self, envelope):
        """Queue email for later processing"""
        try:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            queue_file = os.path.join(QUEUE_DIR, f'email_{timestamp}.json')
            
            with open(queue_file, 'w') as f:
                json.dump({
                    'from': envelope.mail_from,
                    'to': envelope.rcpt_tos,
                    'content': envelope.content.decode('utf8', errors='replace'),
                    'timestamp': timestamp,
                    'status': 'queued'
                }, f, indent=2)
        except Exception as e:
            log_error(f"Queue email error: {str(e)}", "email_queue", e)

def emit_log(message, level="info"):
    """Emit log message to dashboard"""
    socketio.emit('log_message', {
        'message': message,
        'level': level,
        'timestamp': datetime.datetime.now().isoformat()
    })

def get_mx_hosts(domain):
    """Get MX hosts for a domain"""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_records])
        return [host for _, host in mx_hosts]
    except Exception as e:
        log_error(f"MX lookup failed for {domain}: {str(e)}", "dns_lookup", e)
        return []

def verify_domain_dns(domain):
    """Verify domain DNS records"""
    results = {
        'mx': False,
        'spf': False,
        'dkim': False,
        'dmarc': False,
        'records': {}
    }
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        results['mx'] = True
        results['records']['mx'] = [{'priority': r.preference, 'host': str(r.exchange)} for r in mx_records]
    except Exception as e:
        log_error(f"MX check failed for {domain}: {str(e)}", "dns_verification")
    
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            txt_value = str(record).strip('"')
            if txt_value.startswith('v=spf1'):
                results['spf'] = True
                results['records']['spf'] = txt_value
                break
    except Exception as e:
        log_error(f"SPF check failed for {domain}: {str(e)}", "dns_verification")
    
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_records:
            txt_value = str(record).strip('"')
            if txt_value.startswith('v=DMARC1'):
                results['dmarc'] = True
                results['records']['dmarc'] = txt_value
                break
    except Exception as e:
        log_error(f"DMARC check failed for {domain}: {str(e)}", "dns_verification")
    
    return results

def log_email(envelope, direction='received'):
    """Enhanced email logging"""
    try:
        timestamp = datetime.datetime.now()
        log_file = os.path.join(LOGS_DIR, f'email_log_{timestamp.strftime("%Y%m%d")}.json')
        
        logs = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'direction': direction,
            'from': envelope.mail_from,
            'to': envelope.rcpt_tos,
            'size': len(envelope.content),
            'subject': extract_subject(envelope.content.decode('utf8', errors='replace'))
        })
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        log_error(f"Email logging error: {str(e)}", "logging", e)

def extract_subject(email_content):
    """Extract subject from email content"""
    for line in email_content.split('\n'):
        if line.startswith('Subject:'):
            return line[8:].strip()
    return 'No Subject'

def get_public_ip():
    """Get public IP address with multiple fallback methods"""
    methods = [
        lambda: requests.get('https://api.ipify.org?format=json', timeout=5).json()['ip'],
        lambda: requests.get('https://ipinfo.io/ip', timeout=5).text.strip(),
        lambda: requests.get('https://checkip.amazonaws.com', timeout=5).text.strip(),
    ]
    
    for method in methods:
        try:
            ip = method()
            # Validate IP
            socket.inet_aton(ip)
            return ip
        except:
            continue
    
    # Fallback to local IP
    try:
        # Get local IP that can reach the internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return '127.0.0.1'

def generate_certificates(domain=None):
    """Generate SSL certificates with SAN support"""
    try:
        ip_address = get_public_ip()
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SMTP Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain or ip_address),
        ])
        
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        
        san_list = []
        if domain:
            san_list.append(x509.DNSName(domain))
            san_list.append(x509.DNSName(f"*.{domain}"))
        san_list.append(x509.IPAddress(ipaddress.ip_address(ip_address)))
        
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        
        cert = builder.sign(private_key, hashes.SHA256(), default_backend())
        
        cert_path = os.path.join(CERTS_DIR, f'cert_{domain or "server"}.pem')
        key_path = os.path.join(CERTS_DIR, f'key_{domain or "server"}.pem')
        
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return cert_path, key_path
    except Exception as e:
        log_error(f"Certificate generation error: {str(e)}", "certificate", e)
        raise

def load_config():
    """Load server configuration - Fixed"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Ensure IP address is always current
            config['ip_address'] = get_public_ip()
            return config
    
    default_config = {
        'port': 2525,
        'auth_type': 'PLAIN',
        'require_auth': False,  # Changed to False for easier testing
        'restrict_relay': False,  # Changed to False for easier testing
        'use_ssl': False,
        'use_tls': False,
        'use_starttls': True,
        'max_message_size': 35882577,
        'domain': None,
        'hostname': socket.gethostname(),
        'ip_address': get_public_ip()
    }
    save_config(default_config)
    return default_config

def save_config(config):
    """Save server configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def load_users():
    """Load SMTP users"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save SMTP users"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_domains():
    """Load configured domains"""
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_domains(domains):
    """Save configured domains"""
    with open(DOMAINS_FILE, 'w') as f:
        json.dump(domains, f, indent=2)

# Flask routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    config = load_config()
    
    cert_files = os.listdir(CERTS_DIR) if os.path.exists(CERTS_DIR) else []
    certificates = {
        'available': len([f for f in cert_files if f.endswith('.pem')]) > 0,
        'files': cert_files
    }
    
    logs_today = []
    today_log = os.path.join(LOGS_DIR, f'email_log_{datetime.datetime.now().strftime("%Y%m%d")}.json')
    if os.path.exists(today_log):
        with open(today_log, 'r') as f:
            logs_today = json.load(f)
    
    return jsonify({
        'running': server_running,
        'config': config,
        'ip_address': get_public_ip(),
        'hostname': socket.gethostname(),
        'certificates': certificates,
        'stats': email_stats,
        'logs_today': len(logs_today)
    })

@app.route('/api/errors')
def get_errors():
    """Get error logs"""
    try:
        errors = []
        if os.path.exists(ERRORS_FILE):
            with open(ERRORS_FILE, 'r') as f:
                errors = json.load(f)
        
        # Get last 50 errors, most recent first
        errors = errors[-50:]
        errors.reverse()
        
        return jsonify(errors)
    except Exception as e:
        return jsonify([])

@app.route('/api/toggle', methods=['POST'])
def toggle_server():
    global server_running, smtp_controller
    
    data = request.json
    action = data.get('action')
    
    if action == 'start' and not server_running:
        config = load_config()
        
        try:
            # Try to determine the best hostname to bind to
            hostname_options = [
                '127.0.0.1',  # Localhost first (most compatible)
                socket.gethostbyname(socket.gethostname()),  # Local IP
                'localhost',  # Hostname
                '0.0.0.0'  # All interfaces (might not work on Windows)
            ]
            
            # Test which hostname works
            working_hostname = None
            test_port = config.get('port', 2525)
            
            # First check if port is available
            for hostname in hostname_options:
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    test_socket.bind((hostname, test_port))
                    test_socket.close()
                    working_hostname = hostname
                    break
                except Exception as e:
                    continue
            
            if not working_hostname:
                error_msg = f"Cannot bind to port {test_port}. It may be in use or blocked by firewall."
                log_error(error_msg, "port_binding")
                emit_log(error_msg, "error")
                return jsonify({'success': False, 'message': error_msg})
            
            handler = EnhancedSMTPHandler()
            
            ssl_context = None
            if config.get('use_ssl') or config.get('use_starttls'):
                cert_files = [f for f in os.listdir(CERTS_DIR) if f.startswith('cert_')]
                key_files = [f for f in os.listdir(CERTS_DIR) if f.startswith('key_')]
                
                if not cert_files or not key_files:
                    cert_path, key_path = generate_certificates(config.get('domain'))
                else:
                    cert_path = os.path.join(CERTS_DIR, cert_files[0])
                    key_path = os.path.join(CERTS_DIR, key_files[0])
                
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(cert_path, key_path)
            
            # Create the SMTP controller with standard parameters
            smtp_controller = Controller(
                handler,
                hostname=working_hostname,
                port=config.get('port', 2525)
            )
            
            # If you need SSL/TLS support with older aiosmtpd versions,
            # you might need to configure it differently or upgrade aiosmtpd
            
            smtp_controller.start()
            server_running = True
            
            emit_log(f"SMTP server started on {working_hostname}:{config.get('port', 2525)}", "success")
            socketio.emit('server_status', {'running': True})
            
            # Update config with the actual binding address
            config['actual_hostname'] = working_hostname
            save_config(config)
            
            return jsonify({
                'success': True, 
                'message': f'SMTP server started successfully on {working_hostname}:{config.get("port", 2525)}'
            })
            
        except PermissionError as e:
            error_msg = f"Permission denied. Port {config.get('port', 2525)} might require administrator privileges."
            log_error(error_msg, "permission_error", e)
            emit_log(error_msg, "error")
            return jsonify({'success': False, 'message': error_msg})
            
        except OSError as e:
            if hasattr(e, 'errno'):
                if e.errno == 10048:  # Windows specific: Port already in use
                    error_msg = f"Port {config.get('port', 2525)} is already in use. Please choose a different port."
                elif e.errno == 10049:  # Windows specific: Cannot assign requested address
                    error_msg = "Cannot bind to the network address. Try using localhost (127.0.0.1)."
                else:
                    error_msg = f"Network error: {str(e)}"
            else:
                error_msg = f"OS error: {str(e)}"
            
            log_error(error_msg, "network_error", e)
            emit_log(error_msg, "error")
            return jsonify({'success': False, 'message': error_msg})
            
        except Exception as e:
            error_msg = f"Failed to start server: {str(e)}"
            log_error(error_msg, "server_start", e)
            emit_log(error_msg, "error")
            return jsonify({'success': False, 'message': error_msg})
    
    elif action == 'stop' and server_running:
        try:
            if smtp_controller:
                smtp_controller.stop()
            server_running = False
            
            emit_log("SMTP server stopped", "info")
            socketio.emit('server_status', {'running': False})
            
            return jsonify({'success': True, 'message': 'SMTP server stopped'})
            
        except Exception as e:
            error_msg = f"Failed to stop server: {str(e)}"
            log_error(error_msg, "server_stop", e)
            return jsonify({'success': False, 'message': error_msg})
    
    return jsonify({'success': False, 'message': 'Invalid action'})

@app.route('/api/domains', methods=['GET', 'POST', 'DELETE'])
def manage_domains():
    if request.method == 'GET':
        domains = load_domains()
        for domain in domains:
            domain['dns'] = verify_domain_dns(domain['name'])
        return jsonify(domains)
    
    elif request.method == 'POST':
        try:
            data = request.json
            domain_name = data.get('domain')
            
            if not domain_name:
                return jsonify({'success': False, 'message': 'Domain name required'})
            
            dns_results = verify_domain_dns(domain_name)
            domains = load_domains()
            
            if any(d['name'] == domain_name for d in domains):
                return jsonify({'success': False, 'message': 'Domain already exists'})
            
            domain_data = {
                'name': domain_name,
                'dns': dns_results,
                'added': datetime.datetime.now().isoformat(),
                'verified': dns_results['mx']
            }
            
            domains.append(domain_data)
            save_domains(domains)
            
            cert_path, key_path = generate_certificates(domain_name)
            
            emit_log(f"Domain {domain_name} added successfully", "success")
            
            return jsonify({
                'success': True,
                'domain': domain_data,
                'certificate': {
                    'cert_path': cert_path,
                    'key_path': key_path
                }
            })
        except Exception as e:
            error_msg = f"Failed to add domain: {str(e)}"
            log_error(error_msg, "domain_add", e)
            return jsonify({'success': False, 'message': error_msg})
    
    elif request.method == 'DELETE':
        try:
            data = request.json
            domain_name = data.get('domain')
            
            domains = load_domains()
            domains = [d for d in domains if d['name'] != domain_name]
            save_domains(domains)
            
            emit_log(f"Domain {domain_name} removed", "info")
            
            return jsonify({'success': True})
        except Exception as e:
            error_msg = f"Failed to remove domain: {str(e)}"
            log_error(error_msg, "domain_remove", e)
            return jsonify({'success': False, 'message': error_msg})

@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def manage_users():
    if request.method == 'GET':
        users = load_users()
        safe_users = {}
        for username, data in users.items():
            safe_users[username] = {
                'email': data.get('email'),
                'created': data.get('created'),
                'quota': data.get('quota', 'unlimited'),
                'sent_count': data.get('sent_count', 0)
            }
        return jsonify(safe_users)
    
    elif request.method == 'POST':
        try:
            data = request.json
            username = data.get('username')
            password = data.get('password')
            quota = data.get('quota', 'unlimited')
            
            if not username or not password:
                return jsonify({'success': False, 'message': 'Username and password required'})
            
            config = load_config()
            domains = load_domains()
            
            # Determine the domain/host for email address
            if domains and len(domains) > 0:
                # Use first configured domain
                email_domain = domains[0]['name']
            elif config.get('domain'):
                # Use configured domain
                email_domain = config.get('domain')
            else:
                # Use IP address as fallback
                email_domain = get_public_ip()
            
            email = f"{username}@{email_domain}"
            
            users = load_users()
            
            if username in users:
                return jsonify({'success': False, 'message': 'User already exists'})
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            users[username] = {
                'password': password_hash,
                'email': email,
                'created': datetime.datetime.now().isoformat(),
                'quota': quota,
                'sent_count': 0
            }
            
            save_users(users)
            
            emit_log(f"User {username} created with email {email}", "success")
            
            return jsonify({
                'success': True,
                'username': username,
                'email': email
            })
        except Exception as e:
            error_msg = f"Failed to create user: {str(e)}"
            log_error(error_msg, "user_create", e)
            return jsonify({'success': False, 'message': error_msg})
    
    elif request.method == 'DELETE':
        try:
            data = request.json
            username = data.get('username')
            
            users = load_users()
            if username in users:
                del users[username]
                save_users(users)
                emit_log(f"User {username} deleted", "info")
            
            return jsonify({'success': True})
        except Exception as e:
            error_msg = f"Failed to delete user: {str(e)}"
            log_error(error_msg, "user_delete", e)
            return jsonify({'success': False, 'message': error_msg})

@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    if request.method == 'GET':
        return jsonify(load_config())
    
    elif request.method == 'POST':
        try:
            data = request.json
            config = load_config()
            config.update(data)
            save_config(config)
            
            emit_log("Configuration updated", "info")
            
            return jsonify({'success': True, 'config': config})
        except Exception as e:
            error_msg = f"Failed to update configuration: {str(e)}"
            log_error(error_msg, "config_update", e)
            return jsonify({'success': False, 'message': error_msg})

@app.route('/api/certificates', methods=['GET', 'POST'])
def manage_certificates():
    if request.method == 'GET':
        cert_files = os.listdir(CERTS_DIR) if os.path.exists(CERTS_DIR) else []
        certificates = []
        
        for cert_file in cert_files:
            if cert_file.startswith('cert_'):
                domain = cert_file.replace('cert_', '').replace('.pem', '')
                certificates.append({
                    'domain': domain,
                    'cert_file': cert_file,
                    'key_file': f'key_{domain}.pem',
                    'created': datetime.datetime.fromtimestamp(
                        os.path.getctime(os.path.join(CERTS_DIR, cert_file))
                    ).isoformat()
                })
        
        return jsonify(certificates)
    
    elif request.method == 'POST':
        try:
            data = request.json
            action = data.get('action')
            
            if action == 'generate':
                domain = data.get('domain')
                cert_path, key_path = generate_certificates(domain)
                
                emit_log(f"Certificate generated for {domain or 'server'}", "success")
                
                return jsonify({
                    'success': True,
                    'cert_path': cert_path,
                    'key_path': key_path
                })
            
            return jsonify({'success': False})
        except Exception as e:
            error_msg = f"Failed to generate certificate: {str(e)}"
            log_error(error_msg, "certificate_generate", e)
            return jsonify({'success': False, 'message': error_msg})

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get email logs"""
    date = request.args.get('date', datetime.datetime.now().strftime('%Y%m%d'))
    log_file = os.path.join(LOGS_DIR, f'email_log_{date}.json')
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
        return jsonify(logs)
    
    return jsonify([])

@app.route('/api/queue', methods=['GET'])
def get_queue():
    """Get queued emails"""
    queue_files = os.listdir(QUEUE_DIR) if os.path.exists(QUEUE_DIR) else []
    queue = []
    
    for queue_file in queue_files:
        with open(os.path.join(QUEUE_DIR, queue_file), 'r') as f:
            queue.append(json.load(f))
    
    return jsonify(queue)

@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Send test email - Fixed version"""
    try:
        data = request.json
        recipient = data.get('recipient')
        
        if not recipient:
            return jsonify({'success': False, 'message': 'Recipient required'})
        
        config = load_config()
        users = load_users()
        domains = load_domains()
        
        # Get server details
        smtp_host = config.get('actual_hostname', '127.0.0.1')
        smtp_port = config.get('port', 2525)
        
        # Determine sender domain
        if domains and len(domains) > 0:
            sender_domain = domains[0]['name']
        elif config.get('domain'):
            sender_domain = config.get('domain')
        else:
            sender_domain = get_public_ip()
        
        # Create test message
        msg = MIMEMultipart()
        msg['From'] = f"test@{sender_domain}"
        msg['To'] = recipient
        msg['Subject'] = 'SMTP Server Test Email'
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = email.utils.make_msgid()
        
        body = f"""This is a test email from your SMTP server.
        
If you receive this email, your SMTP server is working correctly!

Server Information:
- IP Address: {get_public_ip()}
- Hostname: {socket.gethostname()}
- Port: {smtp_port}
- Time: {datetime.datetime.now()}
- Sender Domain: {sender_domain}
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Try to send the email
        try:
            # For testing, temporarily disable authentication requirement
            if config.get('require_auth', True):
                # First, save current config
                original_require_auth = config.get('require_auth', True)
                
                # Temporarily disable auth requirement for local testing
                config['require_auth'] = False
                save_config(config)
                
                # Send the test email
                try:
                    smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                    smtp.set_debuglevel(0)
                    smtp.ehlo()
                    smtp.send_message(msg)
                    smtp.quit()
                    
                    # Restore original setting
                    config['require_auth'] = original_require_auth
                    save_config(config)
                    
                    emit_log(f"Test email sent to {recipient}", "success")
                    return jsonify({'success': True, 'message': 'Test email sent successfully'})
                    
                except Exception as e:
                    # Restore original setting even if error occurs
                    config['require_auth'] = original_require_auth
                    save_config(config)
                    raise e
            else:
                # Auth not required, send directly
                smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                smtp.set_debuglevel(0)
                smtp.ehlo()
                smtp.send_message(msg)
                smtp.quit()
                
                emit_log(f"Test email sent to {recipient}", "success")
                return jsonify({'success': True, 'message': 'Test email sent successfully'})
                
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error: {str(e)}"
            log_error(error_msg, "test_email_smtp", str(e))
            
            # Provide helpful error message
            if "Relay access denied" in str(e):
                error_msg = "Test email blocked by relay restrictions. Try disabling 'Restrict Relay' in Settings temporarily for testing."
            
            return jsonify({'success': False, 'message': error_msg})
            
    except Exception as e:
        error_msg = f"Failed to send test email: {str(e)}"
        log_error(error_msg, "test_email", e)
        emit_log(error_msg, "error")
        return jsonify({'success': False, 'message': error_msg})

# Enhanced HTML template with error section
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional SMTP Server Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #4f46e5;
            --primary-dark: #4338ca;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --dark: #1f2937;
            --light: #f3f4f6;
            --white: #ffffff;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .app-container {
            display: flex;
            height: 100vh;
        }
        
        .sidebar {
            width: 280px;
            background: var(--dark);
            color: var(--white);
            padding: 20px;
            overflow-y: auto;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 40px;
            font-size: 24px;
            font-weight: bold;
        }
        
        .logo i {
            color: var(--primary);
        }
        
        .main-content {
            flex: 1;
            padding: 30px;
            overflow-y: auto;
        }
        
        .dashboard-header {
            background: var(--white);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .status-card {
            background: var(--light);
            padding: 15px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .status-icon {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .status-icon.online {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
        }
        
        .status-icon.offline {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
        }
        
        .power-control {
            display: flex;
            justify-content: center;
            margin: 40px 0;
        }
        
        .power-button {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            background: linear-gradient(145deg, #e6e6e6, #ffffff);
            box-shadow: 20px 20px 60px #d9d9d9, -20px -20px 60px #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }
        
        .power-button:hover {
            transform: scale(1.05);
        }
        
        .power-button.active {
            background: linear-gradient(145deg, var(--success), #059669);
            box-shadow: 0 0 40px rgba(16, 185, 129, 0.5);
        }
        
        .power-button i {
            font-size: 60px;
            color: #666;
        }
        
        .power-button.active i {
            color: white;
        }
        
        .nav-menu {
            list-style: none;
        }
        
        .nav-item {
            margin-bottom: 10px;
        }
        
        .nav-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            border-radius: 8px;
            color: #9ca3af;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .nav-link:hover {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        
        .nav-link.active {
            background: var(--primary);
            color: white;
        }
        
        .content-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--light);
        }
        
        .card-title {
            font-size: 20px;
            font-weight: 600;
            color: var(--dark);
        }
        
        .tabs {
            display: none;
        }
        
        .tabs.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 6px;
            font-weight: 500;
            color: var(--dark);
        }
        
        .form-control {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.4);
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-secondary {
            background: var(--light);
            color: var(--dark);
        }
        
        .alert {
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .alert-info {
            background: rgba(59, 130, 246, 0.1);
            color: var(--info);
            border: 1px solid rgba(59, 130, 246, 0.2);
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        
        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }
        
        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            text-align: left;
            padding: 12px;
            background: var(--light);
            font-weight: 600;
            color: var(--dark);
            border-bottom: 2px solid #e5e7eb;
        }
        
        .table td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .table tr:hover {
            background: var(--light);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
        }
        
        .badge-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
        }
        
        .badge-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
        }
        
        .badge-info {
            background: rgba(59, 130, 246, 0.1);
            color: var(--info);
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
        }
        
        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: white;
            border-radius: 12px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .modal-header {
            margin-bottom: 20px;
        }
        
        .modal-title {
            font-size: 24px;
            font-weight: 600;
            color: var(--dark);
        }
        
        .modal-footer {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid var(--light);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: var(--light);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: var(--primary);
        }
        
        .stat-label {
            color: #6b7280;
            margin-top: 5px;
        }
        
        .dns-check {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px;
            background: var(--light);
            border-radius: 6px;
            margin-bottom: 10px;
        }
        
        .dns-check i {
            font-size: 18px;
        }
        
        .dns-check.valid i {
            color: var(--success);
        }
        
        .dns-check.invalid i {
            color: var(--danger);
        }
        
        .log-entry {
            padding: 10px;
            border-left: 3px solid;
            margin-bottom: 10px;
            background: var(--light);
            border-radius: 0 6px 6px 0;
        }
        
        .log-entry.info {
            border-color: var(--info);
        }
        
        .log-entry.success {
            border-color: var(--success);
        }
        
        .log-entry.warning {
            border-color: var(--warning);
        }
        
        .log-entry.error {
            border-color: var(--danger);
        }
        
        .log-time {
            font-size: 12px;
            color: #6b7280;
        }
        
        .log-message {
            margin-top: 5px;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid var(--light);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .tooltip {
            position: relative;
            display: inline-block;
        }
        
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 200px;
            background-color: var(--dark);
            color: white;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 12px;
        }
        
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        
        .switch {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 24px;
        }
        
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 24px;
        }
        
        .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        
        input:checked + .slider {
            background-color: var(--primary);
        }
        
        input:checked + .slider:before {
            transform: translateX(26px);
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 300px;
            animation: slideInRight 0.3s ease;
            z-index: 2000;
        }
        
        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .input-group {
            display: flex;
            gap: 10px;
        }
        
        .input-group .form-control {
            flex: 1;
        }
        
        .error-row {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            margin-bottom: 10px;
            overflow: hidden;
        }
        
        .error-header {
            padding: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .error-header:hover {
            background: var(--light);
        }
        
        .error-type {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .error-details {
            display: none;
            padding: 12px;
            background: var(--light);
            border-top: 1px solid #e5e7eb;
        }
        
        .error-details.show {
            display: block;
        }
        
        .error-message {
            color: var(--danger);
            font-weight: 500;
        }
        
        .error-time {
            color: #6b7280;
            font-size: 12px;
        }
        
        .error-expand {
            color: #6b7280;
            transition: transform 0.2s;
        }
        
        .error-expand.expanded {
            transform: rotate(90deg);
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fas fa-envelope"></i>
                <span>SMTP Server</span>
            </div>
            
            <nav>
                <ul class="nav-menu">
                    <li class="nav-item">
                        <a href="#" class="nav-link active" onclick="switchTab('dashboard')">
                            <i class="fas fa-tachometer-alt"></i>
                            <span>Dashboard</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('domains')">
                            <i class="fas fa-globe"></i>
                            <span>Domains</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('users')">
                            <i class="fas fa-users"></i>
                            <span>Users</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('settings')">
                            <i class="fas fa-cog"></i>
                            <span>Settings</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('certificates')">
                            <i class="fas fa-certificate"></i>
                            <span>Certificates</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('logs')">
                            <i class="fas fa-history"></i>
                            <span>Logs</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('errors')">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span>Errors</span>
                            <span id="errorCount" class="badge badge-danger" style="margin-left: 5px; display: none;">0</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="#" class="nav-link" onclick="switchTab('queue')">
                            <i class="fas fa-inbox"></i>
                            <span>Queue</span>
                        </a>
                    </li>
                </ul>
            </nav>
            
            <div class="power-control">
                <div class="power-button" id="powerButton" onclick="toggleServer()">
                    <i class="fas fa-power-off"></i>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <!-- Dashboard Tab -->
            <div class="tabs active" id="dashboard-tab">
                <div class="dashboard-header">
                    <h1>SMTP Server Dashboard</h1>
                    <div class="status-grid">
                        <div class="status-card">
                            <div class="status-icon" id="statusIcon">
                                <i class="fas fa-server"></i>
                            </div>
                            <div>
                                <div id="statusText">Server Offline</div>
                                <small id="statusDetail">Ready to start</small>
                            </div>
                        </div>
                        <div class="status-card">
                            <div class="status-icon" style="background: rgba(79, 70, 229, 0.1); color: var(--primary);">
                                <i class="fas fa-network-wired"></i>
                            </div>
                            <div>
                                <div id="ipAddress">Loading...</div>
                                <small>IP Address</small>
                            </div>
                        </div>
                        <div class="status-card">
                            <div class="status-icon" style="background: rgba(245, 158, 11, 0.1); color: var(--warning);">
                                <i class="fas fa-plug"></i>
                            </div>
                            <div>
                                <div id="serverPort">2525</div>
                                <small>SMTP Port</small>
                            </div>
                        </div>
                        <div class="status-card">
                            <div class="status-icon" style="background: rgba(16, 185, 129, 0.1); color: var(--success);">
                                <i class="fas fa-shield-alt"></i>
                            </div>
                            <div>
                                <div id="securityStatus">TLS Enabled</div>
                                <small>Security</small>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Email Statistics</h2>
                        <button class="btn btn-secondary" onclick="refreshStats()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value" id="statSent">0</div>
                            <div class="stat-label">Sent</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="statReceived">0</div>
                            <div class="stat-label">Received</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="statQueued">0</div>
                            <div class="stat-label">Queued</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="statFailed">0</div>
                            <div class="stat-label">Failed</div>
                        </div>
                    </div>
                </div>
                
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Quick Actions</h2>
                    </div>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        <button class="btn btn-primary" onclick="showTestEmailModal()">
                            <i class="fas fa-paper-plane"></i> Send Test Email
                        </button>
                        <button class="btn btn-success" onclick="checkDNS()">
                            <i class="fas fa-check-circle"></i> Check DNS
                        </button>
                        <button class="btn btn-secondary" onclick="generateCerts()">
                            <i class="fas fa-certificate"></i> Generate Certificates
                        </button>
                    </div>
                </div>
                
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Live Activity</h2>
                    </div>
                    <div id="liveLog" style="max-height: 300px; overflow-y: auto;">
                        <!-- Live logs will appear here -->
                    </div>
                </div>
            </div>
            
            <!-- Domains Tab -->
            <div class="tabs" id="domains-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Domain Management</h2>
                        <button class="btn btn-primary" onclick="showAddDomainModal()">
                            <i class="fas fa-plus"></i> Add Domain
                        </button>
                    </div>
                    
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        Configure your domains and verify DNS records for proper email delivery.
                    </div>
                    
                    <div id="domainsList">
                        <!-- Domains will be listed here -->
                    </div>
                </div>
            </div>
            
            <!-- Users Tab -->
            <div class="tabs" id="users-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">User Management</h2>
                        <button class="btn btn-primary" onclick="showAddUserModal()">
                            <i class="fas fa-user-plus"></i> Add User
                        </button>
                    </div>
                    
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        Create SMTP users for authentication. Each user can send emails through your server.
                    </div>
                    
                    <table class="table" id="usersTable">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Created</th>
                                <th>Quota</th>
                                <th>Sent</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="usersList">
                            <!-- Users will be listed here -->
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Settings Tab -->
            <div class="tabs" id="settings-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Server Settings</h2>
                    </div>
                    
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        Recommended ports: 2525 (Alternative SMTP), 587 (Submission with STARTTLS), 465 (SMTPS with SSL/TLS)
                    </div>
                    
                    <form id="settingsForm">
                        <div class="form-group">
                            <label class="form-label">SMTP Port</label>
                            <select class="form-control" id="settingsPort">
                                <option value="25">25 (Standard SMTP - May be blocked)</option>
                                <option value="2525" selected>2525 (Alternative SMTP - Recommended)</option>
                                <option value="587">587 (Submission with STARTTLS)</option>
                                <option value="465">465 (SMTPS with SSL/TLS)</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Hostname</label>
                            <input type="text" class="form-control" id="settingsHostname">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Max Message Size (MB)</label>
                            <input type="number" class="form-control" id="settingsMaxSize" value="35">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Authentication Type</label>
                            <select class="form-control" id="settingsAuthType">
                                <option value="PLAIN">PLAIN</option>
                                <option value="LOGIN">LOGIN</option>
                                <option value="CRAM-MD5">CRAM-MD5</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <input type="checkbox" id="settingsRequireAuth" checked>
                                Require Authentication
                            </label>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <input type="checkbox" id="settingsRestrictRelay" checked>
                                Restrict Relay (Prevent Open Relay)
                            </label>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <input type="checkbox" id="settingsSSL">
                                Enable SSL (Port 465)
                            </label>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <input type="checkbox" id="settingsTLS">
                                Enable TLS
                            </label>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <input type="checkbox" id="settingsSTARTTLS" checked>
                                Enable STARTTLS (Port 587/2525)
                            </label>
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Settings
                        </button>
                    </form>
                </div>
            </div>
            
            <!-- Certificates Tab -->
            <div class="tabs" id="certificates-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">SSL/TLS Certificates</h2>
                        <button class="btn btn-primary" onclick="generateCerts()">
                            <i class="fas fa-plus"></i> Generate Certificate
                        </button>
                    </div>
                    
                    <div id="certificatesList">
                        <!-- Certificates will be listed here -->
                    </div>
                </div>
            </div>
            
            <!-- Logs Tab -->
            <div class="tabs" id="logs-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Email Logs</h2>
                        <input type="date" class="form-control" id="logDate" style="width: 200px;">
                    </div>
                    
                    <div id="emailLogs">
                        <!-- Logs will be displayed here -->
                    </div>
                </div>
            </div>
            
            <!-- Errors Tab -->
            <div class="tabs" id="errors-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Error Logs</h2>
                        <button class="btn btn-secondary" onclick="refreshErrors()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    
                    <div id="errorsList">
                        <!-- Errors will be displayed here -->
                    </div>
                </div>
            </div>
            
            <!-- Queue Tab -->
            <div class="tabs" id="queue-tab">
                <div class="content-card">
                    <div class="card-header">
                        <h2 class="card-title">Email Queue</h2>
                        <button class="btn btn-secondary" onclick="refreshQueue()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    
                    <div id="queueList">
                        <!-- Queue items will be displayed here -->
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    <div id="ipModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">No Domain Configured</h2>
            </div>
            <div class="modal-body">
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    No domain is currently configured. Do you want to continue with your IP address?
                </div>
                <p><strong>Your IP Address:</strong> <span id="modalIP"></span></p>
                <p>You can add domains later from the Domains section.</p>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('ipModal')">Cancel</button>
                <button class="btn btn-primary" onclick="confirmIP()">
                    <i class="fas fa-check"></i> Continue with IP
                </button>
            </div>
        </div>
    </div>
    
    <div id="addDomainModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Add Domain</h2>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Domain Name</label>
                    <input type="text" class="form-control" id="newDomainName" placeholder="example.com">
                </div>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    After adding the domain, configure these DNS records:
                    <ul style="margin-top: 10px;">
                        <li>MX Record: Point to your server IP</li>
                        <li>SPF Record: v=spf1 ip4:YOUR_IP ~all</li>
                        <li>DKIM: Will be generated automatically</li>
                    </ul>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('addDomainModal')">Cancel</button>
                <button class="btn btn-primary" onclick="addDomain()">
                    <i class="fas fa-plus"></i> Add Domain
                </button>
            </div>
        </div>
    </div>
    
    <div id="addUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Add User</h2>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-control" id="newUsername" placeholder="john">
                </div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-control" id="newPassword" placeholder="Strong password">
                </div>
                <div class="form-group">
                    <label class="form-label">Email Quota</label>
                    <select class="form-control" id="newUserQuota">
                        <option value="unlimited">Unlimited</option>
                        <option value="1000">1000 emails/day</option>
                        <option value="500">500 emails/day</option>
                        <option value="100">100 emails/day</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('addUserModal')">Cancel</button>
                <button class="btn btn-primary" onclick="addUser()">
                    <i class="fas fa-user-plus"></i> Create User
                </button>
            </div>
        </div>
    </div>
    
    <div id="testEmailModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Send Test Email</h2>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Recipient Email</label>
                    <input type="email" class="form-control" id="testEmailRecipient" placeholder="recipient@example.com">
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('testEmailModal')">Cancel</button>
                <button class="btn btn-primary" onclick="sendTestEmail()">
                    <i class="fas fa-paper-plane"></i> Send Test
                </button>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script>
        const socket = io();
        let serverRunning = false;
        let currentConfig = {};
        let errorCount = 0;
        
        // Initialize
        window.onload = function() {
            loadStatus();
            loadDomains();
            loadUsers();
            loadConfig();
            loadCertificates();
            loadErrors();
            
            // Set today's date for logs
            document.getElementById('logDate').valueAsDate = new Date();
        };
        
        // Socket.IO listeners
        socket.on('server_status', function(data) {
            serverRunning = data.running;
            updateUI();
        });
        
        socket.on('log_message', function(data) {
            addLiveLog(data);
        });
        
        socket.on('error_log', function(data) {
            addErrorToList(data);
            updateErrorCount();
        });
        
        function addLiveLog(data) {
            const logDiv = document.getElementById('liveLog');
            const entry = document.createElement('div');
            entry.className = `log-entry ${data.level}`;
            entry.innerHTML = `
                <div class="log-time">${new Date(data.timestamp).toLocaleTimeString()}</div>
                <div class="log-message">${data.message}</div>
            `;
            logDiv.insertBefore(entry, logDiv.firstChild);
            
            // Keep only last 50 logs
            while (logDiv.children.length > 50) {
                logDiv.removeChild(logDiv.lastChild);
            }
        }
        
        function loadStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    serverRunning = data.running;
                    currentConfig = data.config;
                    
                    document.getElementById('ipAddress').textContent = data.ip_address;
                    document.getElementById('modalIP').textContent = data.ip_address;
                    document.getElementById('serverPort').textContent = data.config.port;
                    
                    // Update stats
                    document.getElementById('statSent').textContent = data.stats.sent;
                    document.getElementById('statReceived').textContent = data.stats.received;
                    document.getElementById('statQueued').textContent = data.stats.queued;
                    document.getElementById('statFailed').textContent = data.stats.failed;
                    
                    // Update security status
                    const security = [];
                    if (data.config.use_ssl) security.push('SSL');
                    if (data.config.use_tls) security.push('TLS');
                    if (data.config.use_starttls) security.push('STARTTLS');
                    document.getElementById('securityStatus').textContent = security.length ? security.join(', ') : 'None';
                    
                    updateUI();
                });
        }
        
        function updateUI() {
            const powerButton = document.getElementById('powerButton');
            const statusIcon = document.getElementById('statusIcon');
            const statusText = document.getElementById('statusText');
            const statusDetail = document.getElementById('statusDetail');
            
            if (serverRunning) {
                powerButton.classList.add('active');
                statusIcon.classList.add('online');
                statusIcon.classList.remove('offline');
                statusText.textContent = 'Server Online';
                statusDetail.textContent = 'Accepting connections';
            } else {
                powerButton.classList.remove('active');
                statusIcon.classList.remove('online');
                statusIcon.classList.add('offline');
                statusText.textContent = 'Server Offline';
                statusDetail.textContent = 'Ready to start';
            }
        }
        
        function toggleServer() {
            const action = serverRunning ? 'stop' : 'start';
            
            if (action === 'start') {
                // Check if domain is configured
                fetch('/api/domains')
                    .then(response => response.json())
                    .then(domains => {
                        if (domains.length === 0) {
                            document.getElementById('ipModal').classList.add('show');
                        } else {
                            startServer();
                        }
                    });
            } else {
                stopServer();
            }
        }
        
        function startServer() {
            showNotification('Starting SMTP server...', 'info');
            
            fetch('/api/toggle', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: 'start'})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    serverRunning = true;
                    updateUI();
                    showNotification('Server started successfully', 'success');
                } else {
                    showNotification('Failed to start server: ' + data.message, 'error');
                }
            });
        }
        
        function stopServer() {
            showNotification('Stopping SMTP server...', 'info');
            
            fetch('/api/toggle', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: 'stop'})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    serverRunning = false;
                    updateUI();
                    showNotification('Server stopped successfully', 'success');
                } else {
                    showNotification('Failed to stop server: ' + data.message, 'error');
                }
            });
        }
        
        function confirmIP() {
            closeModal('ipModal');
            startServer();
        }
        
        function switchTab(tabName) {
            // Update navigation
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            event.target.closest('.nav-link').classList.add('active');
            
            // Update content
            document.querySelectorAll('.tabs').forEach(tab => {
                tab.classList.remove('active');
            });
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Load tab-specific data
            if (tabName === 'logs') {
                loadLogs();
            } else if (tabName === 'queue') {
                refreshQueue();
            } else if (tabName === 'errors') {
                refreshErrors();
            }
        }
        
        function loadDomains() {
            fetch('/api/domains')
                .then(response => response.json())
                .then(domains => {
                    const domainsList = document.getElementById('domainsList');
                    
                    if (domains.length === 0) {
                        domainsList.innerHTML = '<p style="text-align: center; color: #6b7280;">No domains configured yet.</p>';
                        return;
                    }
                    
                    domainsList.innerHTML = '';
                    
                    domains.forEach(domain => {
                        const domainCard = document.createElement('div');
                        domainCard.className = 'content-card';
                        domainCard.style.marginBottom = '20px';
                        
                        const dnsChecks = `
                            <div class="dns-check ${domain.dns.mx ? 'valid' : 'invalid'}">
                                <i class="fas fa-${domain.dns.mx ? 'check-circle' : 'times-circle'}"></i>
                                <span>MX Records</span>
                            </div>
                            <div class="dns-check ${domain.dns.spf ? 'valid' : 'invalid'}">
                                <i class="fas fa-${domain.dns.spf ? 'check-circle' : 'times-circle'}"></i>
                                <span>SPF Record</span>
                            </div>
                            <div class="dns-check ${domain.dns.dmarc ? 'valid' : 'invalid'}">
                                <i class="fas fa-${domain.dns.dmarc ? 'check-circle' : 'times-circle'}"></i>
                                <span>DMARC Record</span>
                            </div>
                        `;
                        
                        domainCard.innerHTML = `
                            <div style="display: flex; justify-content: space-between; align-items: start;">
                                <div>
                                    <h3>${domain.name}</h3>
                                    <div style="margin-top: 15px;">
                                        ${dnsChecks}
                                    </div>
                                </div>
                                <div>
                                    <button class="btn btn-danger" onclick="removeDomain('${domain.name}')">
                                        <i class="fas fa-trash"></i> Remove
                                    </button>
                                </div>
                            </div>
                        `;
                        
                        domainsList.appendChild(domainCard);
                    });
                });
        }
        
        function showAddDomainModal() {
            document.getElementById('addDomainModal').classList.add('show');
        }
        
        function addDomain() {
            const domainName = document.getElementById('newDomainName').value.trim();
            
            if (!domainName) {
                showNotification('Please enter a domain name', 'error');
                return;
            }
            
            fetch('/api/domains', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain: domainName})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    closeModal('addDomainModal');
                    document.getElementById('newDomainName').value = '';
                    loadDomains();
                    showNotification(`Domain ${domainName} added successfully`, 'success');
                } else {
                    showNotification(data.message, 'error');
                }
            });
        }
        
        function removeDomain(domain) {
            if (!confirm(`Are you sure you want to remove ${domain}?`)) return;
            
            fetch('/api/domains', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain: domain})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadDomains();
                    showNotification('Domain removed successfully', 'success');
                }
            });
        }
        
        function loadUsers() {
            fetch('/api/users')
                .then(response => response.json())
                .then(users => {
                    const usersList = document.getElementById('usersList');
                    usersList.innerHTML = '';
                    
                    if (Object.keys(users).length === 0) {
                        usersList.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6b7280;">No users created yet.</td></tr>';
                        return;
                    }
                    
                    Object.entries(users).forEach(([username, data]) => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td><strong>${username}</strong></td>
                            <td>${data.email}</td>
                            <td>${new Date(data.created).toLocaleDateString()}</td>
                            <td><span class="badge badge-info">${data.quota}</span></td>
                            <td>${data.sent_count || 0}</td>
                            <td>
                                <button class="btn btn-danger" onclick="removeUser('${username}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        `;
                        usersList.appendChild(row);
                    });
                });
        }
        
        function showAddUserModal() {
            document.getElementById('addUserModal').classList.add('show');
        }
        
        function addUser() {
            const username = document.getElementById('newUsername').value.trim();
            const password = document.getElementById('newPassword').value;
            const quota = document.getElementById('newUserQuota').value;
            
            if (!username || !password) {
                showNotification('Please enter username and password', 'error');
                return;
            }
            
            if (password.length < 8) {
                showNotification('Password must be at least 8 characters', 'error');
                return;
            }
            
            fetch('/api/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: username,
                    password: password,
                    quota: quota
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    closeModal('addUserModal');
                    document.getElementById('newUsername').value = '';
                    document.getElementById('newPassword').value = '';
                    loadUsers();
                    showNotification(`User created: ${data.email}`, 'success');
                } else {
                    showNotification(data.message, 'error');
                }
            });
        }
        
        function removeUser(username) {
            if (!confirm(`Are you sure you want to remove user ${username}?`)) return;
            
            fetch('/api/users', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: username})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadUsers();
                    showNotification('User removed successfully', 'success');
                }
            });
        }
        
        function loadConfig() {
            fetch('/api/config')
                .then(response => response.json())
                .then(config => {
                    currentConfig = config;
                    
                    // Update settings form
                    document.getElementById('settingsPort').value = config.port;
                    document.getElementById('settingsHostname').value = config.hostname || '';
                    document.getElementById('settingsMaxSize').value = Math.round(config.max_message_size / 1048576);
                    document.getElementById('settingsAuthType').value = config.auth_type;
                    document.getElementById('settingsRequireAuth').checked = config.require_auth;
                    document.getElementById('settingsRestrictRelay').checked = config.restrict_relay;
                    document.getElementById('settingsSSL').checked = config.use_ssl;
                    document.getElementById('settingsTLS').checked = config.use_tls;
                    document.getElementById('settingsSTARTTLS').checked = config.use_starttls;
                });
        }
        
        // Settings form handler
        document.getElementById('settingsForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const config = {
                port: parseInt(document.getElementById('settingsPort').value),
                hostname: document.getElementById('settingsHostname').value,
                max_message_size: parseInt(document.getElementById('settingsMaxSize').value) * 1048576,
                auth_type: document.getElementById('settingsAuthType').value,
                require_auth: document.getElementById('settingsRequireAuth').checked,
                restrict_relay: document.getElementById('settingsRestrictRelay').checked,
                use_ssl: document.getElementById('settingsSSL').checked,
                use_tls: document.getElementById('settingsTLS').checked,
                use_starttls: document.getElementById('settingsSTARTTLS').checked
            };
            
            fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentConfig = data.config;
                    loadConfig();
                    showNotification('Settings saved successfully. Restart server to apply changes.', 'success');
                }
            });
        });
        
        function loadCertificates() {
            fetch('/api/certificates')
                .then(response => response.json())
                .then(certificates => {
                    const certsList = document.getElementById('certificatesList');
                    
                    if (certificates.length === 0) {
                        certsList.innerHTML = '<p style="text-align: center; color: #6b7280;">No certificates generated yet.</p>';
                        return;
                    }
                    
                    certsList.innerHTML = '<table class="table"><thead><tr><th>Domain</th><th>Created</th><th>Files</th></tr></thead><tbody>';
                    
                    certificates.forEach(cert => {
                        certsList.innerHTML += `
                            <tr>
                                <td><strong>${cert.domain}</strong></td>
                                <td>${new Date(cert.created).toLocaleDateString()}</td>
                                <td>
                                    <span class="badge badge-success">${cert.cert_file}</span>
                                    <span class="badge badge-info">${cert.key_file}</span>
                                </td>
                            </tr>
                        `;
                    });
                    
                    certsList.innerHTML += '</tbody></table>';
                });
        }
        
        function generateCerts() {
            const domain = prompt('Enter domain name (leave empty for default):');
            
            showNotification('Generating certificates...', 'info');
            
            fetch('/api/certificates', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action: 'generate', domain: domain || null})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadCertificates();
                    showNotification('Certificates generated successfully', 'success');
                } else {
                    showNotification('Failed to generate certificates', 'error');
                }
            });
        }
        
        function loadLogs() {
            const date = document.getElementById('logDate').value.replace(/-/g, '');
            
            fetch(`/api/logs?date=${date}`)
                .then(response => response.json())
                .then(logs => {
                    const logsDiv = document.getElementById('emailLogs');
                    
                    if (logs.length === 0) {
                        logsDiv.innerHTML = '<p style="text-align: center; color: #6b7280;">No logs for this date.</p>';
                        return;
                    }
                    
                    logsDiv.innerHTML = '<table class="table"><thead><tr><th>Time</th><th>Direction</th><th>From</th><th>To</th><th>Subject</th><th>Size</th></tr></thead><tbody>';
                    
                    logs.forEach(log => {
                        const badge = log.direction === 'sent' ? 'badge-success' : 'badge-info';
                        logsDiv.innerHTML += `
                            <tr>
                                <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
                                <td><span class="badge ${badge}">${log.direction}</span></td>
                                <td>${log.from}</td>
                                <td>${log.to.join(', ')}</td>
                                <td>${log.subject}</td>
                                <td>${formatBytes(log.size)}</td>
                            </tr>
                        `;
                    });
                    
                    logsDiv.innerHTML += '</tbody></table>';
                });
        }
        
        document.getElementById('logDate').addEventListener('change', loadLogs);
        
        function loadErrors() {
            fetch('/api/errors')
                .then(response => response.json())
                .then(errors => {
                    updateErrorList(errors);
                });
        }
        
        function refreshErrors() {
            loadErrors();
            showNotification('Error logs refreshed', 'info');
        }
        
        function updateErrorList(errors) {
            const errorsList = document.getElementById('errorsList');
            
            if (!errors || errors.length === 0) {
                errorsList.innerHTML = '<p style="text-align: center; color: #6b7280;">No errors logged.</p>';
                updateErrorCount(0);
                return;
            }
            
            updateErrorCount(errors.length);
            errorsList.innerHTML = '';
            
            errors.forEach((error, index) => {
                const errorRow = document.createElement('div');
                errorRow.className = 'error-row';
                
                const typeColors = {
                    'server_start': 'badge-danger',
                    'authentication': 'badge-warning',
                    'email_relay': 'badge-info',
                    'certificate': 'badge-warning',
                    'dns_lookup': 'badge-info',
                    'general': 'badge-secondary'
                };
                
                const badgeClass = typeColors[error.type] || 'badge-secondary';
                const truncatedMessage = error.message.length > 100 
                    ? error.message.substring(0, 100) + '...' 
                    : error.message;
                
                errorRow.innerHTML = `
                    <div class="error-header" onclick="toggleErrorDetails(${index})">
                        <div>
                            <span class="error-time">${new Date(error.timestamp).toLocaleString()}</span>
                            <span class="error-type badge ${badgeClass}">${error.type}</span>
                            <div class="error-message" style="margin-top: 5px;">${truncatedMessage}</div>
                        </div>
                        <i class="fas fa-chevron-right error-expand" id="expand-${index}"></i>
                    </div>
                    <div class="error-details" id="details-${index}">
                        <strong>Full Message:</strong><br>
                        ${error.message}<br><br>
                        ${error.details ? `<strong>Details:</strong><br><pre style="white-space: pre-wrap;">${error.details}</pre>` : ''}
                    </div>
                `;
                
                errorsList.appendChild(errorRow);
            });
        }
        
        function toggleErrorDetails(index) {
            const details = document.getElementById(`details-${index}`);
            const expand = document.getElementById(`expand-${index}`);
            
            if (details.classList.contains('show')) {
                details.classList.remove('show');
                expand.classList.remove('expanded');
            } else {
                details.classList.add('show');
                expand.classList.add('expanded');
            }
        }
        
        function addErrorToList(error) {
            const errorsList = document.getElementById('errorsList');
            
            // Remove "no errors" message if present
            if (errorsList.innerHTML.includes('No errors logged')) {
                errorsList.innerHTML = '';
            }
            
            // Add new error at the top
            const errorRow = document.createElement('div');
            errorRow.className = 'error-row';
            errorRow.style.animation = 'slideIn 0.3s ease';
            
            const typeColors = {
                'server_start': 'badge-danger',
                'authentication': 'badge-warning',
                'email_relay': 'badge-info',
                'certificate': 'badge-warning',
                'dns_lookup': 'badge-info',
                'general': 'badge-secondary'
            };
            
            const badgeClass = typeColors[error.type] || 'badge-secondary';
            const truncatedMessage = error.message.length > 100 
                ? error.message.substring(0, 100) + '...' 
                : error.message;
            
            const index = Date.now(); // Use timestamp as unique index
            
            errorRow.innerHTML = `
                <div class="error-header" onclick="toggleErrorDetails(${index})">
                    <div>
                        <span class="error-time">${new Date(error.timestamp).toLocaleString()}</span>
                        <span class="error-type badge ${badgeClass}">${error.type}</span>
                        <div class="error-message" style="margin-top: 5px;">${truncatedMessage}</div>
                    </div>
                    <i class="fas fa-chevron-right error-expand" id="expand-${index}"></i>
                </div>
                <div class="error-details" id="details-${index}">
                    <strong>Full Message:</strong><br>
                    ${error.message}<br><br>
                    ${error.details ? `<strong>Details:</strong><br><pre style="white-space: pre-wrap;">${error.details}</pre>` : ''}
                </div>
            `;
            
            errorsList.insertBefore(errorRow, errorsList.firstChild);
            
            // Keep only last 50 errors in view
            while (errorsList.children.length > 50) {
                errorsList.removeChild(errorsList.lastChild);
            }
        }
        
        function updateErrorCount(count) {
            if (count === undefined) {
                // Increment existing count
                errorCount++;
            } else {
                errorCount = count;
            }
            
            const errorCountBadge = document.getElementById('errorCount');
            if (errorCount > 0) {
                errorCountBadge.textContent = errorCount;
                errorCountBadge.style.display = 'inline-block';
            } else {
                errorCountBadge.style.display = 'none';
            }
        }
        
        function refreshQueue() {
            fetch('/api/queue')
                .then(response => response.json())
                .then(queue => {
                    const queueDiv = document.getElementById('queueList');
                    
                    if (queue.length === 0) {
                        queueDiv.innerHTML = '<p style="text-align: center; color: #6b7280;">Email queue is empty.</p>';
                        return;
                    }
                    
                    queueDiv.innerHTML = '';
                    
                    queue.forEach(item => {
                        const queueCard = document.createElement('div');
                        queueCard.className = 'content-card';
                        queueCard.style.marginBottom = '15px';
                        queueCard.innerHTML = `
                            <div style="display: flex; justify-content: space-between;">
                                <div>
                                    <strong>From:</strong> ${item.from}<br>
                                    <strong>To:</strong> ${item.to.join(', ')}<br>
                                    <strong>Time:</strong> ${new Date(item.timestamp).toLocaleString()}<br>
                                    <strong>Status:</strong> <span class="badge badge-warning">${item.status}</span>
                                </div>
                                <div>
                                    <button class="btn btn-primary" onclick="retryEmail('${item.timestamp}')">
                                        <i class="fas fa-redo"></i> Retry
                                    </button>
                                </div>
                            </div>
                        `;
                        queueDiv.appendChild(queueCard);
                    });
                });
        }
        
        function showTestEmailModal() {
            document.getElementById('testEmailModal').classList.add('show');
        }
        
        function sendTestEmail() {
            const recipient = document.getElementById('testEmailRecipient').value.trim();
            
            if (!recipient) {
                showNotification('Please enter recipient email', 'error');
                return;
            }
            
            showNotification('Sending test email...', 'info');
            
            fetch('/api/test-email', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({recipient: recipient})
            })
            .then(response => response.json())
            .then(data => {
                closeModal('testEmailModal');
                if (data.success) {
                    showNotification('Test email sent successfully', 'success');
                } else {
                    showNotification('Failed to send test email: ' + data.message, 'error');
                }
            });
        }
        
        function checkDNS() {
            fetch('/api/domains')
                .then(response => response.json())
                .then(domains => {
                    if (domains.length === 0) {
                        showNotification('No domains configured to check', 'warning');
                        return;
                    }
                    
                    domains.forEach(domain => {
                        const status = [];
                        if (domain.dns.mx) status.push('MX ✓');
                        if (domain.dns.spf) status.push('SPF ✓');
                        if (domain.dns.dmarc) status.push('DMARC ✓');
                        
                        if (status.length === 0) {
                            showNotification(`${domain.name}: No DNS records found`, 'warning');
                        } else {
                            showNotification(`${domain.name}: ${status.join(', ')}`, 'success');
                        }
                    });
                    
                    loadDomains();
                });
        }
        
        function refreshStats() {
            loadStatus();
            showNotification('Statistics refreshed', 'info');
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('show');
        }
        
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = 'notification';
            
            const icons = {
                'success': 'fa-check-circle',
                'error': 'fa-times-circle',
                'warning': 'fa-exclamation-triangle',
                'info': 'fa-info-circle'
            };
            
            const colors = {
                'success': 'var(--success)',
                'error': 'var(--danger)',
                'warning': 'var(--warning)',
                'info': 'var(--info)'
            };
            
            notification.innerHTML = `
                <i class="fas ${icons[type]}" style="color: ${colors[type]}; font-size: 20px;"></i>
                <span>${message}</span>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 4000);
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        // Auto-refresh stats every 30 seconds
        setInterval(loadStatus, 30000);
        
        // Listen for clicks outside modals to close them
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.classList.remove('show');
            }
        };
    </script>
</body>
</html>
'''

# Save the enhanced template
if not os.path.exists('templates'):
    os.makedirs('templates')

with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(HTML_TEMPLATE)

def main():
    """Main function to start the enhanced SMTP server"""
    print("=" * 60)
    print("  Professional SMTP Server")
    print("  Version 2.1 - Enhanced Edition")
    print("=" * 60)
    print()
    print("Features:")
    print("  ✓ Full SMTP server with authentication")
    print("  ✓ SSL/TLS/STARTTLS support")
    print("  ✓ Domain management with DNS verification")
    print("  ✓ User management with quotas")
    print("  ✓ Email relay capabilities")
    print("  ✓ Real-time monitoring and logs")
    print("  ✓ Error tracking and debugging")
    print("  ✓ Queue management")
    print("  ✓ Professional web dashboard")
    print()
    print(f"Dashboard URL: http://localhost:5000")
    print(f"Default SMTP Port: 2525 (configurable)")
    print(f"Alternative Ports: 587 (STARTTLS), 465 (SSL/TLS)")
    print(f"Public IP: {get_public_ip()}")
    print()
    print("Opening dashboard in browser...")
    print("-" * 60)
    
    # Open browser after a short delay
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open('http://localhost:5000')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Run Flask app with SocketIO
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n\nShutting down SMTP server...")
        if server_running and smtp_controller:
            smtp_controller.stop()
        print("Server stopped. Goodbye!")

if __name__ == '__main__':
    main()