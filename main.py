"""
Original work Copyright (c) [2023] [doot]
Modified work Copyright (c) [2025] [mister-gone-int]
Licensed under the MIT License - see LICENSE file for details.
https://github.com/dootss/catbox-scraper
"""

import os
import sys
import yaml
import time
import random
import string
import asyncio
import aiohttp
import aiofiles
import threading
import magic
import re
import struct
import subprocess
import json
import tempfile
import hashlib
import datetime
import math
import ssl
import certifi
from typing import List, Optional, Tuple, Dict, Any, Set
from aiohttp_socks import ProxyConnector
from collections import defaultdict, deque, Counter
from path_sanitizer import sanitize_filename, validate_safe_path, create_safe_path


CONFIG_FILE = 'config.yaml'
URL = 'https://files.catbox.moe/'
os.system('')
sys.stdout.write('\033[?25l')


with open(CONFIG_FILE, 'r') as config_file:
    config = yaml.safe_load(config_file)

file_extensions = config['file_extensions']
threads = config['threads']
update_rate = config['update_rate']

urls_scanned = 0
valid_found = 0
start_time = time.time()
status_board_running = True

print_lock = asyncio.Semaphore()
file_lock = asyncio.Lock()


class RateLimiter:
    """Manages request rates to avoid overloading servers or triggering anti-scraping measures."""
    
    def __init__(self, requests_per_minute: int = 60, cooldown_time: int = 5):
        self.requests_per_minute = requests_per_minute
        self.cooldown_time = cooldown_time
        self.request_times = defaultdict(lambda: deque(maxlen=requests_per_minute))
        self.cooldown_until = defaultdict(float)
        self.lock = asyncio.Lock()
        self.stats = {
            "rate_limited": 0,
            "cooldowns": 0
        }
    
    async def wait_if_needed(self, thread_id: int) -> bool:
        """
        Check if we need to wait before making another request.
        
        Args:
            thread_id: ID of the thread making the request
            
        Returns:
            True if rate limited, False otherwise
        """
        async with self.lock:
            current_time = time.time()
            
            # Check if we're in a cooldown period
            if current_time < self.cooldown_until[thread_id]:
                self.stats["rate_limited"] += 1
                return True
            
            # Remove requests older than 60 seconds
            while (self.request_times[thread_id] and 
                   self.request_times[thread_id][0] < current_time - 60):
                self.request_times[thread_id].popleft()
            
            # Check if we've exceeded the rate limit
            if len(self.request_times[thread_id]) >= self.requests_per_minute:
                # Enter cooldown mode
                self.cooldown_until[thread_id] = current_time + self.cooldown_time
                self.stats["cooldowns"] += 1
                self.stats["rate_limited"] += 1
                return True
            
            # Record this request
            self.request_times[thread_id].append(current_time)
            return False
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about rate limiting."""
        return self.stats


class IsolationManager:
    """Manages isolation of suspicious files for further analysis."""
    
    def __init__(self, base_dir: str = "isolated", 
                 malware_folder: str = "malware", 
                 adult_folder: str = "adult",
                 unknown_folder: str = "unknown",
                 generate_reports: bool = True):
        self.base_dir = base_dir
        self.malware_folder = os.path.join(base_dir, malware_folder)
        self.adult_folder = os.path.join(base_dir, adult_folder)
        self.unknown_folder = os.path.join(base_dir, unknown_folder)
        self.generate_reports = generate_reports
        
        # Create isolation directories
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.malware_folder, exist_ok=True)
        os.makedirs(self.adult_folder, exist_ok=True)
        os.makedirs(self.unknown_folder, exist_ok=True)
        
        self.stats = {
            "malware_isolated": 0,
            "adult_isolated": 0,
            "unknown_isolated": 0,
            "reports_generated": 0
        }
    
    async def isolate_file(self, file_path: str, reason: str, category: str = "unknown") -> str:
        """
        Isolate a suspicious file for further analysis.
        
        Args:
            file_path: Path to the file to isolate
            reason: Reason for isolation
            category: Category of the file (malware, adult, unknown)
            
        Returns:
            Path to the isolated file
        """
        if not os.path.exists(file_path):
            return ""
        
        # Determine target directory
        if category == "malware":
            target_dir = self.malware_folder
            self.stats["malware_isolated"] += 1
        elif category == "adult":
            target_dir = self.adult_folder
            self.stats["adult_isolated"] += 1
        else:
            target_dir = self.unknown_folder
            self.stats["unknown_isolated"] += 1
        
        # Create a unique filename and sanitize it
        filename = os.path.basename(file_path)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        
        # Sanitize the filename and create a safe path
        safe_filename = sanitize_filename(unique_filename)
        target_path = create_safe_path(target_dir, safe_filename)
        
        # Copy the file to the isolation directory
        try:
            with open(file_path, 'rb') as src_file:
                content = src_file.read()
                
            async with aiofiles.open(target_path, 'wb') as dst_file:
                await dst_file.write(content)
            
            # Generate a report if enabled
            if self.generate_reports:
                await self._generate_report(target_path, file_path, reason, category)
                self.stats["reports_generated"] += 1
            
            return target_path
        except Exception as e:
            print(f"Error isolating file: {e}")
            return ""
    
    async def _generate_report(self, isolated_path: str, original_path: str, reason: str, category: str) -> None:
        """Generate a report for an isolated file."""
        report_path = f"{isolated_path}.report.txt"
        
        try:
            # Calculate file hash
            with open(isolated_path, 'rb') as f:
                file_content = f.read()
                md5_hash = hashlib.md5(file_content).hexdigest()
                sha256_hash = hashlib.sha256(file_content).hexdigest()
            
            # Get file size
            file_size = os.path.getsize(isolated_path)
            
            # Get file type
            file_type = magic.Magic().from_file(isolated_path)
            
            # Create report
            report = [
                f"ISOLATION REPORT",
                f"===============",
                f"",
                f"File: {os.path.basename(isolated_path)}",
                f"Original Path: {original_path}",
                f"Isolation Category: {category}",
                f"Isolation Reason: {reason}",
                f"Isolation Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"",
                f"File Information",
                f"---------------",
                f"Size: {file_size} bytes",
                f"Type: {file_type}",
                f"MD5: {md5_hash}",
                f"SHA256: {sha256_hash}",
                f"",
                f"Submission Information",
                f"---------------------",
                f"This file has been isolated for further analysis.",
                f"If this file contains malware, consider submitting it to:",
                f"- VirusTotal: https://www.virustotal.com/",
                f"- Hybrid Analysis: https://www.hybrid-analysis.com/",
                f"",
                f"If this file contains adult content, consider using a multi-modal AI",
                f"to determine if it's safe adult content or content that should be removed."
            ]
            
            # Write report to file
            async with aiofiles.open(report_path, 'w') as f:
                await f.write('\n'.join(report))
                
        except Exception as e:
            print(f"Error generating report: {e}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about isolated files."""
        return self.stats


class SecurityManager:
    """Handles security checks for downloaded files."""
    
    # MIME types that correspond to common file extensions
    MIME_TYPES = {
        '.png': ['image/png'],
        '.jpg': ['image/jpeg'],
        '.jpeg': ['image/jpeg'],
        '.gif': ['image/gif'],
        '.webm': ['video/webm'],
        '.mp4': ['video/mp4'],
        '.bmp': ['image/bmp'],
        '.tif': ['image/tiff'],
        '.tiff': ['image/tiff'],
        '.webp': ['image/webp'],
        '.mov': ['video/quicktime'],
        '.avi': ['video/x-msvideo'],
        '.mkv': ['video/x-matroska'],
        '.flv': ['video/x-flv'],
        '.wmv': ['video/x-ms-wmv'],
        '.mp3': ['audio/mpeg'],
        '.wav': ['audio/wav', 'audio/x-wav'],
        '.aac': ['audio/aac'],
        '.flac': ['audio/flac'],
        '.ogg': ['audio/ogg'],
        '.m4a': ['audio/mp4'],
        '.zip': ['application/zip'],
        '.rar': ['application/x-rar-compressed'],
        '.7z': ['application/x-7z-compressed'],
        '.tar': ['application/x-tar'],
        '.gz': ['application/gzip'],
        '.bz2': ['application/x-bzip2'],
        '.xz': ['application/x-xz'],
        '.txt': ['text/plain'],
        '.md': ['text/markdown', 'text/plain'],
        '.pdf': ['application/pdf'],
        '.doc': ['application/msword'],
        '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        '.odt': ['application/vnd.oasis.opendocument.text'],
        '.rtf': ['application/rtf', 'text/rtf'],
    }
    
    # Suspicious patterns that might indicate malicious content
    SUSPICIOUS_PATTERNS = [
        # Executable headers
        rb'MZ',  # Windows PE
        rb'\x7fELF',  # ELF (Linux)
        rb'\xca\xfe\xba\xbe',  # Mach-O (macOS)
        
        # Script tags that might be hidden in images
        rb'<script',
        rb'eval\(',
        rb'document\.write',
        
        # Common malware strings
        rb'cmd\.exe',
        rb'powershell',
        rb'wget http',
        rb'curl http',
    ]
    
    # Malware signatures for common threats
    # Format: (name, signature_pattern)
    MALWARE_SIGNATURES = [
        ("JS/Redirector", rb"window\.location\s*="),
        ("Exploit/PDF", rb"%PDF.*\beval\b"),
        ("Backdoor/PHP", rb"<\?php.*system\s*\("),
        ("Exploit/XSS", rb"<script>alert\("),
        ("Malware/Dropper", rb"powershell.*downloadstring"),
        ("Malware/Crypter", rb"function\s+decrypt"),
        ("Exploit/SQLi", rb"UNION\s+SELECT"),
        ("Malware/Obfuscated", rb"eval\(base64_decode"),
        ("Malware/Stealer", rb"document\.cookie"),
        ("Exploit/ShellShock", rb"\(\)\s*\{\s*:;\s*\}\s*;"),
    ]
    
    # File format headers for validation
    FORMAT_HEADERS = {
        # PNG signature and IHDR chunk
        '.png': (rb'\x89PNG\r\n\x1a\n', rb'IHDR'),
        
        # JPEG SOI marker and APP0 segment
        '.jpg': (rb'\xff\xd8\xff', rb'JFIF'),
        '.jpeg': (rb'\xff\xd8\xff', rb'JFIF'),
        
        # GIF signature and version
        '.gif': (rb'GIF8[79]a', None),
        
        # WebP signature
        '.webp': (rb'RIFF....WEBP', None),
        
        # MP4 ftyp box
        '.mp4': (rb'....ftyp', None),
        
        # WebM EBML header
        '.webm': (rb'\x1a\x45\xdf\xa3', None),
    }
    
    def __init__(self, verify_file_type: bool = True, scan_for_malicious: bool = True, 
                 steg_detection: Dict[str, Any] = None, advanced_security: Dict[str, Any] = None):
        self.verify_file_type = verify_file_type
        self.scan_for_malicious = scan_for_malicious
        self.magic = magic.Magic(mime=True)
        
        # Steganography detection settings
        self.steg_detection = steg_detection or {}
        self.steg_enabled = self.steg_detection.get('enabled', False)
        self.isolate_steg_files = self.steg_detection.get('isolate_steg_files', True)
        self.detection_level = self.steg_detection.get('detection_level', 'normal')
        
        # Check if unblob is installed
        self.unblob_available = self._check_unblob_available() if self.steg_enabled else False
        
        # Advanced security settings
        self.advanced_security = advanced_security or {}
        self.advanced_enabled = self.advanced_security.get('enabled', False)
        self.async_processing = self.advanced_security.get('async_processing', True)
        
        # Signature detection settings
        self.signature_detection = self.advanced_security.get('signature_detection', {})
        self.signature_enabled = self.signature_detection.get('enabled', False)
        
        # Entropy analysis settings
        self.entropy_analysis = self.advanced_security.get('entropy_analysis', {})
        self.entropy_enabled = self.entropy_analysis.get('enabled', False)
        self.entropy_threshold = self.entropy_analysis.get('threshold', 7.0)
        
        # Header analysis settings
        self.header_analysis = self.advanced_security.get('header_analysis', {})
        self.header_enabled = self.header_analysis.get('enabled', False)
        self.polyglot_detection = self.header_analysis.get('polyglot_detection', True)
        self.format_validation = self.header_analysis.get('format_validation', True)
        
        # Certificate pinning settings
        self.cert_pinning = self.advanced_security.get('certificate_pinning', {})
        self.cert_pinning_enabled = self.cert_pinning.get('enabled', False)
        self.cert_pins = self.cert_pinning.get('pins', [])
        
        # Initialize SSL context for certificate pinning if enabled
        if self.cert_pinning_enabled and self.cert_pins:
            self.ssl_context = self._create_pinned_ssl_context()
        else:
            self.ssl_context = None
        
        self.security_stats = {
            "verified": 0,
            "type_mismatch": 0,
            "malicious_detected": 0,
            "steg_detected": 0,
            "steg_scanned": 0,
            "signature_matches": 0,
            "high_entropy_files": 0,
            "header_anomalies": 0,
            "cert_pinning_failures": 0
        }
    
    def _check_unblob_available(self) -> bool:
        """Check if unblob is available on the system."""
        try:
            result = subprocess.run(
                ["unblob", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except FileNotFoundError:
            print("Warning: unblob not found. Steganography detection disabled.")
            return False
    
    def detect_steganography(self, file_path: str) -> Tuple[bool, str]:
        """
        Detect steganography in a file using unblob.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (has_steganography, reason)
        """
        if not self.steg_enabled or not self.unblob_available:
            return False, "Steganography detection disabled"
        
        # Only scan image files
        if not file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
            return False, "Not an image file"
        
        self.security_stats["steg_scanned"] += 1
        
        # Create a temporary directory for unblob output
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Set unblob command based on detection level
                cmd = ["unblob", "-d", temp_dir, file_path]
                
                if self.detection_level == "thorough":
                    cmd.insert(1, "--thorough")
                elif self.detection_level == "basic":
                    cmd.insert(1, "--quick")
                
                # Run unblob
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30  # Timeout after 30 seconds
                )
                
                # Check if unblob found any hidden data
                if result.returncode == 0:
                    # Check if any files were extracted
                    extracted_files = []
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            extracted_files.append(os.path.join(root, file))
                    
                    if extracted_files:
                        self.security_stats["steg_detected"] += 1
                        return True, f"Hidden data detected: {len(extracted_files)} files found"
                    
                    return False, "No hidden data detected"
                else:
                    # If unblob failed, check for specific error messages
                    if "No valid extractors found" in result.stderr:
                        return False, "No hidden data detected"
                    else:
                        return False, f"Error during steganography detection: {result.stderr}"
                
            except subprocess.TimeoutExpired:
                return False, "Steganography detection timed out"
            except Exception as e:
                return False, f"Error during steganography detection: {str(e)}"
    
    def verify_file(self, file_path: str, expected_extension: str) -> Tuple[bool, str]:
        """
        Verify that a file's content matches its extension.
        
        Args:
            file_path: Path to the file
            expected_extension: Expected file extension (e.g., '.png')
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if not self.verify_file_type:
            return True, "File type verification disabled"
        
        try:
            # Get the actual MIME type
            mime_type = self.magic.from_file(file_path)
            
            # Check if the MIME type matches the expected extension
            expected_mime_types = self.MIME_TYPES.get(expected_extension.lower(), [])
            
            if not expected_mime_types:
                # If we don't have expected MIME types for this extension, consider it valid
                return True, f"Unknown extension {expected_extension}, assuming valid"
            
            if mime_type in expected_mime_types:
                self.security_stats["verified"] += 1
                return True, f"File is a valid {expected_extension} ({mime_type})"
            else:
                self.security_stats["type_mismatch"] += 1
                return False, f"File claims to be {expected_extension} but is actually {mime_type}"
                
        except Exception as e:
            # If there's an error, log it but don't block the file
            return True, f"Error verifying file type: {str(e)}"
    
    def _create_pinned_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context with certificate pinning."""
        # Create a default SSL context with certifi's CA bundle
        context = ssl.create_default_context(cafile=certifi.where())
        
        # Set up certificate verification callback
        def verify_callback(conn, cert, errno, depth, result):
            # Skip intermediate certificates
            if depth != 0:
                return result
            
            # Get the certificate's fingerprint
            der = ssl.DER_cert_to_PEM_cert(cert)
            x509 = ssl.PEM_cert_to_DER_cert(der)
            fingerprint = hashlib.sha256(x509).hexdigest()
            
            # Check if the fingerprint is in our pinned certificates
            if fingerprint in self.cert_pins:
                return True
            else:
                self.security_stats["cert_pinning_failures"] += 1
                print(f"Certificate pinning failure: {fingerprint}")
                return False
        
        # Set the verification callback
        context.set_verify(ssl.CERT_REQUIRED, verify_callback)
        return context
    
    def check_signature_matches(self, content: bytes) -> Tuple[bool, str]:
        """
        Check if the content matches any known malware signatures.
        
        Args:
            content: File content to check
            
        Returns:
            Tuple of (has_match, reason)
        """
        if not self.signature_enabled:
            return False, "Signature detection disabled"
        
        for name, pattern in self.MALWARE_SIGNATURES:
            if re.search(pattern, content):
                self.security_stats["signature_matches"] += 1
                return True, f"Signature match: {name}"
        
        return False, "No signature matches"
    
    def calculate_entropy(self, content: bytes) -> float:
        """
        Calculate Shannon entropy of the content.
        
        Args:
            content: File content
            
        Returns:
            Entropy value (0-8, higher values indicate more randomness)
        """
        # Count byte frequencies
        byte_counts = Counter(content)
        file_size = len(content)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def check_high_entropy(self, content: bytes) -> Tuple[bool, str]:
        """
        Check if the content has high entropy, which may indicate encryption or compression.
        
        Args:
            content: File content to check
            
        Returns:
            Tuple of (is_high_entropy, reason)
        """
        if not self.entropy_enabled:
            return False, "Entropy analysis disabled"
        
        entropy = self.calculate_entropy(content)
        
        if entropy > self.entropy_threshold:
            self.security_stats["high_entropy_files"] += 1
            return True, f"High entropy detected: {entropy:.2f} (threshold: {self.entropy_threshold})"
        
        return False, f"Normal entropy: {entropy:.2f}"
    
    def validate_file_format(self, file_path: str, content: bytes) -> Tuple[bool, str]:
        """
        Validate the file format by checking headers and structure.
        
        Args:
            file_path: Path to the file
            content: File content
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if not self.header_enabled:
            return True, "Header analysis disabled"
        
        extension = os.path.splitext(file_path)[1].lower()
        
        # Check for polyglot files (valid as multiple formats)
        if self.polyglot_detection:
            format_matches = []
            
            # Check how many format signatures match
            for ext, (signature, secondary) in self.FORMAT_HEADERS.items():
                if signature and re.match(signature, content[:20]):
                    format_matches.append(ext)
            
            if len(format_matches) > 1:
                self.security_stats["header_anomalies"] += 1
                return False, f"Polyglot file detected (matches formats: {', '.join(format_matches)})"
        
        # Validate format-specific structures
        if self.format_validation and extension in self.FORMAT_HEADERS:
            signature, secondary = self.FORMAT_HEADERS[extension]
            
            # Check primary signature
            if signature and not re.match(signature, content[:20]):
                self.security_stats["header_anomalies"] += 1
                return False, f"Invalid {extension} header"
            
            # Check secondary marker if applicable
            if secondary and secondary not in content[:1024]:
                self.security_stats["header_anomalies"] += 1
                return False, f"Missing {secondary} marker in {extension} file"
            
            # Format-specific validation
            if extension == '.png':
                # Validate PNG chunks
                pos = 8  # Skip signature
                while pos < len(content):
                    if pos + 8 > len(content):
                        self.security_stats["header_anomalies"] += 1
                        return False, "Truncated PNG chunk"
                    
                    # Get chunk length and type
                    chunk_length = int.from_bytes(content[pos:pos+4], byteorder='big')
                    chunk_type = content[pos+4:pos+8]
                    
                    # Ensure chunk doesn't extend beyond file end
                    if pos + chunk_length + 12 > len(content):
                        self.security_stats["header_anomalies"] += 1
                        return False, "Invalid PNG chunk size"
                    
                    # Move to next chunk
                    pos += chunk_length + 12
            
            elif extension in ('.jpg', '.jpeg'):
                # Validate JPEG markers
                pos = 2  # Skip SOI marker
                while pos < len(content):
                    if pos + 2 > len(content):
                        self.security_stats["header_anomalies"] += 1
                        return False, "Truncated JPEG marker"
                    
                    # Check for marker prefix
                    if content[pos] != 0xFF:
                        self.security_stats["header_anomalies"] += 1
                        return False, "Invalid JPEG marker"
                    
                    # Get marker type
                    marker_type = content[pos+1]
                    
                    # Skip certain markers without length fields
                    if marker_type in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9):
                        pos += 2
                        continue
                    
                    # Get marker length
                    if pos + 4 > len(content):
                        self.security_stats["header_anomalies"] += 1
                        return False, "Truncated JPEG marker length"
                    
                    marker_length = int.from_bytes(content[pos+2:pos+4], byteorder='big')
                    
                    # Ensure marker doesn't extend beyond file end
                    if pos + marker_length + 2 > len(content):
                        self.security_stats["header_anomalies"] += 1
                        return False, "Invalid JPEG marker length"
                    
                    # Move to next marker
                    pos += marker_length + 2
        
        return True, "Format validation passed"
    
    async def scan_file_for_malicious_content(self, file_path: str) -> Tuple[bool, str]:
        """
        Scan a file for potentially malicious content.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (is_safe, reason)
        """
        if not self.scan_for_malicious:
            return True, "Malicious content scanning disabled"
        
        try:
            # Read the file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Basic checks
            # Check for suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, content):
                    self.security_stats["malicious_detected"] += 1
                    return False, f"Suspicious pattern detected: {pattern}"
            
            # Check for hidden data beyond the end of the image (for common formats)
            if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                is_safe, reason = self._check_for_hidden_data(file_path, content)
                if not is_safe:
                    self.security_stats["malicious_detected"] += 1
                    return False, reason
            
            # Advanced security checks
            if self.advanced_enabled:
                # Run advanced checks asynchronously if enabled
                if self.async_processing:
                    # Create tasks for all enabled checks
                    tasks = []
                    
                    # Signature-based detection
                    if self.signature_enabled:
                        tasks.append(asyncio.to_thread(self.check_signature_matches, content))
                    
                    # Entropy analysis
                    if self.entropy_enabled:
                        tasks.append(asyncio.to_thread(self.check_high_entropy, content))
                    
                    # Header analysis
                    if self.header_enabled:
                        tasks.append(asyncio.to_thread(self.validate_file_format, file_path, content))
                    
                    # Run all checks concurrently
                    if tasks:
                        results = await asyncio.gather(*tasks)
                        
                        # Check results
                        for is_malicious, reason in results:
                            if is_malicious:
                                self.security_stats["malicious_detected"] += 1
                                return False, reason
                else:
                    # Run checks sequentially
                    
                    # Signature-based detection
                    if self.signature_enabled:
                        has_match, reason = self.check_signature_matches(content)
                        if has_match:
                            self.security_stats["malicious_detected"] += 1
                            return False, reason
                    
                    # Entropy analysis
                    if self.entropy_enabled:
                        is_high_entropy, reason = self.check_high_entropy(content)
                        if is_high_entropy:
                            self.security_stats["malicious_detected"] += 1
                            return False, reason
                    
                    # Header analysis
                    if self.header_enabled:
                        is_valid, reason = self.validate_file_format(file_path, content)
                        if not is_valid:
                            self.security_stats["malicious_detected"] += 1
                            return False, reason
            
            return True, "No malicious content detected"
                
        except Exception as e:
            # If there's an error, log it but don't block the file
            return True, f"Error scanning for malicious content: {str(e)}"
    
    def _check_for_hidden_data(self, file_path: str, content: bytes) -> Tuple[bool, str]:
        """Check for data hidden after the end of an image file."""
        try:
            # For PNG files
            if file_path.lower().endswith('.png'):
                # PNG files end with an IEND chunk
                iend_pos = content.rfind(b'IEND')
                if iend_pos != -1:
                    # IEND chunk is 8 bytes (including the IEND marker)
                    end_pos = iend_pos + 8
                    if len(content) > end_pos:
                        return False, f"Hidden data found after PNG end marker ({len(content) - end_pos} bytes)"
            
            # For JPEG files
            elif file_path.lower().endswith(('.jpg', '.jpeg')):
                # JPEG files end with an EOI marker (0xFFD9)
                eoi_pos = content.rfind(b'\xFF\xD9')
                if eoi_pos != -1:
                    end_pos = eoi_pos + 2
                    if len(content) > end_pos:
                        return False, f"Hidden data found after JPEG end marker ({len(content) - end_pos} bytes)"
            
            # For GIF files
            elif file_path.lower().endswith('.gif'):
                # GIF files end with a trailer (0x3B)
                if content[-1] == 0x3B and len(content) > 1:
                    # Check if there's data after the trailer
                    trailer_pos = content.rfind(b'\x3B')
                    if trailer_pos != len(content) - 1:
                        return False, f"Hidden data found after GIF end marker ({len(content) - trailer_pos - 1} bytes)"
            
            return True, "No hidden data detected"
            
        except Exception as e:
            # If there's an error, log it but don't block the file
            return True, f"Error checking for hidden data: {str(e)}"
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about security checks."""
        return self.security_stats


class ProxyManager:
    def __init__(self, proxies: List[str], selection_method: str = "random", proxy_type: str = "http"):
        self.proxies = proxies
        self.selection_method = selection_method
        self.proxy_type = proxy_type
        self.current_index = 0
        self.proxy_stats = {proxy: {"success": 0, "failure": 0} for proxy in proxies}
        
    def get_proxy(self) -> Optional[str]:
        """Get a proxy based on the selection method."""
        if not self.proxies:
            return None
            
        if self.selection_method == "random":
            return random.choice(self.proxies)
        else:  # rotate
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            return proxy
    
    def create_connector(self, proxy: Optional[str] = None) -> Optional[ProxyConnector]:
        """Create a connector for the given proxy."""
        if not proxy:
            return None
        
        # If the proxy URL already includes the protocol, use it directly
        if proxy.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
            return ProxyConnector.from_url(proxy)
        
        # Handle PacketStream proxy format: username:password_country-CountryName:host:port
        if ':' in proxy and not proxy.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
            try:
                parts = proxy.split(':')
                if len(parts) == 4:  # username:password:host:port format
                    username = parts[0]
                    password = parts[1]
                    host = parts[2]
                    port = parts[3]
                    
                    # Check if password contains country info and extract it
                    if '_country-' in password:
                        password = password.split('_country-')[0]
                    
                    # Create the proxy URL with the configured proxy type
                    proxy_url = f"{self.proxy_type}://{username}:{password}@{host}:{port}"
                    return ProxyConnector.from_url(proxy_url)
            except Exception as e:
                print(f"Error parsing proxy format: {e}")
        
        # Fallback: prepend the configured proxy type
        proxy_url = f"{self.proxy_type}://{proxy}"
        return ProxyConnector.from_url(proxy_url)
    
    def record_success(self, proxy: str) -> None:
        """Record a successful request with the given proxy."""
        if proxy in self.proxy_stats:
            self.proxy_stats[proxy]["success"] += 1
    
    def record_failure(self, proxy: str) -> None:
        """Record a failed request with the given proxy."""
        if proxy in self.proxy_stats:
            self.proxy_stats[proxy]["failure"] += 1
    
    def get_stats(self) -> dict:
        """Get statistics about proxy usage."""
        return self.proxy_stats


def clear_screen():
    if sys.platform == 'linux' or sys.platform == 'linux2':
        os.system('clear')
    elif sys.platform == 'win32':
        os.system('cls')

def random_string(length=6):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

def format_elapsed_time(seconds):
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"

async def download_image(session, url, folder_name, random_filename, security_manager=None, isolation_manager=None):
    """Download an image and optionally perform security checks."""
    # Sanitize the filename to prevent path traversal attacks
    safe_filename = sanitize_filename(random_filename)
    
    # Create a safe path that is guaranteed to be within the base directory
    file_path = create_safe_path(folder_name, safe_filename)
    extension = os.path.splitext(safe_filename)[1]
    
    # The session already has the proxy configuration from check_url
    async with session.get(url) as image_data:
        if image_data.status == 200:
            content = await image_data.read()
            if content:
                # Save the file first
                os.makedirs(folder_name, exist_ok=True)
                async with aiofiles.open(file_path, mode='wb') as f:
                    await f.write(content)
                
                # Perform security checks if enabled
                if security_manager:
                    # Verify file type
                    is_valid_type, type_reason = security_manager.verify_file(file_path, extension)
                    if not is_valid_type:
                        print(f"Security warning: {type_reason} - {file_path}")
                        
                        # If isolation manager is available, isolate the file
                        if isolation_manager:
                            isolated_path = await isolation_manager.isolate_file(
                                file_path, 
                                type_reason, 
                                "unknown"
                            )
                            if isolated_path:
                                print(f"File isolated to: {isolated_path}")
                                # Remove the original file if it was successfully isolated
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                        else:
                            # Fallback to simple quarantine
                            quarantine_dir = os.path.join(folder_name, "quarantine")
                            os.makedirs(quarantine_dir, exist_ok=True)
                            quarantine_path = os.path.join(quarantine_dir, random_filename)
                            os.rename(file_path, quarantine_path)
                        
                        return False
                    
                    # Scan for malicious content
                    is_safe, safety_reason = security_manager.scan_file_for_malicious_content(file_path)
                    if not is_safe:
                        print(f"Security warning: {safety_reason} - {file_path}")
                        
                        # If isolation manager is available, isolate the file
                        if isolation_manager:
                            isolated_path = await isolation_manager.isolate_file(
                                file_path, 
                                safety_reason, 
                                "malware"
                            )
                            if isolated_path:
                                print(f"File isolated to: {isolated_path}")
                                # Remove the original file if it was successfully isolated
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                        else:
                            # Fallback to simple quarantine
                            quarantine_dir = os.path.join(folder_name, "quarantine")
                            os.makedirs(quarantine_dir, exist_ok=True)
                            quarantine_path = os.path.join(quarantine_dir, random_filename)
                            os.rename(file_path, quarantine_path)
                        
                        return False
                    
                    # Check for steganography if enabled
                    if security_manager.steg_enabled and security_manager.unblob_available:
                        has_steg, steg_reason = security_manager.detect_steganography(file_path)
                        if has_steg and security_manager.isolate_steg_files:
                            print(f"Steganography detected: {steg_reason} - {file_path}")
                            
                            # If isolation manager is available, isolate the file
                            if isolation_manager:
                                isolated_path = await isolation_manager.isolate_file(
                                    file_path, 
                                    steg_reason, 
                                    "unknown"  # Could be malware or adult content
                                )
                                if isolated_path:
                                    print(f"File with steganography isolated to: {isolated_path}")
                                    # We keep the original file since steganography is not necessarily malicious
                            else:
                                # Fallback to simple steganography folder
                                steg_dir = os.path.join(folder_name, "steganography")
                                os.makedirs(steg_dir, exist_ok=True)
                                steg_path = os.path.join(steg_dir, random_filename)
                                # Copy instead of move, since steganography is not necessarily malicious
                                with open(file_path, 'rb') as src:
                                    with open(steg_path, 'wb') as dst:
                                        dst.write(src.read())
                
                return True
    
    return False

async def save_valid_url(folder_name, url):
    os.makedirs(folder_name, exist_ok=True)
    # Create a safe path for the valids.txt file
    safe_path = create_safe_path(folder_name, "valids.txt")
    async with aiofiles.open(safe_path, "a") as file:
        await file.write(url + "\n")

def status_board(proxy_manager=None, security_manager=None, isolation_manager=None, rate_limiter=None):
    global urls_scanned, valid_found, start_time, status_board_running

    while status_board_running:
        if urls_scanned > 0:
            elapsed_time = time.time() - start_time
            formatted_elapsed_time = format_elapsed_time(elapsed_time)

            # Basic stats
            sys.stdout.write('\033[5;1H[-----------------------]\n')
            sys.stdout.write(f'\033[7;1H TIME ELAPSED : {formatted_elapsed_time}\n')
            sys.stdout.write(f'\033[8;1H CHECKS       : {urls_scanned:,}\n')
            sys.stdout.write(f'\033[9;1H HITS         : {valid_found:,}\n')
            sys.stdout.write(f'\033[6;1H PER SECOND   : {int(urls_scanned / elapsed_time):,}\n')
            sys.stdout.write('\033[10;1H[-----------------------]\n')
            
            line = 12
            
            # Security stats if available
            if security_manager:
                security_stats = security_manager.get_stats()
                sys.stdout.write(f'\033[{line};1H[------ SECURITY ------]\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H VERIFIED FILES  : {security_stats["verified"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H TYPE MISMATCHES : {security_stats["type_mismatch"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H MALICIOUS FILES : {security_stats["malicious_detected"]:,}\n')
                line += 1
                
                # Steganography stats if enabled
                if security_manager.steg_enabled and security_manager.unblob_available:
                    sys.stdout.write(f'\033[{line};1H STEG SCANNED   : {security_stats["steg_scanned"]:,}\n')
                    line += 1
                    sys.stdout.write(f'\033[{line};1H STEG DETECTED  : {security_stats["steg_detected"]:,}\n')
                    line += 1
                
                # Advanced security stats if enabled
                if security_manager.advanced_enabled:
                    if security_manager.signature_enabled:
                        sys.stdout.write(f'\033[{line};1H SIGNATURE MATCH : {security_stats["signature_matches"]:,}\n')
                        line += 1
                    
                    if security_manager.entropy_enabled:
                        sys.stdout.write(f'\033[{line};1H HIGH ENTROPY   : {security_stats["high_entropy_files"]:,}\n')
                        line += 1
                    
                    if security_manager.header_enabled:
                        sys.stdout.write(f'\033[{line};1H HEADER ANOMALY : {security_stats["header_anomalies"]:,}\n')
                        line += 1
                    
                    if security_manager.cert_pinning_enabled:
                        sys.stdout.write(f'\033[{line};1H CERT FAILURES  : {security_stats["cert_pinning_failures"]:,}\n')
                        line += 1
                
                sys.stdout.write(f'\033[{line};1H[-----------------------]\n')
                line += 2
            
            # Isolation stats if available
            if isolation_manager:
                isolation_stats = isolation_manager.get_stats()
                sys.stdout.write(f'\033[{line};1H[------ ISOLATION -----]\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H MALWARE ISOLATED : {isolation_stats["malware_isolated"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H ADULT ISOLATED   : {isolation_stats["adult_isolated"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H UNKNOWN ISOLATED : {isolation_stats["unknown_isolated"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H REPORTS GENERATED: {isolation_stats["reports_generated"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H[-----------------------]\n')
                line += 2
            
            # Rate limiting stats if available
            if rate_limiter:
                rate_stats = rate_limiter.get_stats()
                sys.stdout.write(f'\033[{line};1H[---- RATE LIMITS ----]\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H RATE LIMITED     : {rate_stats["rate_limited"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H COOLDOWNS        : {rate_stats["cooldowns"]:,}\n')
                line += 1
                sys.stdout.write(f'\033[{line};1H[-----------------------]\n')
                line += 2
            
            # Proxy stats if available
            if proxy_manager and proxy_manager.proxies:
                proxy_stats = proxy_manager.get_stats()
                sys.stdout.write(f'\033[{line};1H[------ PROXIES ------]\n')
                line += 1
                for i, (proxy, stats) in enumerate(proxy_stats.items(), 1):
                    # Truncate proxy URL to keep display clean
                    proxy_display = proxy
                    if len(proxy_display) > 30:
                        proxy_display = proxy_display[:27] + "..."
                    
                    total = stats["success"] + stats["failure"]
                    success_rate = (stats["success"] / total * 100) if total > 0 else 0
                    
                    sys.stdout.write(f'\033[{line};1H {i:2d}. {proxy_display:<30} | '
                                    f'S: {stats["success"]:5d} | F: {stats["failure"]:5d} | '
                                    f'Rate: {success_rate:5.1f}%\n')
                    line += 1
                sys.stdout.write(f'\033[{line};1H[-----------------------]\n')
            
            sys.stdout.flush()
        time.sleep(update_rate)

async def check_url(thread_id, proxy_manager=None, security_manager=None, isolation_manager=None, rate_limiter=None):
    global urls_scanned, valid_found
    
    while True:
        # Apply rate limiting if enabled
        if rate_limiter:
            # Wait if we're rate limited
            while await rate_limiter.wait_if_needed(thread_id):
                # If we're rate limited, wait a bit before trying again
                await asyncio.sleep(1)
        
        # Get a proxy for this session
        proxy = None if proxy_manager is None else proxy_manager.get_proxy()
        
        # Create session options
        session_kwargs = {}
        if proxy:
            # For PacketStream proxies and SOCKS proxies, we need to use a connector
            if ':' in proxy and not proxy.startswith(('http://', 'https://')):
                connector = proxy_manager.create_connector(proxy)
                if connector:
                    session_kwargs["connector"] = connector
            else:
                # For HTTP/HTTPS proxies with standard format, we can use the proxy parameter
                session_kwargs["proxy"] = proxy
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            for ext in file_extensions:
                filename = random_string() + ext
                random_url = URL + filename
                try:
                    async with session.get(random_url, timeout=5) as response:
                        urls_scanned += 1

                        if response.status == 200:
                            valid_found += 1
                            os.makedirs(ext.strip('.'), exist_ok=True)
                            
                            # Download and verify the file
                            download_success = await download_image(
                                session, 
                                random_url, 
                                ext.strip('.'), 
                                filename,
                                security_manager,
                                isolation_manager
                            )
                            
                            if download_success:
                                await save_valid_url(ext.strip('.'), random_url)
                                
                                # Record successful proxy use
                                if proxy and proxy_manager:
                                    proxy_manager.record_success(proxy)

                except (asyncio.exceptions.TimeoutError, 
                        ConnectionResetError, 
                        aiohttp.ClientConnectorError,
                        aiohttp.ClientProxyConnectionError,
                        aiohttp.ClientHttpProxyError):
                    # Record failed proxy use
                    if proxy and proxy_manager:
                        proxy_manager.record_failure(proxy)
                    continue
                except Exception as e:
                    print(f"Exception {type(e).__name__}: {e}")
                    # Record failed proxy use for unexpected errors
                    if proxy and proxy_manager:
                        proxy_manager.record_failure(proxy)


if __name__ == "__main__":
    clear_screen()
    print(" CATBOX SCRAPER")
    print("[==============]")
    print("    BY DOOT\n")
    
    # Initialize proxy manager if proxies are enabled in config
    proxy_manager = None
    if 'proxies' in config and config['proxies'].get('enabled', False):
        proxy_list = config['proxies'].get('list', [])
        if proxy_list:
            selection_method = config['proxies'].get('selection_method', 'random')
            proxy_type = config['proxies'].get('proxy_type', 'http')
            proxy_manager = ProxyManager(proxy_list, selection_method, proxy_type)
            print(f" USING {len(proxy_list)} PROXIES ({selection_method.upper()} MODE, {proxy_type.upper()} TYPE)")
        else:
            print(" PROXY ENABLED BUT NO PROXIES CONFIGURED")
    else:
        print(" USING LOCAL IP (NO PROXIES)")
    
    # Initialize rate limiter if rate limiting is enabled in config
    rate_limiter = None
    if 'security' in config and 'rate_limiting' in config['security'] and config['security']['rate_limiting'].get('enabled', False):
        requests_per_minute = config['security']['rate_limiting'].get('requests_per_minute', 60)
        cooldown_time = config['security']['rate_limiting'].get('cooldown_time', 5)
        rate_limiter = RateLimiter(requests_per_minute, cooldown_time)
        print(f" RATE LIMITING ENABLED ({requests_per_minute} REQUESTS/MINUTE, {cooldown_time}s COOLDOWN)")
    
    # Initialize isolation manager if isolation is enabled in config
    isolation_manager = None
    if 'security' in config and 'isolation' in config['security'] and config['security']['isolation'].get('enabled', False):
        malware_folder = config['security']['isolation'].get('malware_folder', 'malware')
        adult_folder = config['security']['isolation'].get('adult_folder', 'adult')
        unknown_folder = config['security']['isolation'].get('unknown_folder', 'unknown')
        generate_reports = config['security']['isolation'].get('generate_reports', True)
        isolation_manager = IsolationManager(
            base_dir="isolated",
            malware_folder=malware_folder,
            adult_folder=adult_folder,
            unknown_folder=unknown_folder,
            generate_reports=generate_reports
        )
        print(f" ISOLATION ENABLED (REPORTS: {'ENABLED' if generate_reports else 'DISABLED'})")
    
    # Initialize security manager if security is enabled in config
    security_manager = None
    if 'security' in config and config['security'].get('enabled', False):
        verify_file_type = config['security'].get('verify_file_type', True)
        scan_for_malicious = config['security'].get('scan_for_malicious', True)
        steg_detection = config['security'].get('steganography', {})
        advanced_security = config['security'].get('advanced_security', {})
        
        security_manager = SecurityManager(
            verify_file_type=verify_file_type,
            scan_for_malicious=scan_for_malicious,
            steg_detection=steg_detection,
            advanced_security=advanced_security
        )
        
        print(f" SECURITY ENABLED (Verify: {verify_file_type}, Scan: {scan_for_malicious})")
        
        # Print steganography detection status
        if steg_detection.get('enabled', False):
            steg_level = steg_detection.get('detection_level', 'normal')
            if security_manager.unblob_available:
                print(f" STEGANOGRAPHY DETECTION ENABLED ({steg_level.upper()} LEVEL)")
            else:
                print(" STEGANOGRAPHY DETECTION ENABLED BUT UNBLOB NOT FOUND")
        
        # Print advanced security status
        if advanced_security.get('enabled', False):
            print(" ADVANCED SECURITY ENABLED:")
            
            if advanced_security.get('signature_detection', {}).get('enabled', False):
                print("   - SIGNATURE DETECTION")
            
            if advanced_security.get('entropy_analysis', {}).get('enabled', False):
                threshold = advanced_security.get('entropy_analysis', {}).get('threshold', 7.0)
                print(f"   - ENTROPY ANALYSIS (THRESHOLD: {threshold})")
            
            if advanced_security.get('header_analysis', {}).get('enabled', False):
                print("   - HEADER ANALYSIS")
            
            if advanced_security.get('certificate_pinning', {}).get('enabled', False):
                print("   - CERTIFICATE PINNING")
    else:
        print(" SECURITY DISABLED")
    
    print(' STARTING...')
    
    # Start status board with all managers
    status_thread = threading.Thread(
        target=status_board, 
        args=(proxy_manager, security_manager, isolation_manager, rate_limiter), 
        daemon=True
    )
    status_thread.start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Create tasks with proxy manager, security manager, isolation manager, and rate limiter
    tasks = [check_url(i, proxy_manager, security_manager, isolation_manager, rate_limiter) for i in range(threads)]
    try:
        loop.run_until_complete(asyncio.gather(*tasks))
    except KeyboardInterrupt:
        status_board_running = False
        sys.exit("Stopped!")
