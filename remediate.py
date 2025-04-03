#!/usr/bin/env python3
"""
Catbox Scraper - Remediation Tool

This script provides tools to safely handle potentially malicious files
that were isolated by the Catbox Scraper. It offers multiple remediation
options including safe viewing, sanitization, and preparation for submission
to security services.
"""

import os
import sys
import argparse
import json
import hashlib
import datetime
import io
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image


class RemediationTool:
    """Tools for safely handling potentially malicious files."""
    
    def __init__(self, isolated_dir: str = "isolated"):
        """
        Initialize the RemediationTool.
        
        Args:
            isolated_dir: Base directory containing isolated files
        """
        self.isolated_dir = isolated_dir
        self.malware_dir = os.path.join(isolated_dir, "malware")
        self.adult_dir = os.path.join(isolated_dir, "adult")
        self.unknown_dir = os.path.join(isolated_dir, "unknown")
        self.safe_dir = os.path.join(isolated_dir, "safe")
        
        # Create safe directory if it doesn't exist
        os.makedirs(self.safe_dir, exist_ok=True)
        
        # Log file for remediation actions
        self.log_file = os.path.join(isolated_dir, "remediation_log.json")
        self.log = self._load_log()
    
    def _load_log(self) -> Dict[str, Any]:
        """Load the existing log or create a new one."""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Could not parse log file {self.log_file}, creating new log")
        
        return {
            "sanitized_files": [],
            "submitted_files": [],
            "deleted_files": []
        }
    
    def _save_log(self) -> None:
        """Save the current log to disk."""
        with open(self.log_file, 'w') as f:
            json.dump(self.log, f, indent=2)
    
    def list_isolated_files(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all isolated files, optionally filtered by category.
        
        Args:
            category: Optional category filter ("malware", "adult", "unknown")
            
        Returns:
            List of file information dictionaries
        """
        result = []
        
        # Determine which directories to scan
        if category == "malware":
            dirs = [self.malware_dir]
        elif category == "adult":
            dirs = [self.adult_dir]
        elif category == "unknown":
            dirs = [self.unknown_dir]
        else:
            dirs = [self.malware_dir, self.adult_dir, self.unknown_dir]
        
        # Scan each directory
        for dir_path in dirs:
            if not os.path.exists(dir_path):
                continue
                
            category_name = os.path.basename(dir_path)
            
            for filename in os.listdir(dir_path):
                # Skip report files
                if filename.endswith(".report.txt"):
                    continue
                
                file_path = os.path.join(dir_path, filename)
                if not os.path.isfile(file_path):
                    continue
                
                # Check if there's a report file
                report_path = f"{file_path}.report.txt"
                report_info = {}
                
                if os.path.exists(report_path):
                    try:
                        with open(report_path, 'r') as f:
                            report_text = f.read()
                            
                            # Extract basic info from the report
                            for line in report_text.split('\n'):
                                if ': ' in line:
                                    key, value = line.split(': ', 1)
                                    report_info[key.strip()] = value.strip()
                    except:
                        pass
                
                # Get file stats
                try:
                    file_size = os.path.getsize(file_path)
                    
                    # Calculate file hash
                    with open(file_path, 'rb') as f:
                        file_data = f.read(1024 * 1024)  # Read up to 1MB for hash
                        file_hash = hashlib.sha256(file_data).hexdigest()
                    
                    result.append({
                        "filename": filename,
                        "path": file_path,
                        "category": category_name,
                        "size": file_size,
                        "hash": file_hash,
                        "report": report_info
                    })
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
        
        return result
    
    def sanitize_image(self, file_path: str) -> Optional[str]:
        """
        Sanitize an image by extracting only the pixel data and creating a new, clean image.
        
        Args:
            file_path: Path to the potentially malicious image
            
        Returns:
            Path to the sanitized image, or None if sanitization failed
        """
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} does not exist")
            return None
        
        try:
            # Calculate hash of the original file
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Check if we've already sanitized this file
            for entry in self.log["sanitized_files"]:
                if entry["original_hash"] == file_hash:
                    sanitized_path = entry["sanitized_path"]
                    if os.path.exists(sanitized_path):
                        print(f"Already sanitized: {file_path} -> {sanitized_path}")
                        return sanitized_path
            
            # Try to open as an image
            try:
                # Use a BytesIO buffer to avoid writing the potentially malicious image to disk again
                image = Image.open(io.BytesIO(file_data))
                
                # Convert to RGB if it's not already (handles transparency, etc.)
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                # Get the raw pixel data
                pixel_data = image.getdata()
                
                # Create a new image with just the pixel data
                sanitized_image = Image.new('RGB', image.size)
                sanitized_image.putdata(pixel_data)
                
                # Save the sanitized image with a new name
                filename = os.path.basename(file_path)
                name, ext = os.path.splitext(filename)
                sanitized_filename = f"{name}_safe.png"
                sanitized_path = os.path.join(self.safe_dir, sanitized_filename)
                
                # Save as PNG, which is generally safer than other formats
                sanitized_image.save(sanitized_path, "PNG")
                
                # Log the sanitization
                self.log["sanitized_files"].append({
                    "original_path": file_path,
                    "original_hash": file_hash,
                    "sanitized_path": sanitized_path,
                    "sanitized_at": datetime.datetime.now().isoformat(),
                    "original_size": os.path.getsize(file_path),
                    "sanitized_size": os.path.getsize(sanitized_path),
                    "dimensions": f"{image.width}x{image.height}"
                })
                self._save_log()
                
                print(f"Sanitized: {file_path} -> {sanitized_path}")
                return sanitized_path
                
            except Exception as e:
                print(f"Error sanitizing image {file_path}: {str(e)}")
                print("This file may not be an image or may be corrupted.")
                return None
                
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")
            return None
    
    def prepare_for_submission(self, file_path: str, service: str = "virustotal") -> Optional[str]:
        """
        Prepare a file for submission to a security service.
        
        Args:
            file_path: Path to the file to prepare
            service: Security service to prepare for ("virustotal", "hybrid-analysis")
            
        Returns:
            Path to the prepared submission package, or None if preparation failed
        """
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} does not exist")
            return None
        
        try:
            # Create a submission directory
            submission_dir = os.path.join(self.isolated_dir, "submissions")
            os.makedirs(submission_dir, exist_ok=True)
            
            # Create a unique submission package
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(file_path)
            submission_name = f"{timestamp}_{filename}_submission"
            submission_path = os.path.join(submission_dir, submission_name)
            os.makedirs(submission_path, exist_ok=True)
            
            # Copy the file to the submission package
            submission_file = os.path.join(submission_path, filename)
            shutil.copy2(file_path, submission_file)
            
            # Create a submission info file
            info = {
                "original_file": file_path,
                "submission_time": datetime.datetime.now().isoformat(),
                "service": service,
                "file_hash": {
                    "sha256": hashlib.sha256(open(file_path, 'rb').read()).hexdigest(),
                    "md5": hashlib.md5(open(file_path, 'rb').read()).hexdigest()
                },
                "file_size": os.path.getsize(file_path)
            }
            
            # Add report info if available
            report_path = f"{file_path}.report.txt"
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    info["original_report"] = f.read()
            
            # Write the submission info
            with open(os.path.join(submission_path, "submission_info.json"), 'w') as f:
                json.dump(info, f, indent=2)
            
            # Create a README with submission instructions
            readme_content = f"""
SUBMISSION INSTRUCTIONS FOR {service.upper()}

File: {filename}
SHA256: {info['file_hash']['sha256']}
MD5: {info['file_hash']['md5']}

CAUTION: This file has been flagged as potentially malicious.
Handle with care and only submit using appropriate security precautions.

Submission Steps for {service}:
"""
            
            if service == "virustotal":
                readme_content += """
1. Go to https://www.virustotal.com/
2. Click "Choose file" and select the file from this package
3. Click "Scan it!"
4. Wait for the analysis to complete
5. Save the analysis report for your records
"""
            elif service == "hybrid-analysis":
                readme_content += """
1. Go to https://www.hybrid-analysis.com/
2. Create an account or log in if you haven't already
3. Click "Upload" and select the file from this package
4. Set appropriate analysis options
5. Click "Submit"
6. Wait for the analysis to complete
7. Save the analysis report for your records
"""
            
            # Write the README
            with open(os.path.join(submission_path, "README.txt"), 'w') as f:
                f.write(readme_content)
            
            # Log the submission preparation
            self.log["submitted_files"].append({
                "original_path": file_path,
                "submission_path": submission_path,
                "service": service,
                "prepared_at": datetime.datetime.now().isoformat()
            })
            self._save_log()
            
            print(f"Prepared for submission to {service}: {submission_path}")
            return submission_path
            
        except Exception as e:
            print(f"Error preparing {file_path} for submission: {str(e)}")
            return None
    
    def delete_file(self, file_path: str, secure: bool = False) -> bool:
        """
        Delete a file, optionally using secure deletion.
        
        Args:
            file_path: Path to the file to delete
            secure: Whether to use secure deletion (overwrite before delete)
            
        Returns:
            True if deletion was successful, False otherwise
        """
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} does not exist")
            return False
        
        try:
            # Calculate hash before deletion for logging
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            file_size = os.path.getsize(file_path)
            
            if secure:
                # Secure deletion by overwriting with random data
                try:
                    # Try using shred on Linux
                    if sys.platform.startswith('linux'):
                        subprocess.run(["shred", "-u", "-z", "-n", "3", file_path], check=True)
                        deleted = True
                    else:
                        # Manual secure deletion
                        with open(file_path, 'wb') as f:
                            # Overwrite with zeros
                            f.write(b'\x00' * file_size)
                            f.flush()
                            os.fsync(f.fileno())
                            
                            # Overwrite with ones
                            f.seek(0)
                            f.write(b'\xff' * file_size)
                            f.flush()
                            os.fsync(f.fileno())
                            
                            # Overwrite with random data
                            f.seek(0)
                            f.write(os.urandom(file_size))
                            f.flush()
                            os.fsync(f.fileno())
                        
                        # Now delete the file
                        os.unlink(file_path)
                        deleted = True
                except Exception as e:
                    print(f"Secure deletion failed, falling back to regular deletion: {str(e)}")
                    os.unlink(file_path)
                    deleted = True
            else:
                # Regular deletion
                os.unlink(file_path)
                deleted = True
            
            # Also delete the report file if it exists
            report_path = f"{file_path}.report.txt"
            if os.path.exists(report_path):
                os.unlink(report_path)
            
            # Log the deletion
            self.log["deleted_files"].append({
                "path": file_path,
                "hash": file_hash,
                "size": file_size,
                "secure_deletion": secure,
                "deleted_at": datetime.datetime.now().isoformat()
            })
            self._save_log()
            
            print(f"{'Securely ' if secure else ''}Deleted: {file_path}")
            return True
            
        except Exception as e:
            print(f"Error deleting {file_path}: {str(e)}")
            return False


def interactive_mode(tool: RemediationTool):
    """Run the tool in interactive mode."""
    while True:
        print("\nCATBOX SCRAPER REMEDIATION TOOL")
        print("==============================")
        print("1. List isolated files")
        print("2. Sanitize an image")
        print("3. Prepare a file for submission")
        print("4. Delete a file")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            print("\nIsolated Files:")
            print("---------------")
            
            category_choice = input("Filter by category? (m)alware, (a)dult, (u)nknown, or (all): ").lower()
            
            if category_choice.startswith("m"):
                category = "malware"
            elif category_choice.startswith("a"):
                category = "adult"
            elif category_choice.startswith("u"):
                category = "unknown"
            else:
                category = None
            
            files = tool.list_isolated_files(category)
            
            if not files:
                print("No isolated files found.")
                continue
            
            print(f"\nFound {len(files)} isolated files:")
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']} ({file_info['category']}, {file_info['size']} bytes)")
                if file_info['report'] and 'Isolation Reason' in file_info['report']:
                    print(f"   Reason: {file_info['report']['Isolation Reason']}")
            
        elif choice == "2":
            files = tool.list_isolated_files()
            
            if not files:
                print("No isolated files found.")
                continue
            
            print("\nSelect an image to sanitize:")
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']} ({file_info['category']})")
            
            try:
                file_idx = int(input("\nEnter file number: ")) - 1
                if 0 <= file_idx < len(files):
                    file_path = files[file_idx]['path']
                    sanitized_path = tool.sanitize_image(file_path)
                    
                    if sanitized_path:
                        print(f"Sanitized image saved to: {sanitized_path}")
                        
                        # Try to open the sanitized image
                        open_choice = input("Open the sanitized image? (y/n): ").lower()
                        if open_choice.startswith("y"):
                            # On Linux
                            if sys.platform.startswith('linux'):
                                try:
                                    subprocess.run(["xdg-open", sanitized_path])
                                except:
                                    print("Could not open the image automatically.")
                            # On macOS
                            elif sys.platform == 'darwin':
                                try:
                                    subprocess.run(["open", sanitized_path])
                                except:
                                    print("Could not open the image automatically.")
                            # On Windows
                            elif sys.platform == 'win32':
                                try:
                                    os.startfile(sanitized_path)
                                except:
                                    print("Could not open the image automatically.")
                else:
                    print("Invalid file number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            
        elif choice == "3":
            files = tool.list_isolated_files()
            
            if not files:
                print("No isolated files found.")
                continue
            
            print("\nSelect a file to prepare for submission:")
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']} ({file_info['category']})")
            
            try:
                file_idx = int(input("\nEnter file number: ")) - 1
                if 0 <= file_idx < len(files):
                    file_path = files[file_idx]['path']
                    
                    print("\nSelect a service:")
                    print("1. VirusTotal")
                    print("2. Hybrid Analysis")
                    
                    service_choice = input("\nEnter service number (1-2): ")
                    
                    if service_choice == "1":
                        service = "virustotal"
                    elif service_choice == "2":
                        service = "hybrid-analysis"
                    else:
                        print("Invalid service. Using VirusTotal.")
                        service = "virustotal"
                    
                    submission_path = tool.prepare_for_submission(file_path, service)
                    
                    if submission_path:
                        print(f"Submission package created at: {submission_path}")
                        print(f"Follow the instructions in {os.path.join(submission_path, 'README.txt')}")
                else:
                    print("Invalid file number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            
        elif choice == "4":
            files = tool.list_isolated_files()
            
            if not files:
                print("No isolated files found.")
                continue
            
            print("\nSelect a file to delete:")
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']} ({file_info['category']})")
            
            try:
                file_idx = int(input("\nEnter file number: ")) - 1
                if 0 <= file_idx < len(files):
                    file_path = files[file_idx]['path']
                    
                    secure_choice = input("Use secure deletion? (y/n): ").lower()
                    secure = secure_choice.startswith("y")
                    
                    confirm = input(f"Are you sure you want to {'securely ' if secure else ''}delete {files[file_idx]['filename']}? (y/n): ").lower()
                    if confirm.startswith("y"):
                        success = tool.delete_file(file_path, secure)
                        if success:
                            print(f"File deleted successfully.")
                    else:
                        print("Deletion cancelled.")
                else:
                    print("Invalid file number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            
        elif choice == "5":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")
        
        input("\nPress Enter to continue...")


def main():
    """Command-line interface for the RemediationTool."""
    parser = argparse.ArgumentParser(description="Catbox Scraper Remediation Tool")
    parser.add_argument("--isolated-dir", default="isolated", help="Base directory containing isolated files")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run in interactive mode")
    parser.add_argument("--list", "-l", action="store_true", help="List isolated files")
    parser.add_argument("--category", "-c", choices=["malware", "adult", "unknown"], help="Filter by category when listing")
    parser.add_argument("--sanitize", "-s", help="Sanitize an image file")
    parser.add_argument("--prepare", "-p", help="Prepare a file for submission")
    parser.add_argument("--service", choices=["virustotal", "hybrid-analysis"], default="virustotal", help="Service to prepare for")
    parser.add_argument("--delete", "-d", help="Delete a file")
    parser.add_argument("--secure", action="store_true", help="Use secure deletion")
    
    args = parser.parse_args()
    
    tool = RemediationTool(isolated_dir=args.isolated_dir)
    
    # Interactive mode
    if args.interactive:
        interactive_mode(tool)
        return
    
    # List files
    if args.list:
        files = tool.list_isolated_files(args.category)
        if not files:
            print("No isolated files found.")
        else:
            print(f"Found {len(files)} isolated files:")
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']} ({file_info['category']}, {file_info['size']} bytes)")
                if file_info['report'] and 'Isolation Reason' in file_info['report']:
                    print(f"   Reason: {file_info['report']['Isolation Reason']}")
    
    # Sanitize an image
    if args.sanitize:
        sanitized_path = tool.sanitize_image(args.sanitize)
        if sanitized_path:
            print(f"Sanitized image saved to: {sanitized_path}")
    
    # Prepare for submission
    if args.prepare:
        submission_path = tool.prepare_for_submission(args.prepare, args.service)
        if submission_path:
            print(f"Submission package created at: {submission_path}")
            print(f"Follow the instructions in {os.path.join(submission_path, 'README.txt')}")
    
    # Delete a file
    if args.delete:
        success = tool.delete_file(args.delete, args.secure)
        if success:
            print(f"File deleted successfully.")


if __name__ == "__main__":
    main()
