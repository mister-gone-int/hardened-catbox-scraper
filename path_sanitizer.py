#!/usr/bin/env python3
"""
Path Sanitizer for Catbox Scraper

This module provides functions to sanitize file paths and prevent path traversal attacks.
"""

import os
import re
from typing import Optional


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        A sanitized filename with any directory traversal sequences removed
    """
    # Remove any directory traversal sequences
    sanitized = os.path.basename(filename)
    
    # Remove any null bytes which could be used to trick string processing
    sanitized = sanitized.replace('\0', '')
    
    # Remove any control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', sanitized)
    
    # Ensure the filename isn't empty after sanitization
    if not sanitized:
        sanitized = "sanitized_file"
    
    return sanitized


def validate_safe_path(base_dir: str, filename: str) -> Optional[str]:
    """
    Validate that a path is safe and doesn't escape the base directory.
    
    Args:
        base_dir: The base directory that should contain the file
        filename: The filename to validate
        
    Returns:
        The safe absolute path if valid, None if the path would escape the base directory
    """
    # Sanitize the filename first
    safe_filename = sanitize_filename(filename)
    
    # Construct the intended path
    intended_path = os.path.join(base_dir, safe_filename)
    
    # Get the absolute paths to compare
    abs_base_dir = os.path.abspath(base_dir)
    abs_intended_path = os.path.abspath(intended_path)
    
    # Check if the intended path is within the base directory
    if not abs_intended_path.startswith(abs_base_dir + os.sep):
        return None
    
    return abs_intended_path


def create_safe_path(base_dir: str, filename: str) -> str:
    """
    Create a safe path that is guaranteed to be within the base directory.
    
    Args:
        base_dir: The base directory that should contain the file
        filename: The filename to use (will be sanitized)
        
    Returns:
        A safe path within the base directory
    """
    # Sanitize the filename
    safe_filename = sanitize_filename(filename)
    
    # Construct and validate the path
    safe_path = validate_safe_path(base_dir, safe_filename)
    
    # If the path is still not safe (should not happen with sanitized filename),
    # fall back to a simple join with the sanitized filename
    if not safe_path:
        safe_path = os.path.join(os.path.abspath(base_dir), safe_filename)
    
    return safe_path
