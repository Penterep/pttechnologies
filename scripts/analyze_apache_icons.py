#!/usr/bin/env python3
"""
Apache Icons Analysis Script

This script downloads Apache tar.gz archives from the Apache archive,
extracts the icons folder from each version, and creates a text file
containing version, filename, and MD5 hash information.

Usage:
    python analyze_apache_icons.py [--start-version VERSION] [--output OUTPUT_FILE]
    
Example:
    python analyze_apache_icons.py --start-version 1.3.0 --output apache_icons.txt
"""

import argparse
import hashlib
import os
import re
import tarfile
import tempfile
from pathlib import Path
from typing import List, Tuple, Optional
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup


class ApacheIconsAnalyzer:
    """Analyzer for Apache icons across different versions."""
    
    BASE_URL = "https://archive.apache.org/dist/httpd/"
    
    def __init__(self, output_file: str = "apache_icons.txt", temp_dir: Optional[str] = None):
        """
        Initialize the analyzer.
        
        Args:
            output_file: Path to output text file
            temp_dir: Temporary directory for downloads (default: system temp)
        """
        self.output_file = output_file
        self.temp_dir = temp_dir or tempfile.mkdtemp(prefix="apache_icons_")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; ApacheIconsAnalyzer/1.0)'
        })
        
    def get_available_versions(self) -> List[str]:
        """
        Parse the Apache archive page to get all available tar.gz versions.
        
        Returns:
            List of version strings (e.g., ['2.2.1', '2.2.2', ...])
        """
        print(f"Fetching available versions from {self.BASE_URL}...")
        try:
            response = self.session.get(self.BASE_URL, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            versions = []
            
            # Both formats: apache_X.Y.Z.tar.gz (old) and httpd-X.Y.Z.tar.gz (new)
            for link in soup.find_all('a', href=True):
                href = link['href']
                text = link.get_text().strip()
                for source in [href, text]:
                    match = re.search(r'httpd-(\d+\.\d+\.\d+)\.tar\.gz', source)
                    if match:
                        version = match.group(1)
                        if version not in versions:
                            versions.append(version)
                        break
                    match = re.search(r'apache[_-](\d+\.\d+\.\d+)\.tar\.gz', source)
                    if match:
                        version = match.group(1)
                        if version not in versions:
                            versions.append(version)
                        break
            
            if not versions:
                matches_httpd = re.findall(r'httpd-(\d+\.\d+\.\d+)\.tar\.gz', response.text)
                matches_apache = re.findall(r'apache[_-](\d+\.\d+\.\d+)\.tar\.gz', response.text)
                versions = list(set(matches_httpd + matches_apache))
            
            def version_key(v):
                parts = v.split('.')
                return tuple(int(p) for p in parts)
            
            versions.sort(key=version_key)
            print(f"Found {len(versions)} Apache versions")
            return versions
            
        except Exception as e:
            print(f"Error fetching versions: {e}")
            return []
    
    def filter_versions_from(self, versions: List[str], start_version: str) -> List[str]:
        """
        Filter versions starting from the specified version.
        
        Args:
            versions: List of all available versions
            start_version: Version to start from (inclusive)
            
        Returns:
            Filtered list of versions
        """
        def version_key(v):
            parts = v.split('.')
            return tuple(int(p) for p in parts)
        
        start_key = version_key(start_version)
        filtered = [v for v in versions if version_key(v) >= start_key]
        return filtered
    
    def download_version(self, version: str) -> Optional[str]:
        """
        Download tar.gz archive for a specific version.
        
        Args:
            version: Apache version (e.g., '2.2.1' or '1.3.9')
            
        Returns:
            Path to downloaded file, or None if failed
        """

        major_version = int(version.split('.')[0])
        if major_version == 1:
            filename = f"apache_{version}.tar.gz"
        else:
            filename = f"httpd-{version}.tar.gz"
        
        url = urljoin(self.BASE_URL, filename)
        local_path = os.path.join(self.temp_dir, filename)
        
        if os.path.exists(local_path):
            print(f"  Using cached: {filename}")
            return local_path
        
        print(f"  Downloading {filename}...")
        try:
            response = self.session.get(url, stream=True, timeout=60)
            
            if response.status_code == 404:
                print(f"    Not found, trying alternative format...")
                if major_version == 1:
                    filename = f"httpd-{version}.tar.gz"
                else:
                    filename = f"apache_{version}.tar.gz"
                url = urljoin(self.BASE_URL, filename)
                local_path = os.path.join(self.temp_dir, filename)
                if os.path.exists(local_path):
                    print(f"  Using cached: {filename}")
                    return local_path
                response = self.session.get(url, stream=True, timeout=60)
            
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\r    Progress: {percent:.1f}%", end='', flush=True)
            
            print()
            return local_path
            
        except Exception as e:
            print(f"\n  Error downloading {filename}: {e}")
            if os.path.exists(local_path):
                os.remove(local_path)
            return None
    
    def extract_icons(self, tar_path: str, version: str) -> List[Tuple[str, str]]:
        """
        Extract icons folder from tar.gz archive and calculate MD5 hashes.
        
        Args:
            tar_path: Path to tar.gz file
            version: Apache version
            
        Returns:
            List of tuples (filename, md5_hash)
        """
        icon_files = []
        
        try:
            with tarfile.open(tar_path, 'r:gz') as tar:
                members = tar.getmembers()
                
                major_version = int(version.split('.')[0])
                if major_version == 1:
                    base_dir = f'apache_{version}'
                else:
                    base_dir = f'httpd-{version}'
                
                possible_paths = [
                    f'{base_dir}/icons/',
                    f'{base_dir}/htdocs/icons/',
                    f'{base_dir}/docs/icons/',
                    f'{base_dir}/share/httpd/icons/',
                    f'{base_dir}/src/icons/',
                    'icons/',
                    'htdocs/icons/',
                    'docs/icons/',
                ]
                
                icon_members = []
                used_base_path = None
                for base_path in possible_paths:
                    icon_members = [
                        m for m in members 
                        if m.name.startswith(base_path) and m.isfile()
                    ]
                    if icon_members:
                        used_base_path = base_path
                        break
                
                if not icon_members:
                    print(f"    ⚠ No icons folder found in {version} - skipping")
                    return icon_files
                
                for member in icon_members:
                    rel_path = member.name.replace(used_base_path, '')
                    if not rel_path:
                        continue
                    
                    rel_path = rel_path.lstrip('/')
                    if not rel_path:
                        continue
                    
                    file_obj = tar.extractfile(member)
                    if file_obj:
                        content = file_obj.read()
                        md5_hash = hashlib.md5(content).hexdigest()
                        icon_files.append((rel_path, md5_hash))
                
                print(f"    Found {len(icon_files)} icon files")
                
        except Exception as e:
            print(f"    Error extracting icons: {e}")
        
        return icon_files
    
    def process_version(self, version: str) -> List[Tuple[str, str]]:
        """
        Process a single Apache version: download and extract icons.
        
        Args:
            version: Apache version to process
            
        Returns:
            List of tuples (filename, md5_hash)
        """
        print(f"\nProcessing version {version}...")
        
        tar_path = self.download_version(version)
        if not tar_path:
            return []
        
        icon_files = self.extract_icons(tar_path, version)
        
        return icon_files
    
    def read_existing_results(self) -> set:
        """
        Read existing results from output file to avoid duplicates.
        
        Returns:
            Set of tuples (version, filename, md5_hash) that already exist
        """
        existing = set()
        if not os.path.exists(self.output_file):
            return existing
        
        try:
            with open(self.output_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines[2:]:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        version = parts[0]
                        filename = parts[1]
                        md5_hash = parts[2]
                        existing.add((version, filename, md5_hash))
        except Exception as e:
            print(f"Warning: Could not read existing file: {e}")
        
        return existing
    
    def write_results(self, results: List[Tuple[str, str, str]], append: bool = False):
        """
        Write results to output file.
        
        Args:
            results: List of tuples (version, filename, md5_hash)
            append: If True, append to existing file; if False, overwrite
        """
        if append:
            existing = self.read_existing_results()
            new_results = [r for r in results if r not in existing]
            
            if not new_results:
                print(f"\nNo new entries to add. All {len(results)} entries already exist in {self.output_file}")
                return
            
            print(f"\nAdding {len(new_results)} new entries to {self.output_file}...")
            print(f"(Skipping {len(results) - len(new_results)} duplicate entries)")
            
            with open(self.output_file, 'a', encoding='utf-8') as f:
                for version, filename, md5_hash in new_results:
                    f.write(f"{version:<7} {filename:<20} {md5_hash}\n")
            
            existing_count = len(existing)
            total_count = existing_count + len(new_results)
            print(f"Total entries in file: {total_count} (added {len(new_results)} new)")
        else:
            print(f"\nWriting results to {self.output_file}...")
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("Verze  Soubor   hash\n")
                f.write("-" * 80 + "\n")
                
                for version, filename, md5_hash in results:
                    f.write(f"{version:<7} {filename:<20} {md5_hash}\n")
            
            print(f"Results written to {self.output_file}")
            print(f"Total entries: {len(results)}")
    
    def cleanup(self):
        """Clean up temporary files."""
        if os.path.exists(self.temp_dir):
            import shutil
            print(f"\nCleaning up temporary directory: {self.temp_dir}")
            shutil.rmtree(self.temp_dir)
    
    def run(self, start_version: Optional[str] = None, overwrite: bool = False):
        """
        Run the analysis process.
        
        Args:
            start_version: Version to start from (None = all versions)
            overwrite: If True, overwrite existing file; if False, append new entries
        """
        try:
            all_versions = self.get_available_versions()
            if not all_versions:
                print("No versions found!")
                return
            
            if start_version:
                versions = self.filter_versions_from(all_versions, start_version)
                print(f"Processing {len(versions)} versions starting from {start_version}")
            else:
                versions = all_versions
                print(f"Processing all {len(versions)} versions")
            
            if not versions:
                print("No versions to process!")
                return
            
            results = []
            versions_with_icons = 0
            versions_without_icons = 0
            
            for version in versions:
                icon_files = self.process_version(version)
                if icon_files:
                    versions_with_icons += 1
                    for filename, md5_hash in icon_files:
                        results.append((version, filename, md5_hash))
                else:
                    versions_without_icons += 1
            
            print(f"\n{'='*60}")
            print(f"Statistics:")
            print(f"  Versions processed: {len(versions)}")
            print(f"  Versions with icons: {versions_with_icons}")
            print(f"  Versions without icons: {versions_without_icons}")
            print(f"{'='*60}")
            
            if results:
                append_mode = not overwrite and os.path.exists(self.output_file)
                self.write_results(results, append=append_mode)
            else:
                print("\nNo icon files found in any version!")
                
        finally:
            pass


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Apache icons across different versions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=
        """
        Examples:
        # Process all versions
        python analyze_apache_icons.py
        
        # Process versions starting from 2.2.1
        python analyze_apache_icons.py --start-version 2.2.1
        
        # Specify output file
        python analyze_apache_icons.py --start-version 2.2.1 --output apache_icons.txt
        """
    )
    
    parser.add_argument(
        '--start-version',
        type=str,
        help='Version to start from (e.g., 2.2.1). All versions from this version onwards will be processed.'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='apache_icons.txt',
        help='Output file path (default: apache_icons.txt)'
    )
    
    parser.add_argument(
        '--keep-temp',
        action='store_true',
        help='Keep temporary downloaded files (default: cleanup after completion)'
    )
    
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Overwrite existing output file (default: append new entries if file exists)'
    )
    
    args = parser.parse_args()
    
    analyzer = ApacheIconsAnalyzer(output_file=args.output)
    analyzer.run(start_version=args.start_version, overwrite=args.overwrite)
    
    if not args.keep_temp:
        analyzer.cleanup()


if __name__ == '__main__':
    main()

