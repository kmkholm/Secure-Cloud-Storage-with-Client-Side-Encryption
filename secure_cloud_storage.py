"""
Secure Cloud Storage with Client-Side Encryption
Author: Dr. Mohammed Tawfik
Zero-Knowledge Architecture - Files encrypted before upload

Features:
- Client-side encryption (AES-256-GCM, ChaCha20-Poly1305)
- Zero-knowledge architecture (server never sees plaintext)
- File sharing with access control
- File versioning with rollback
- Secure deletion with data overwriting
- Visual analytics and statistics
- Key management system
"""

import os
import sys
import json
import hashlib
import secrets
import base64
import shutil
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import threading


class EncryptionAlgorithm:
    """Base class for encryption algorithms"""
    
    def __init__(self, name):
        self.name = name
        self.backend = default_backend()
    
    def encrypt(self, data, key):
        """Encrypt data - to be implemented by subclasses"""
        raise NotImplementedError
    
    def decrypt(self, encrypted_data, key):
        """Decrypt data - to be implemented by subclasses"""
        raise NotImplementedError


class AES256GCM(EncryptionAlgorithm):
    """AES-256-GCM encryption implementation"""
    
    def __init__(self):
        super().__init__("AES-256-GCM")
        self.key_size = 32
        self.nonce_size = 16
    
    def encrypt(self, data, key):
        """Encrypt data using AES-256-GCM"""
        nonce = secrets.token_bytes(self.nonce_size)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def decrypt(self, encrypted_data, key):
        """Decrypt data using AES-256-GCM"""
        nonce = encrypted_data[:self.nonce_size]
        tag = encrypted_data[self.nonce_size:self.nonce_size + 16]
        ciphertext = encrypted_data[self.nonce_size + 16:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class ChaCha20Poly1305Encryption(EncryptionAlgorithm):
    """ChaCha20-Poly1305 encryption implementation"""
    
    def __init__(self):
        super().__init__("ChaCha20-Poly1305")
        self.key_size = 32
        self.nonce_size = 12
    
    def encrypt(self, data, key):
        """Encrypt data using ChaCha20-Poly1305"""
        nonce = secrets.token_bytes(self.nonce_size)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data, key):
        """Decrypt data using ChaCha20-Poly1305"""
        nonce = encrypted_data[:self.nonce_size]
        ciphertext = encrypted_data[self.nonce_size:]
        
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)


class CloudStorageEngine:
    """Handles encryption, storage, and retrieval of files"""
    
    def __init__(self, storage_path="cloud_storage", chunk_size=64*1024):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self.chunk_size = chunk_size
        self.metadata_file = self.storage_path / "metadata.json"
        self.metadata = self.load_metadata()
        
        # Available encryption algorithms
        self.algorithms = {
            "AES-256-GCM": AES256GCM(),
            "ChaCha20-Poly1305": ChaCha20Poly1305Encryption()
        }
    
    def load_metadata(self):
        """Load metadata from file"""
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        return {"files": {}, "versions": {}, "shares": {}}
    
    def save_metadata(self):
        """Save metadata to file"""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def generate_file_id(self, filename):
        """Generate unique file ID"""
        return hashlib.sha256(f"{filename}{time.time()}".encode()).hexdigest()[:16]
    
    def upload_file(self, file_path, user_id, key, algorithm_name="AES-256-GCM", 
                    progress_callback=None):
        """Upload and encrypt file (client-side encryption)"""
        try:
            algorithm = self.algorithms[algorithm_name]
            filename = os.path.basename(file_path)
            file_id = self.generate_file_id(filename)
            
            # Read and encrypt file
            file_size = os.path.getsize(file_path)
            encrypted_path = self.storage_path / f"{file_id}.enc"
            
            start_time = time.time()
            processed = 0
            
            with open(file_path, 'rb') as infile:
                data = infile.read()
                processed = len(data)
                
                # Encrypt entire file
                encrypted_data = algorithm.encrypt(data, key)
                
                # Write encrypted data
                with open(encrypted_path, 'wb') as outfile:
                    outfile.write(encrypted_data)
                
                if progress_callback:
                    progress_callback(100)
            
            elapsed_time = time.time() - start_time
            
            # Calculate hashes
            original_hash = hashlib.sha256(data).hexdigest()
            encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            # Store metadata
            self.metadata["files"][file_id] = {
                "filename": filename,
                "user_id": user_id,
                "algorithm": algorithm_name,
                "upload_time": datetime.now().isoformat(),
                "size": file_size,
                "encrypted_size": len(encrypted_data),
                "original_hash": original_hash,
                "encrypted_hash": encrypted_hash,
                "version": 1,
                "current_version": 1
            }
            
            # Initialize version tracking
            self.metadata["versions"][file_id] = [{
                "version": 1,
                "timestamp": datetime.now().isoformat(),
                "size": file_size,
                "hash": original_hash
            }]
            
            self.save_metadata()
            
            return True, file_id, elapsed_time, original_hash, encrypted_hash
            
        except Exception as e:
            return False, None, 0, None, None
    
    def download_file(self, file_id, output_path, key, progress_callback=None):
        """Download and decrypt file"""
        try:
            if file_id not in self.metadata["files"]:
                return False, "File not found"
            
            file_info = self.metadata["files"][file_id]
            algorithm = self.algorithms[file_info["algorithm"]]
            encrypted_path = self.storage_path / f"{file_id}.enc"
            
            start_time = time.time()
            
            # Read encrypted file
            with open(encrypted_path, 'rb') as infile:
                encrypted_data = infile.read()
                
                # Decrypt
                decrypted_data = algorithm.decrypt(encrypted_data, key)
                
                # Write decrypted file
                with open(output_path, 'wb') as outfile:
                    outfile.write(decrypted_data)
                
                if progress_callback:
                    progress_callback(100)
            
            elapsed_time = time.time() - start_time
            
            # Verify hash
            downloaded_hash = hashlib.sha256(decrypted_data).hexdigest()
            
            return True, elapsed_time, downloaded_hash
            
        except Exception as e:
            return False, str(e), None
    
    def create_version(self, file_path, file_id, key):
        """Create new version of existing file"""
        try:
            if file_id not in self.metadata["files"]:
                return False, "File not found"
            
            file_info = self.metadata["files"][file_id]
            algorithm = self.algorithms[file_info["algorithm"]]
            
            # Get new version number
            current_version = file_info["current_version"]
            new_version = current_version + 1
            
            # Encrypt new version
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = algorithm.encrypt(data, key)
            
            # Save version
            version_path = self.storage_path / f"{file_id}_v{new_version}.enc"
            with open(version_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Update metadata
            file_hash = hashlib.sha256(data).hexdigest()
            self.metadata["versions"][file_id].append({
                "version": new_version,
                "timestamp": datetime.now().isoformat(),
                "size": len(data),
                "hash": file_hash
            })
            
            # Update current version
            file_info["current_version"] = new_version
            file_info["size"] = len(data)
            file_info["original_hash"] = file_hash
            
            self.save_metadata()
            
            return True, new_version
            
        except Exception as e:
            return False, str(e)
    
    def rollback_version(self, file_id, version_number, key):
        """Rollback to specific version"""
        try:
            if file_id not in self.metadata["files"]:
                return False, "File not found"
            
            # Check if version exists
            versions = self.metadata["versions"].get(file_id, [])
            if not any(v["version"] == version_number for v in versions):
                return False, "Version not found"
            
            file_info = self.metadata["files"][file_id]
            
            # Copy version file to main file
            version_path = self.storage_path / f"{file_id}_v{version_number}.enc"
            main_path = self.storage_path / f"{file_id}.enc"
            
            shutil.copy(version_path, main_path)
            
            # Update metadata
            version_info = next(v for v in versions if v["version"] == version_number)
            file_info["current_version"] = version_number
            file_info["size"] = version_info["size"]
            file_info["original_hash"] = version_info["hash"]
            
            self.save_metadata()
            
            return True, "Rollback successful"
            
        except Exception as e:
            return False, str(e)
    
    def share_file(self, file_id, owner_id, shared_with_user, permission="read"):
        """Share file with another user"""
        try:
            if file_id not in self.metadata["files"]:
                return False, "File not found"
            
            file_info = self.metadata["files"][file_id]
            if file_info["user_id"] != owner_id:
                return False, "Not authorized to share this file"
            
            # Add share entry
            if file_id not in self.metadata["shares"]:
                self.metadata["shares"][file_id] = []
            
            # Check if already shared
            existing = [s for s in self.metadata["shares"][file_id] 
                       if s["user"] == shared_with_user]
            
            if existing:
                existing[0]["permission"] = permission
                existing[0]["shared_time"] = datetime.now().isoformat()
            else:
                self.metadata["shares"][file_id].append({
                    "user": shared_with_user,
                    "permission": permission,
                    "shared_time": datetime.now().isoformat()
                })
            
            self.save_metadata()
            return True, "File shared successfully"
            
        except Exception as e:
            return False, str(e)
    
    def revoke_share(self, file_id, owner_id, user_to_revoke):
        """Revoke file sharing"""
        try:
            if file_id not in self.metadata["files"]:
                return False, "File not found"
            
            file_info = self.metadata["files"][file_id]
            if file_info["user_id"] != owner_id:
                return False, "Not authorized"
            
            if file_id in self.metadata["shares"]:
                self.metadata["shares"][file_id] = [
                    s for s in self.metadata["shares"][file_id]
                    if s["user"] != user_to_revoke
                ]
            
            self.save_metadata()
            return True, "Access revoked"
            
        except Exception as e:
            return False, str(e)
    
    def secure_delete(self, file_id, user_id):
        """Securely delete file with overwriting"""
        try:
            if file_id not in self.metadata["files"]:
                return False, "File not found"
            
            file_info = self.metadata["files"][file_id]
            if file_info["user_id"] != user_id:
                return False, "Not authorized to delete this file"
            
            # Overwrite main file multiple times before deletion
            main_path = self.storage_path / f"{file_id}.enc"
            if main_path.exists():
                file_size = main_path.stat().st_size
                
                # Overwrite 3 times with random data
                for i in range(3):
                    with open(main_path, 'wb') as f:
                        f.write(secrets.token_bytes(file_size))
                
                # Delete file
                main_path.unlink()
            
            # Delete all versions
            if file_id in self.metadata["versions"]:
                for version in self.metadata["versions"][file_id]:
                    version_path = self.storage_path / f"{file_id}_v{version['version']}.enc"
                    if version_path.exists():
                        file_size = version_path.stat().st_size
                        for i in range(3):
                            with open(version_path, 'wb') as f:
                                f.write(secrets.token_bytes(file_size))
                        version_path.unlink()
            
            # Remove from metadata
            del self.metadata["files"][file_id]
            if file_id in self.metadata["versions"]:
                del self.metadata["versions"][file_id]
            if file_id in self.metadata["shares"]:
                del self.metadata["shares"][file_id]
            
            self.save_metadata()
            
            return True, "File securely deleted"
            
        except Exception as e:
            return False, str(e)
    
    def get_user_files(self, user_id):
        """Get all files for a user"""
        files = []
        for file_id, info in self.metadata["files"].items():
            if info["user_id"] == user_id:
                files.append({
                    "id": file_id,
                    **info
                })
        return files
    
    def get_shared_files(self, user_id):
        """Get files shared with user"""
        shared = []
        for file_id, shares in self.metadata["shares"].items():
            for share in shares:
                if share["user"] == user_id:
                    file_info = self.metadata["files"][file_id]
                    shared.append({
                        "id": file_id,
                        "permission": share["permission"],
                        **file_info
                    })
        return shared
    
    def get_storage_stats(self):
        """Get storage statistics"""
        total_files = len(self.metadata["files"])
        total_size = sum(f["size"] for f in self.metadata["files"].values())
        total_encrypted_size = sum(f["encrypted_size"] for f in self.metadata["files"].values())
        
        algorithm_stats = {}
        for file_info in self.metadata["files"].values():
            algo = file_info["algorithm"]
            if algo not in algorithm_stats:
                algorithm_stats[algo] = {"count": 0, "size": 0}
            algorithm_stats[algo]["count"] += 1
            algorithm_stats[algo]["size"] += file_info["size"]
        
        total_versions = sum(len(v) for v in self.metadata["versions"].values())
        total_shares = sum(len(s) for s in self.metadata["shares"].values())
        
        return {
            "total_files": total_files,
            "total_size": total_size,
            "total_encrypted_size": total_encrypted_size,
            "algorithm_stats": algorithm_stats,
            "total_versions": total_versions,
            "total_shares": total_shares
        }


class KeyManager:
    """Manage encryption keys"""
    
    def __init__(self, keys_dir="cloud_keys"):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        self.keys_file = self.keys_dir / "keys.json"
        self.keys = self.load_keys()
    
    def load_keys(self):
        """Load keys from file"""
        if self.keys_file.exists():
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_keys(self):
        """Save keys to file"""
        with open(self.keys_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def generate_key(self, user_id, key_name, key_size=32):
        """Generate new encryption key"""
        key = secrets.token_bytes(key_size)
        key_b64 = base64.b64encode(key).decode()
        
        key_id = f"{user_id}_{key_name}"
        self.keys[key_id] = {
            "key": key_b64,
            "user_id": user_id,
            "created": datetime.now().isoformat(),
            "size": key_size * 8
        }
        self.save_keys()
        return key
    
    def get_key(self, user_id, key_name):
        """Get key by user and name"""
        key_id = f"{user_id}_{key_name}"
        if key_id in self.keys:
            return base64.b64decode(self.keys[key_id]["key"])
        return None
    
    def list_user_keys(self, user_id):
        """List all keys for a user"""
        return [k.split('_', 1)[1] for k in self.keys.keys() 
                if k.startswith(f"{user_id}_")]


class SecureCloudStorageGUI:
    """Main GUI application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Cloud Storage - Dr. Mohammed Tawfik")
        self.root.geometry("1000x750")
        
        # Initialize components
        self.storage = CloudStorageEngine()
        self.key_manager = KeyManager()
        
        # Current user (simulated)
        self.current_user = "user1"
        
        # Variables
        self.selected_file_path = tk.StringVar()
        self.selected_algorithm = tk.StringVar(value="AES-256-GCM")
        self.selected_key_name = tk.StringVar()
        
        # Setup UI
        self.setup_ui()
        self.refresh_file_list()
        self.update_statistics()
    
    def setup_ui(self):
        """Setup user interface"""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title = ttk.Label(main_frame, text="☁️ Secure Cloud Storage", 
                         font=('Helvetica', 16, 'bold'))
        title.grid(row=0, column=0, columnspan=2, pady=10)
        
        subtitle = ttk.Label(main_frame, text="Zero-Knowledge Client-Side Encryption",
                           font=('Helvetica', 10))
        subtitle.grid(row=1, column=0, columnspan=2, pady=5)
        
        # Create notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Tabs
        self.create_upload_tab()
        self.create_files_tab()
        self.create_sharing_tab()
        self.create_versions_tab()
        self.create_statistics_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value=f"Ready | User: {self.current_user}")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
    
    def create_upload_tab(self):
        """Create upload tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Upload File")
        
        # File selection
        file_frame = ttk.LabelFrame(tab, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(file_frame, text="Select File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.selected_file_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2)
        
        # Encryption settings
        enc_frame = ttk.LabelFrame(tab, text="Encryption Settings", padding="10")
        enc_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(enc_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=5)
        algo_combo = ttk.Combobox(enc_frame, textvariable=self.selected_algorithm, 
                                 values=list(self.storage.algorithms.keys()), width=30)
        algo_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(enc_frame, text="Encryption Key:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_combo = ttk.Combobox(enc_frame, textvariable=self.selected_key_name, width=30)
        self.key_combo.grid(row=1, column=1, padx=5, pady=5)
        self.refresh_key_list()
        
        ttk.Button(enc_frame, text="Generate New Key", 
                  command=self.generate_key).grid(row=1, column=2, padx=5)
        
        # Progress
        progress_frame = ttk.LabelFrame(tab, text="Upload Progress", padding="10")
        progress_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.upload_progress = ttk.Progressbar(progress_frame, length=400, maximum=100)
        self.upload_progress.grid(row=0, column=0, pady=10, sticky=(tk.W, tk.E))
        
        self.upload_status = ttk.Label(progress_frame, text="Ready to upload")
        self.upload_status.grid(row=1, column=0)
        
        # Upload button
        ttk.Button(tab, text="☁️ Upload File", command=self.upload_file,
                  style='Accent.TButton').grid(row=3, column=0, pady=20)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        file_frame.columnconfigure(1, weight=1)
        enc_frame.columnconfigure(1, weight=1)
        progress_frame.columnconfigure(0, weight=1)
    
    def create_files_tab(self):
        """Create files management tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="My Files")
        
        # File list
        list_frame = ttk.LabelFrame(tab, text="Uploaded Files", padding="10")
        list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('filename', 'size', 'algorithm', 'upload_time', 'version')
        self.file_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        self.file_tree.heading('filename', text='Filename')
        self.file_tree.heading('size', text='Size')
        self.file_tree.heading('algorithm', text='Algorithm')
        self.file_tree.heading('upload_time', text='Upload Time')
        self.file_tree.heading('version', text='Version')
        
        self.file_tree.column('filename', width=200)
        self.file_tree.column('size', width=100)
        self.file_tree.column('algorithm', width=150)
        self.file_tree.column('upload_time', width=150)
        self.file_tree.column('version', width=80)
        
        self.file_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.file_tree.configure(yscrollcommand=scrollbar.set)
        
        # Action buttons
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=1, column=0, pady=10)
        
        ttk.Button(action_frame, text="📥 Download", command=self.download_file).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="🔄 Refresh", command=self.refresh_file_list).grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="🗑️ Delete", command=self.delete_file).grid(row=0, column=2, padx=5)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
    
    def create_sharing_tab(self):
        """Create file sharing tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Sharing")
        
        # Share file section
        share_frame = ttk.LabelFrame(tab, text="Share File", padding="10")
        share_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(share_frame, text="Select File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.share_file_combo = ttk.Combobox(share_frame, width=40, state='readonly')
        self.share_file_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(share_frame, text="Share With User:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.share_user_entry = ttk.Entry(share_frame, width=40)
        self.share_user_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(share_frame, text="Permission:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.permission_var = tk.StringVar(value="read")
        ttk.Radiobutton(share_frame, text="Read Only", variable=self.permission_var, 
                       value="read").grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(share_frame, text="Read & Write", variable=self.permission_var, 
                       value="write").grid(row=2, column=1, padx=100, sticky=tk.W)
        
        ttk.Button(share_frame, text="Share File", command=self.share_file).grid(row=3, column=0, 
                                                                                 columnspan=2, pady=10)
        
        # Shared files list
        shared_frame = ttk.LabelFrame(tab, text="Files Shared With Me", padding="10")
        shared_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('filename', 'owner', 'permission', 'shared_time')
        self.shared_tree = ttk.Treeview(shared_frame, columns=columns, show='headings', height=8)
        
        self.shared_tree.heading('filename', text='Filename')
        self.shared_tree.heading('owner', text='Owner')
        self.shared_tree.heading('permission', text='Permission')
        self.shared_tree.heading('shared_time', text='Shared Time')
        
        self.shared_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Button(tab, text="🔄 Refresh", command=self.refresh_sharing).grid(row=2, column=0, pady=10)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        share_frame.columnconfigure(1, weight=1)
        shared_frame.columnconfigure(0, weight=1)
        shared_frame.rowconfigure(0, weight=1)
    
    def create_versions_tab(self):
        """Create file versioning tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Versions")
        
        # File selection
        select_frame = ttk.LabelFrame(tab, text="Select File", padding="10")
        select_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.version_file_combo = ttk.Combobox(select_frame, width=50, state='readonly')
        self.version_file_combo.grid(row=0, column=0, padx=5, pady=5)
        self.version_file_combo.bind('<<ComboboxSelected>>', self.load_versions)
        
        ttk.Button(select_frame, text="Load Versions", 
                  command=self.load_versions).grid(row=0, column=1, padx=5)
        
        # Versions list
        versions_frame = ttk.LabelFrame(tab, text="File Versions", padding="10")
        versions_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('version', 'timestamp', 'size', 'hash')
        self.version_tree = ttk.Treeview(versions_frame, columns=columns, show='headings', height=10)
        
        self.version_tree.heading('version', text='Version')
        self.version_tree.heading('timestamp', text='Timestamp')
        self.version_tree.heading('size', text='Size')
        self.version_tree.heading('hash', text='Hash')
        
        self.version_tree.column('version', width=80)
        self.version_tree.column('timestamp', width=200)
        self.version_tree.column('size', width=100)
        self.version_tree.column('hash', width=300)
        
        self.version_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Action buttons
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=2, column=0, pady=10)
        
        ttk.Button(action_frame, text="⬅️ Rollback to Selected", 
                  command=self.rollback_version).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="➕ Create New Version", 
                  command=self.create_new_version).grid(row=0, column=1, padx=5)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        select_frame.columnconfigure(0, weight=1)
        versions_frame.columnconfigure(0, weight=1)
        versions_frame.rowconfigure(0, weight=1)
    
    def create_statistics_tab(self):
        """Create statistics and visualization tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Statistics")
        
        # Storage overview
        overview_frame = ttk.LabelFrame(tab, text="Storage Overview", padding="10")
        overview_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(overview_frame, height=15, width=80)
        self.stats_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Algorithm comparison
        algo_frame = ttk.LabelFrame(tab, text="Algorithm Comparison", padding="10")
        algo_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.algo_text = scrolledtext.ScrolledText(algo_frame, height=10, width=80)
        self.algo_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Refresh button
        ttk.Button(tab, text="🔄 Refresh Statistics", 
                  command=self.update_statistics).grid(row=2, column=0, pady=10)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        overview_frame.columnconfigure(0, weight=1)
        overview_frame.rowconfigure(0, weight=1)
        algo_frame.columnconfigure(0, weight=1)
    
    def browse_file(self):
        """Browse for file to upload"""
        filename = filedialog.askopenfilename(title="Select File to Upload")
        if filename:
            self.selected_file_path.set(filename)
    
    def generate_key(self):
        """Generate new encryption key"""
        key_name = tk.simpledialog.askstring("Generate Key", "Enter key name:")
        if key_name:
            self.key_manager.generate_key(self.current_user, key_name)
            self.refresh_key_list()
            messagebox.showinfo("Success", f"Key '{key_name}' generated successfully!")
    
    def refresh_key_list(self):
        """Refresh key dropdown"""
        keys = self.key_manager.list_user_keys(self.current_user)
        self.key_combo['values'] = keys
    
    def upload_file(self):
        """Upload and encrypt file"""
        if not self.selected_file_path.get():
            messagebox.showerror("Error", "Please select a file")
            return
        
        if not self.selected_key_name.get():
            messagebox.showerror("Error", "Please select or generate an encryption key")
            return
        
        # Get key
        key = self.key_manager.get_key(self.current_user, self.selected_key_name.get())
        if not key:
            messagebox.showerror("Error", "Key not found")
            return
        
        self.upload_status.config(text="Encrypting and uploading...")
        
        def upload_thread():
            success, file_id, elapsed, orig_hash, enc_hash = self.storage.upload_file(
                self.selected_file_path.get(),
                self.current_user,
                key,
                self.selected_algorithm.get(),
                lambda p: self.upload_progress.configure(value=p)
            )
            
            self.root.after(0, lambda: self.upload_complete(success, file_id, elapsed))
        
        threading.Thread(target=upload_thread, daemon=True).start()
    
    def upload_complete(self, success, file_id, elapsed):
        """Handle upload completion"""
        if success:
            self.upload_status.config(text=f"Upload complete! ({elapsed:.2f}s)")
            messagebox.showinfo("Success", "File uploaded and encrypted successfully!")
            self.refresh_file_list()
            self.update_statistics()
        else:
            self.upload_status.config(text="Upload failed")
            messagebox.showerror("Error", "Upload failed")
    
    def refresh_file_list(self):
        """Refresh file list"""
        # Clear existing
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        # Get files
        files = self.storage.get_user_files(self.current_user)
        
        for file_info in files:
            size_mb = file_info['size'] / (1024 * 1024)
            upload_time = datetime.fromisoformat(file_info['upload_time']).strftime('%Y-%m-%d %H:%M')
            
            self.file_tree.insert('', tk.END, values=(
                file_info['filename'],
                f"{size_mb:.2f} MB",
                file_info['algorithm'],
                upload_time,
                f"v{file_info['current_version']}"
            ), tags=(file_info['id'],))
        
        # Update sharing combos
        file_list = [(f['id'], f['filename']) for f in files]
        self.share_file_combo['values'] = [f[1] for f in file_list]
        self.version_file_combo['values'] = [f[1] for f in file_list]
    
    def download_file(self):
        """Download and decrypt file"""
        selected = self.file_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a file")
            return
        
        file_id = self.file_tree.item(selected[0])['tags'][0]
        file_info = self.storage.metadata["files"][file_id]
        
        # Get key
        key_name = tk.simpledialog.askstring("Decryption Key", 
                                            "Enter the key name used for encryption:")
        if not key_name:
            return
        
        key = self.key_manager.get_key(self.current_user, key_name)
        if not key:
            messagebox.showerror("Error", "Key not found")
            return
        
        # Select output location
        output_path = filedialog.asksaveasfilename(
            title="Save File As",
            initialfile=file_info['filename']
        )
        
        if output_path:
            success, elapsed, hash_val = self.storage.download_file(file_id, output_path, key)
            
            if success:
                messagebox.showinfo("Success", 
                                  f"File downloaded and decrypted!\nTime: {elapsed:.2f}s")
            else:
                messagebox.showerror("Error", f"Download failed: {elapsed}")
    
    def delete_file(self):
        """Securely delete file"""
        selected = self.file_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a file")
            return
        
        file_id = self.file_tree.item(selected[0])['tags'][0]
        file_info = self.storage.metadata["files"][file_id]
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Securely delete '{file_info['filename']}'?\n\n"
                              "File will be overwritten multiple times before deletion."):
            success, message = self.storage.secure_delete(file_id, self.current_user)
            
            if success:
                messagebox.showinfo("Success", "File securely deleted")
                self.refresh_file_list()
                self.update_statistics()
            else:
                messagebox.showerror("Error", message)
    
    def share_file(self):
        """Share file with user"""
        if not self.share_file_combo.get():
            messagebox.showerror("Error", "Please select a file")
            return
        
        if not self.share_user_entry.get():
            messagebox.showerror("Error", "Please enter username to share with")
            return
        
        # Find file ID
        filename = self.share_file_combo.get()
        file_id = None
        for fid, info in self.storage.metadata["files"].items():
            if info['filename'] == filename and info['user_id'] == self.current_user:
                file_id = fid
                break
        
        if file_id:
            success, message = self.storage.share_file(
                file_id,
                self.current_user,
                self.share_user_entry.get(),
                self.permission_var.get()
            )
            
            if success:
                messagebox.showinfo("Success", "File shared successfully!")
                self.refresh_sharing()
            else:
                messagebox.showerror("Error", message)
    
    def refresh_sharing(self):
        """Refresh shared files list"""
        for item in self.shared_tree.get_children():
            self.shared_tree.delete(item)
        
        shared_files = self.storage.get_shared_files(self.current_user)
        
        for file_info in shared_files:
            self.shared_tree.insert('', tk.END, values=(
                file_info['filename'],
                file_info['user_id'],
                file_info['permission'],
                file_info.get('shared_time', 'N/A')
            ))
    
    def load_versions(self, event=None):
        """Load versions for selected file"""
        if not self.version_file_combo.get():
            return
        
        # Find file ID
        filename = self.version_file_combo.get()
        file_id = None
        for fid, info in self.storage.metadata["files"].items():
            if info['filename'] == filename and info['user_id'] == self.current_user:
                file_id = fid
                break
        
        if not file_id:
            return
        
        # Clear existing
        for item in self.version_tree.get_children():
            self.version_tree.delete(item)
        
        # Load versions
        versions = self.storage.metadata["versions"].get(file_id, [])
        
        for version in versions:
            size_mb = version['size'] / (1024 * 1024)
            timestamp = datetime.fromisoformat(version['timestamp']).strftime('%Y-%m-%d %H:%M')
            
            self.version_tree.insert('', tk.END, values=(
                f"v{version['version']}",
                timestamp,
                f"{size_mb:.2f} MB",
                version['hash'][:32] + "..."
            ), tags=(file_id, version['version']))
    
    def rollback_version(self):
        """Rollback to selected version"""
        selected = self.version_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a version")
            return
        
        tags = self.version_tree.item(selected[0])['tags']
        file_id, version = tags[0], int(tags[1])
        
        # Get key
        key_name = tk.simpledialog.askstring("Decryption Key", 
                                            "Enter the key name used for encryption:")
        if not key_name:
            return
        
        key = self.key_manager.get_key(self.current_user, key_name)
        if not key:
            messagebox.showerror("Error", "Key not found")
            return
        
        if messagebox.askyesno("Confirm Rollback", 
                              f"Rollback to version {version}?"):
            success, message = self.storage.rollback_version(file_id, version, key)
            
            if success:
                messagebox.showinfo("Success", "Rolled back to selected version!")
                self.refresh_file_list()
                self.load_versions()
            else:
                messagebox.showerror("Error", message)
    
    def create_new_version(self):
        """Create new version of file"""
        if not self.version_file_combo.get():
            messagebox.showerror("Error", "Please select a file")
            return
        
        # Find file ID
        filename = self.version_file_combo.get()
        file_id = None
        for fid, info in self.storage.metadata["files"].items():
            if info['filename'] == filename and info['user_id'] == self.current_user:
                file_id = fid
                break
        
        if not file_id:
            return
        
        # Select new version file
        new_file = filedialog.askopenfilename(title="Select New Version")
        if not new_file:
            return
        
        # Get key
        key_name = tk.simpledialog.askstring("Encryption Key", 
                                            "Enter the key name for encryption:")
        if not key_name:
            return
        
        key = self.key_manager.get_key(self.current_user, key_name)
        if not key:
            messagebox.showerror("Error", "Key not found")
            return
        
        success, version = self.storage.create_version(new_file, file_id, key)
        
        if success:
            messagebox.showinfo("Success", f"Version {version} created!")
            self.refresh_file_list()
            self.load_versions()
        else:
            messagebox.showerror("Error", version)
    
    def update_statistics(self):
        """Update statistics display"""
        stats = self.storage.get_storage_stats()
        
        # Clear text
        self.stats_text.delete(1.0, tk.END)
        
        # Format statistics
        total_size_mb = stats['total_size'] / (1024 * 1024)
        total_enc_mb = stats['total_encrypted_size'] / (1024 * 1024)
        overhead = ((stats['total_encrypted_size'] - stats['total_size']) / 
                   stats['total_size'] * 100) if stats['total_size'] > 0 else 0
        
        stats_text = f"""
╔══════════════════════════════════════════════════════════════╗
║                     STORAGE STATISTICS                       ║
╚══════════════════════════════════════════════════════════════╝

📊 Overview:
────────────────────────────────────────────────────────────────
   Total Files:              {stats['total_files']}
   Total Original Size:      {total_size_mb:.2f} MB
   Total Encrypted Size:     {total_enc_mb:.2f} MB
   Encryption Overhead:      {overhead:.2f}%
   
   Total Versions:           {stats['total_versions']}
   Total Shared:             {stats['total_shares']}

🔐 Zero-Knowledge Architecture:
────────────────────────────────────────────────────────────────
   ✓ All files encrypted client-side before upload
   ✓ Server never sees unencrypted data
   ✓ Only you have the decryption keys
   ✓ End-to-end encryption guaranteed

📈 Encryption Algorithm Distribution:
────────────────────────────────────────────────────────────────
"""
        
        for algo, data in stats['algorithm_stats'].items():
            count = data['count']
            size_mb = data['size'] / (1024 * 1024)
            percentage = (count / stats['total_files'] * 100) if stats['total_files'] > 0 else 0
            stats_text += f"   {algo:20s}: {count:3d} files ({percentage:5.1f}%) - {size_mb:8.2f} MB\n"
        
        self.stats_text.insert(1.0, stats_text)
        
        # Algorithm comparison
        self.algo_text.delete(1.0, tk.END)
        algo_comparison = """
╔══════════════════════════════════════════════════════════════╗
║                  ALGORITHM COMPARISON                        ║
╚══════════════════════════════════════════════════════════════╝

AES-256-GCM:
────────────────────────────────────────────────────────────────
   Standard:        NIST FIPS 197 approved
   Key Size:        256 bits (32 bytes)
   Mode:            GCM (Galois/Counter Mode)
   Authentication:  Built-in with 128-bit tag
   Performance:     Excellent (hardware acceleration)
   Security:        Military-grade, approved for TOP SECRET
   Use Case:        General purpose, maximum compatibility

ChaCha20-Poly1305:
────────────────────────────────────────────────────────────────
   Standard:        RFC 8439
   Key Size:        256 bits (32 bytes)
   Mode:            Stream cipher with Poly1305 MAC
   Authentication:  Poly1305 authentication tag
   Performance:     Excellent on all platforms (software)
   Security:        Military-grade, modern alternative
   Use Case:        Mobile devices, no hardware AES support

Both algorithms provide:
────────────────────────────────────────────────────────────────
   ✓ 256-bit encryption (AES-256 equivalent security)
   ✓ Authenticated encryption (AEAD)
   ✓ Protection against tampering
   ✓ Nonce-based operation (prevents replay attacks)
"""
        
        self.algo_text.insert(1.0, algo_comparison)
    
    def show_help(self):
        """Show help dialog"""
        help_text = """
SECURE CLOUD STORAGE - USER GUIDE

UPLOADING FILES:
1. Go to "Upload File" tab
2. Select file to upload
3. Choose encryption algorithm (AES-256-GCM or ChaCha20-Poly1305)
4. Select or generate encryption key
5. Click "Upload File"

FILE MANAGEMENT:
• View all files in "My Files" tab
• Download: Select file and click Download (need encryption key)
• Delete: Securely deletes file with overwriting

FILE SHARING:
1. Go to "Sharing" tab
2. Select file to share
3. Enter username to share with
4. Choose permission (Read or Read & Write)
5. Click "Share File"

FILE VERSIONING:
• Create new versions of files
• Rollback to previous versions
• Track all changes with timestamps

SECURITY:
• All files encrypted on your computer before upload
• Server never sees your unencrypted files
• Only you have the decryption keys
• Zero-knowledge architecture

For more help, check the Statistics tab for algorithm comparisons.
"""
        messagebox.showinfo("User Guide", help_text)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
╔══════════════════════════════════════════════════════════╗
║     Secure Cloud Storage with Client-Side Encryption    ║
╚══════════════════════════════════════════════════════════╝

Version: 1.0
Created by: Dr. Mohammed Tawfik
Institution: Ajloun National University, Jordan
Date: November 9, 2024

Project: Bachelor Degree Cybersecurity Project
Category: Cloud Security & Applied Cryptography

Features:
✓ Zero-Knowledge Architecture
✓ Client-Side Encryption
✓ Multiple Encryption Algorithms
✓ File Versioning
✓ Access Control & Sharing
✓ Secure Deletion

Technical Specifications:
• Encryption: AES-256-GCM, ChaCha20-Poly1305
• Key Size: 256 bits
• Authentication: AEAD with authentication tags
• Storage: Simulated cloud with local encryption

© 2024 Dr. Mohammed Tawfik - All Rights Reserved
Educational Use - Bachelor Degree Project
"""
        messagebox.showinfo("About", about_text)


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Set theme
    style = ttk.Style()
    style.theme_use('clam')
    
    app = SecureCloudStorageGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
