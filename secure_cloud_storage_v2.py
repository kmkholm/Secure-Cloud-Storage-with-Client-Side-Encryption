"""
Secure Cloud Storage - ENHANCED VERSION V2.0
Author: Dr. Mohammed Tawfik
Features: User Management, Visualization, Simulation, Multi-User Support

New in V2.0:
- User registration and management system
- Visual charts and graphs for statistics
- Interactive file sharing with user selection
- Multi-user simulation mode
- Real-time visualization of storage usage
- Network activity simulation
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
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import threading

# Import matplotlib for visualizations
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("⚠️  matplotlib not installed - visualizations will be text-based")
    print("   Install with: pip install matplotlib")


class User:
    """User account representation"""
    
    def __init__(self, user_id, username, email, created_date=None, storage_used=0, file_count=0):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.created_date = created_date or datetime.now().isoformat()
        self.storage_used = storage_used
        self.file_count = file_count


class UserManager:
    """Manage user accounts"""
    
    def __init__(self, storage_path="cloud_storage"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)  # Create directory if not exists
        self.users_file = self.storage_path / "users.json"
        self.users = self.load_users()
    
    def load_users(self):
        """Load users from file"""
        if self.users_file.exists():
            with open(self.users_file, 'r') as f:
                data = json.load(f)
                return {uid: User(**u) for uid, u in data.items()}
        return {}
    
    def save_users(self):
        """Save users to file"""
        data = {uid: {
            'user_id': u.user_id,
            'username': u.username,
            'email': u.email,
            'created_date': u.created_date,
            'storage_used': u.storage_used,
            'file_count': u.file_count
        } for uid, u in self.users.items()}
        
        with open(self.users_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def register_user(self, username, email):
        """Register new user"""
        # Check if username exists
        if any(u.username == username for u in self.users.values()):
            return False, "Username already exists"
        
        # Generate user ID
        user_id = hashlib.sha256(f"{username}{time.time()}".encode()).hexdigest()[:12]
        
        # Create user
        user = User(user_id, username, email)
        self.users[user_id] = user
        self.save_users()
        
        return True, user_id
    
    def get_user(self, user_id):
        """Get user by ID"""
        return self.users.get(user_id)
    
    def get_user_by_username(self, username):
        """Get user by username"""
        for user in self.users.values():
            if user.username == username:
                return user
        return None
    
    def list_users(self):
        """List all users"""
        return list(self.users.values())
    
    def update_user_stats(self, user_id, storage_used, file_count):
        """Update user storage statistics"""
        if user_id in self.users:
            self.users[user_id].storage_used = storage_used
            self.users[user_id].file_count = file_count
            self.save_users()


class SimulationEngine:
    """Simulate network activity and multi-user interactions"""
    
    def __init__(self):
        self.activity_log = []
        self.max_log_size = 100
    
    def log_activity(self, user_id, action, details):
        """Log user activity"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'action': action,
            'details': details
        }
        self.activity_log.append(entry)
        
        # Keep log size manageable
        if len(self.activity_log) > self.max_log_size:
            self.activity_log.pop(0)
    
    def simulate_upload(self, user_id, filename, size, callback=None):
        """Simulate network upload with delay"""
        # Simulate network delay (50ms per KB)
        delay = (size / 1024) * 0.05
        time.sleep(min(delay, 2))  # Max 2 seconds
        
        self.log_activity(user_id, 'upload', f"Uploaded {filename} ({size} bytes)")
        
        if callback:
            callback()
    
    def simulate_download(self, user_id, filename, size, callback=None):
        """Simulate network download with delay"""
        delay = (size / 1024) * 0.04
        time.sleep(min(delay, 2))
        
        self.log_activity(user_id, 'download', f"Downloaded {filename} ({size} bytes)")
        
        if callback:
            callback()
    
    def get_recent_activity(self, limit=20):
        """Get recent activity log"""
        return self.activity_log[-limit:]


# Import previous CloudStorageEngine and encryption classes
from secure_cloud_storage import (
    EncryptionAlgorithm, AES256GCM, ChaCha20Poly1305Encryption,
    CloudStorageEngine, KeyManager
)


class VisualizationManager:
    """Manage charts and visualizations"""
    
    def __init__(self, parent):
        self.parent = parent
    
    def create_storage_pie_chart(self, frame, stats):
        """Create pie chart for storage distribution"""
        if not MATPLOTLIB_AVAILABLE:
            return self.create_text_chart(frame, stats)
        
        fig = Figure(figsize=(6, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        # Prepare data
        algo_stats = stats.get('algorithm_stats', {})
        if not algo_stats:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
        else:
            labels = list(algo_stats.keys())
            sizes = [data['count'] for data in algo_stats.values()]
            colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
            
            ax.pie(sizes, labels=labels, colors=colors[:len(sizes)], autopct='%1.1f%%',
                   startangle=90)
            ax.set_title('Storage by Algorithm')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        return canvas
    
    def create_storage_bar_chart(self, frame, users, user_manager):
        """Create bar chart for user storage"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig = Figure(figsize=(8, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        # Prepare data
        usernames = []
        storage = []
        
        for user_id in users[:10]:  # Top 10 users
            user = user_manager.get_user(user_id)
            if user:
                usernames.append(user.username[:15])
                storage.append(user.storage_used / (1024*1024))  # MB
        
        if usernames:
            ax.bar(usernames, storage, color='#3498db')
            ax.set_xlabel('Users')
            ax.set_ylabel('Storage Used (MB)')
            ax.set_title('Storage Usage by User')
            ax.tick_params(axis='x', rotation=45)
            fig.tight_layout()
        else:
            ax.text(0.5, 0.5, 'No user data', ha='center', va='center')
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        return canvas
    
    def create_activity_timeline(self, frame, activity_log):
        """Create timeline of recent activity"""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        fig = Figure(figsize=(8, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        if not activity_log:
            ax.text(0.5, 0.5, 'No activity yet', ha='center', va='center')
        else:
            # Count activities by type
            actions = {}
            for entry in activity_log:
                action = entry['action']
                actions[action] = actions.get(action, 0) + 1
            
            labels = list(actions.keys())
            counts = list(actions.values())
            
            ax.bar(labels, counts, color=['#3498db', '#e74c3c', '#2ecc71', '#f39c12'][:len(labels)])
            ax.set_xlabel('Activity Type')
            ax.set_ylabel('Count')
            ax.set_title('Recent Activity (Last 100 actions)')
            fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        return canvas
    
    def create_text_chart(self, frame, stats):
        """Create text-based chart when matplotlib not available"""
        text = scrolledtext.ScrolledText(frame, height=15, width=60)
        text.pack(fill=tk.BOTH, expand=True)
        
        algo_stats = stats.get('algorithm_stats', {})
        total = sum(data['count'] for data in algo_stats.values())
        
        chart_text = "📊 STORAGE DISTRIBUTION (Text Mode)\n"
        chart_text += "═" * 50 + "\n\n"
        
        for algo, data in algo_stats.items():
            percentage = (data['count'] / total * 100) if total > 0 else 0
            bar_length = int(percentage / 2)
            bar = "█" * bar_length
            chart_text += f"{algo:20s} {bar} {percentage:.1f}%\n"
            chart_text += f"                    Files: {data['count']}, "
            chart_text += f"Size: {data['size']/(1024*1024):.2f} MB\n\n"
        
        text.insert(1.0, chart_text)
        text.config(state='disabled')
        
        return text


class EnhancedCloudStorageGUI:
    """Enhanced GUI with user management and visualization"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Cloud Storage V2.0 - Dr. Mohammed Tawfik")
        self.root.geometry("1100x800")
        
        # Initialize components
        self.storage = CloudStorageEngine()
        self.key_manager = KeyManager()
        self.user_manager = UserManager()
        self.simulation = SimulationEngine()
        self.viz = VisualizationManager(root)
        
        # Current user
        self.current_user = None
        
        # Check if we have users, if not show registration
        if not self.user_manager.users:
            self.show_initial_setup()
        else:
            self.show_login()
    
    def show_initial_setup(self):
        """Show initial setup dialog"""
        setup_window = tk.Toplevel(self.root)
        setup_window.title("Initial Setup")
        setup_window.geometry("400x300")
        setup_window.transient(self.root)
        setup_window.grab_set()
        
        # Center window
        setup_window.update_idletasks()
        x = (setup_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (setup_window.winfo_screenheight() // 2) - (300 // 2)
        setup_window.geometry(f"+{x}+{y}")
        
        ttk.Label(setup_window, text="Welcome to Secure Cloud Storage V2.0",
                 font=('Helvetica', 12, 'bold')).pack(pady=20)
        
        ttk.Label(setup_window, text="Create your administrator account").pack(pady=10)
        
        frame = ttk.Frame(setup_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(frame, width=30)
        username_entry.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(frame, text="Email:").grid(row=1, column=0, sticky=tk.W, pady=5)
        email_entry = ttk.Entry(frame, width=30)
        email_entry.grid(row=1, column=1, pady=5, padx=5)
        
        def create_account():
            username = username_entry.get().strip()
            email = email_entry.get().strip()
            
            if not username or not email:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            success, result = self.user_manager.register_user(username, email)
            if success:
                self.current_user = result
                setup_window.destroy()
                self.setup_main_ui()
                messagebox.showinfo("Success", f"Welcome {username}!")
            else:
                messagebox.showerror("Error", result)
        
        ttk.Button(frame, text="Create Account", command=create_account).grid(
            row=2, column=0, columnspan=2, pady=20)
        
        username_entry.focus()
    
    def show_login(self):
        """Show login dialog"""
        login_window = tk.Toplevel(self.root)
        login_window.title("Login")
        login_window.geometry("350x250")
        login_window.transient(self.root)
        login_window.grab_set()
        
        # Center window
        login_window.update_idletasks()
        x = (login_window.winfo_screenwidth() // 2) - (350 // 2)
        y = (login_window.winfo_screenheight() // 2) - (250 // 2)
        login_window.geometry(f"+{x}+{y}")
        
        ttk.Label(login_window, text="Secure Cloud Storage V2.0",
                 font=('Helvetica', 12, 'bold')).pack(pady=20)
        
        frame = ttk.Frame(login_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(frame, width=25)
        username_entry.grid(row=0, column=1, pady=5, padx=5)
        
        def do_login():
            username = username_entry.get().strip()
            if not username:
                messagebox.showerror("Error", "Please enter username")
                return
            
            user = self.user_manager.get_user_by_username(username)
            if user:
                self.current_user = user.user_id
                login_window.destroy()
                self.setup_main_ui()
            else:
                messagebox.showerror("Error", "User not found")
        
        def register():
            reg_window = tk.Toplevel(login_window)
            reg_window.title("Register New User")
            reg_window.geometry("350x200")
            
            ttk.Label(reg_window, text="Register New User",
                     font=('Helvetica', 11, 'bold')).pack(pady=10)
            
            reg_frame = ttk.Frame(reg_window, padding="20")
            reg_frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(reg_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
            new_username = ttk.Entry(reg_frame, width=25)
            new_username.grid(row=0, column=1, pady=5, padx=5)
            
            ttk.Label(reg_frame, text="Email:").grid(row=1, column=0, sticky=tk.W, pady=5)
            new_email = ttk.Entry(reg_frame, width=25)
            new_email.grid(row=1, column=1, pady=5, padx=5)
            
            def do_register():
                username = new_username.get().strip()
                email = new_email.get().strip()
                
                if not username or not email:
                    messagebox.showerror("Error", "Please fill all fields")
                    return
                
                success, result = self.user_manager.register_user(username, email)
                if success:
                    messagebox.showinfo("Success", f"User {username} registered!")
                    reg_window.destroy()
                else:
                    messagebox.showerror("Error", result)
            
            ttk.Button(reg_frame, text="Register", command=do_register).grid(
                row=2, column=0, columnspan=2, pady=15)
        
        ttk.Button(frame, text="Login", command=do_login).grid(
            row=1, column=0, pady=15, padx=5)
        ttk.Button(frame, text="Register", command=register).grid(
            row=1, column=1, pady=15, padx=5)
        
        username_entry.focus()
    
    def setup_main_ui(self):
        """Setup main application UI"""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Switch User", command=self.switch_user)
        file_menu.add_command(label="Manage Users", command=self.show_user_management)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title with current user
        user = self.user_manager.get_user(self.current_user)
        title_text = f"☁️ Secure Cloud Storage V2.0 - Welcome {user.username}!"
        title = ttk.Label(main_frame, text=title_text, font=('Helvetica', 14, 'bold'))
        title.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Create notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Tabs
        self.create_upload_tab()
        self.create_files_tab()
        self.create_sharing_tab()
        self.create_users_tab()
        self.create_visualization_tab()
        self.create_simulation_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value=f"Ready | User: {user.username}")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var,
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Initial refresh
        self.refresh_all()
    
    def create_users_tab(self):
        """Create user management tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Users")
        
        # User list
        list_frame = ttk.LabelFrame(tab, text="Registered Users", padding="10")
        list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('username', 'email', 'files', 'storage', 'created')
        self.user_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        self.user_tree.heading('username', text='Username')
        self.user_tree.heading('email', text='Email')
        self.user_tree.heading('files', text='Files')
        self.user_tree.heading('storage', text='Storage Used')
        self.user_tree.heading('created', text='Joined')
        
        self.user_tree.column('username', width=150)
        self.user_tree.column('email', width=200)
        self.user_tree.column('files', width=80)
        self.user_tree.column('storage', width=120)
        self.user_tree.column('created', width=150)
        
        self.user_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.user_tree.configure(yscrollcommand=scrollbar.set)
        
        # Action buttons
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=1, column=0, pady=10)
        
        ttk.Button(action_frame, text="➕ Add User", command=self.add_user).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="🔄 Refresh", command=self.refresh_user_list).grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="📊 View Stats", command=self.show_user_stats).grid(row=0, column=2, padx=5)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
    
    def create_visualization_tab(self):
        """Create visualization tab with charts"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="📊 Visualization")
        
        # Create container for charts
        chart_container = ttk.Frame(tab)
        chart_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Storage distribution chart
        storage_frame = ttk.LabelFrame(chart_container, text="Storage Distribution", padding="10")
        storage_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        self.storage_chart_frame = ttk.Frame(storage_frame)
        self.storage_chart_frame.pack(fill=tk.BOTH, expand=True)
        
        # User storage chart
        user_frame = ttk.LabelFrame(chart_container, text="User Storage Usage", padding="10")
        user_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        self.user_chart_frame = ttk.Frame(user_frame)
        self.user_chart_frame.pack(fill=tk.BOTH, expand=True)
        
        # Activity timeline
        activity_frame = ttk.LabelFrame(tab, text="Activity Timeline", padding="10")
        activity_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.activity_chart_frame = ttk.Frame(activity_frame)
        self.activity_chart_frame.pack(fill=tk.BOTH, expand=True)
        
        # Refresh button
        ttk.Button(tab, text="🔄 Refresh Charts", command=self.refresh_visualizations).grid(row=2, column=0, pady=10)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        chart_container.columnconfigure(0, weight=1)
        chart_container.columnconfigure(1, weight=1)
        chart_container.rowconfigure(0, weight=1)
    
    def create_simulation_tab(self):
        """Create simulation tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="🎮 Simulation")
        
        # Simulation controls
        control_frame = ttk.LabelFrame(tab, text="Simulation Controls", padding="10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(control_frame, text="Simulate multi-user cloud activity",
                 font=('Helvetica', 10)).grid(row=0, column=0, columnspan=3, pady=10)
        
        ttk.Button(control_frame, text="🚀 Simulate Uploads", 
                  command=self.simulate_uploads).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(control_frame, text="📥 Simulate Downloads", 
                  command=self.simulate_downloads).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(control_frame, text="🤝 Simulate Sharing", 
                  command=self.simulate_sharing).grid(row=1, column=2, padx=5, pady=5)
        
        # Activity log
        log_frame = ttk.LabelFrame(tab, text="Activity Log", padding="10")
        log_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(log_frame, height=20, width=90)
        self.activity_log.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Network simulation status
        status_frame = ttk.Frame(tab)
        status_frame.grid(row=2, column=0, pady=10)
        
        self.sim_status = ttk.Label(status_frame, text="Ready for simulation")
        self.sim_status.pack()
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
    
    def create_upload_tab(self):
        """Create upload tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="📤 Upload")
        
        # File selection
        file_frame = ttk.LabelFrame(tab, text="File Selection", padding="10")
        file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.selected_file_path = tk.StringVar()
        ttk.Label(file_frame, text="Select File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.selected_file_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2)
        
        # Encryption settings
        enc_frame = ttk.LabelFrame(tab, text="Encryption Settings", padding="10")
        enc_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.selected_algorithm = tk.StringVar(value="AES-256-GCM")
        ttk.Label(enc_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=5)
        algo_combo = ttk.Combobox(enc_frame, textvariable=self.selected_algorithm, 
                                 values=["AES-256-GCM", "ChaCha20-Poly1305"], width=30)
        algo_combo.grid(row=0, column=1, padx=5, pady=5)
        
        self.selected_key_name = tk.StringVar()
        ttk.Label(enc_frame, text="Encryption Key:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_combo = ttk.Combobox(enc_frame, textvariable=self.selected_key_name, width=30)
        self.key_combo.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(enc_frame, text="Generate New Key", 
                  command=self.generate_key).grid(row=1, column=2, padx=5)
        
        # Upload button
        ttk.Button(tab, text="☁️ Upload File", command=self.upload_file,
                  style='Accent.TButton').grid(row=2, column=0, pady=20)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        file_frame.columnconfigure(1, weight=1)
        enc_frame.columnconfigure(1, weight=1)
    
    def create_files_tab(self):
        """Create files tab"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="📁 My Files")
        
        # File list
        list_frame = ttk.LabelFrame(tab, text="My Files", padding="10")
        list_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('filename', 'size', 'algorithm', 'upload_time')
        self.file_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        self.file_tree.heading('filename', text='Filename')
        self.file_tree.heading('size', text='Size')
        self.file_tree.heading('algorithm', text='Algorithm')
        self.file_tree.heading('upload_time', text='Upload Time')
        
        self.file_tree.column('filename', width=250)
        self.file_tree.column('size', width=100)
        self.file_tree.column('algorithm', width=150)
        self.file_tree.column('upload_time', width=150)
        
        self.file_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.file_tree.configure(yscrollcommand=scrollbar.set)
        
        # Action buttons
        action_frame = ttk.Frame(tab)
        action_frame.grid(row=1, column=0, pady=10)
        
        ttk.Button(action_frame, text="📥 Download", command=self.download_file).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="🔄 Refresh", command=self.refresh_file_list).grid(row=0, column=1, padx=5)
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
    
    def create_sharing_tab(self):
        """Create enhanced sharing tab with user selection"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="🤝 Sharing")
        
        # Share file section
        share_frame = ttk.LabelFrame(tab, text="Share File", padding="10")
        share_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(share_frame, text="Select File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.share_file_combo = ttk.Combobox(share_frame, width=40, state='readonly')
        self.share_file_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(share_frame, text="Share With User:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.share_user_combo = ttk.Combobox(share_frame, width=40, state='readonly')
        self.share_user_combo.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(share_frame, text="Permission:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.permission_var = tk.StringVar(value="read")
        perm_frame = ttk.Frame(share_frame)
        perm_frame.grid(row=2, column=1, sticky=tk.W)
        ttk.Radiobutton(perm_frame, text="Read Only", variable=self.permission_var, 
                       value="read").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(perm_frame, text="Read & Write", variable=self.permission_var, 
                       value="write").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(share_frame, text="🤝 Share File", command=self.share_file).grid(row=3, column=0, 
                                                                                     columnspan=2, pady=10)
        
        # Refresh button for user list
        ttk.Button(share_frame, text="🔄 Refresh Users", 
                  command=self.refresh_sharing_users).grid(row=4, column=0, columnspan=2, pady=5)
        
        # Shared files list
        shared_frame = ttk.LabelFrame(tab, text="Files Shared With Me", padding="10")
        shared_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        columns = ('filename', 'owner', 'permission')
        self.shared_tree = ttk.Treeview(shared_frame, columns=columns, show='headings', height=8)
        
        self.shared_tree.heading('filename', text='Filename')
        self.shared_tree.heading('owner', text='Owner')
        self.shared_tree.heading('permission', text='Permission')
        
        self.shared_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        share_frame.columnconfigure(1, weight=1)
        shared_frame.columnconfigure(0, weight=1)
        shared_frame.rowconfigure(0, weight=1)
    
    # Helper methods
    def browse_file(self):
        """Browse for file"""
        filename = filedialog.askopenfilename(title="Select File to Upload")
        if filename:
            self.selected_file_path.set(filename)
    
    def generate_key(self):
        """Generate encryption key"""
        key_name = simpledialog.askstring("Generate Key", "Enter key name:")
        if key_name:
            self.key_manager.generate_key(self.current_user, key_name)
            self.refresh_key_list()
            messagebox.showinfo("Success", f"Key '{key_name}' generated!")
    
    def refresh_key_list(self):
        """Refresh key dropdown"""
        keys = self.key_manager.list_user_keys(self.current_user)
        self.key_combo['values'] = keys
    
    def upload_file(self):
        """Upload file with simulation"""
        if not self.selected_file_path.get():
            messagebox.showerror("Error", "Please select a file")
            return
        
        if not self.selected_key_name.get():
            messagebox.showerror("Error", "Please select or generate an encryption key")
            return
        
        key = self.key_manager.get_key(self.current_user, self.selected_key_name.get())
        if not key:
            messagebox.showerror("Error", "Key not found")
            return
        
        # Simulate network upload
        file_size = os.path.getsize(self.selected_file_path.get())
        
        def upload_thread():
            self.simulation.simulate_upload(self.current_user, 
                                           os.path.basename(self.selected_file_path.get()),
                                           file_size)
            
            success, file_id, elapsed, _, _ = self.storage.upload_file(
                self.selected_file_path.get(),
                self.current_user,
                key,
                self.selected_algorithm.get()
            )
            
            self.root.after(0, lambda: self.upload_complete(success, file_id))
        
        threading.Thread(target=upload_thread, daemon=True).start()
        self.status_var.set("Uploading...")
    
    def upload_complete(self, success, file_id):
        """Handle upload completion"""
        if success:
            self.status_var.set("Upload complete!")
            messagebox.showinfo("Success", "File uploaded successfully!")
            self.refresh_all()
        else:
            self.status_var.set("Upload failed")
            messagebox.showerror("Error", "Upload failed")
    
    def download_file(self):
        """Download file"""
        selected = self.file_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a file")
            return
        
        file_id = self.file_tree.item(selected[0])['tags'][0]
        file_info = self.storage.metadata["files"][file_id]
        
        key_name = simpledialog.askstring("Decryption Key", 
                                         "Enter the key name used for encryption:")
        if not key_name:
            return
        
        key = self.key_manager.get_key(self.current_user, key_name)
        if not key:
            messagebox.showerror("Error", "Key not found")
            return
        
        output_path = filedialog.asksaveasfilename(
            title="Save File As",
            initialfile=file_info['filename']
        )
        
        if output_path:
            success, elapsed, _ = self.storage.download_file(file_id, output_path, key)
            
            if success:
                messagebox.showinfo("Success", f"File downloaded!")
                self.simulation.log_activity(self.current_user, 'download', 
                                            f"Downloaded {file_info['filename']}")
            else:
                messagebox.showerror("Error", f"Download failed")
    
    def share_file(self):
        """Share file with selected user"""
        if not self.share_file_combo.get() or not self.share_user_combo.get():
            messagebox.showerror("Error", "Please select file and user")
            return
        
        # Get file ID
        filename = self.share_file_combo.get()
        file_id = None
        for fid, info in self.storage.metadata["files"].items():
            if info['filename'] == filename and info['user_id'] == self.current_user:
                file_id = fid
                break
        
        # Get target user
        target_username = self.share_user_combo.get()
        target_user = self.user_manager.get_user_by_username(target_username)
        
        if file_id and target_user:
            success, message = self.storage.share_file(
                file_id,
                self.current_user,
                target_user.user_id,
                self.permission_var.get()
            )
            
            if success:
                messagebox.showinfo("Success", f"File shared with {target_username}!")
                self.simulation.log_activity(self.current_user, 'share',
                                            f"Shared {filename} with {target_username}")
            else:
                messagebox.showerror("Error", message)
    
    def refresh_sharing_users(self):
        """Refresh user list for sharing"""
        users = self.user_manager.list_users()
        current_user = self.user_manager.get_user(self.current_user)
        
        # Exclude current user
        other_users = [u.username for u in users if u.user_id != self.current_user]
        self.share_user_combo['values'] = other_users
        
        # Refresh file list
        files = self.storage.get_user_files(self.current_user)
        self.share_file_combo['values'] = [f['filename'] for f in files]
    
    def refresh_file_list(self):
        """Refresh file list"""
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        files = self.storage.get_user_files(self.current_user)
        
        for file_info in files:
            size_mb = file_info['size'] / (1024 * 1024)
            upload_time = datetime.fromisoformat(file_info['upload_time']).strftime('%Y-%m-%d %H:%M')
            
            self.file_tree.insert('', tk.END, values=(
                file_info['filename'],
                f"{size_mb:.2f} MB",
                file_info['algorithm'],
                upload_time
            ), tags=(file_info['id'],))
    
    def refresh_user_list(self):
        """Refresh user list"""
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        users = self.user_manager.list_users()
        
        for user in users:
            created = datetime.fromisoformat(user.created_date).strftime('%Y-%m-%d')
            storage_mb = user.storage_used / (1024 * 1024) if user.storage_used > 0 else 0
            
            self.user_tree.insert('', tk.END, values=(
                user.username,
                user.email,
                user.file_count,
                f"{storage_mb:.2f} MB",
                created
            ))
    
    def refresh_visualizations(self):
        """Refresh all charts"""
        # Clear existing charts
        for widget in self.storage_chart_frame.winfo_children():
            widget.destroy()
        for widget in self.user_chart_frame.winfo_children():
            widget.destroy()
        for widget in self.activity_chart_frame.winfo_children():
            widget.destroy()
        
        # Get data
        stats = self.storage.get_storage_stats()
        users = list(self.user_manager.users.keys())
        activity = self.simulation.get_recent_activity()
        
        # Create charts
        self.viz.create_storage_pie_chart(self.storage_chart_frame, stats)
        self.viz.create_storage_bar_chart(self.user_chart_frame, users, self.user_manager)
        self.viz.create_activity_timeline(self.activity_chart_frame, activity)
    
    def simulate_uploads(self):
        """Simulate multiple uploads"""
        self.sim_status.config(text="Simulating uploads...")
        
        users = list(self.user_manager.users.keys())[:5]
        for user_id in users:
            user = self.user_manager.get_user(user_id)
            self.simulation.log_activity(user_id, 'upload', 
                                        f"User {user.username} uploaded test_file.txt")
        
        self.update_activity_log()
        self.sim_status.config(text="Simulation complete")
    
    def simulate_downloads(self):
        """Simulate multiple downloads"""
        self.sim_status.config(text="Simulating downloads...")
        
        users = list(self.user_manager.users.keys())[:5]
        for user_id in users:
            user = self.user_manager.get_user(user_id)
            self.simulation.log_activity(user_id, 'download', 
                                        f"User {user.username} downloaded document.pdf")
        
        self.update_activity_log()
        self.sim_status.config(text="Simulation complete")
    
    def simulate_sharing(self):
        """Simulate file sharing"""
        self.sim_status.config(text="Simulating sharing...")
        
        users = list(self.user_manager.users.keys())[:3]
        if len(users) >= 2:
            user1 = self.user_manager.get_user(users[0])
            user2 = self.user_manager.get_user(users[1])
            self.simulation.log_activity(users[0], 'share',
                                        f"{user1.username} shared file with {user2.username}")
        
        self.update_activity_log()
        self.sim_status.config(text="Simulation complete")
    
    def update_activity_log(self):
        """Update activity log display"""
        self.activity_log.delete(1.0, tk.END)
        
        activities = self.simulation.get_recent_activity()
        
        log_text = "RECENT ACTIVITY LOG\n"
        log_text += "=" * 80 + "\n\n"
        
        for activity in reversed(activities):
            timestamp = datetime.fromisoformat(activity['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            user = self.user_manager.get_user(activity['user_id'])
            username = user.username if user else "Unknown"
            
            log_text += f"[{timestamp}] {username}: {activity['action'].upper()}\n"
            log_text += f"   {activity['details']}\n\n"
        
        self.activity_log.insert(1.0, log_text)
    
    def add_user(self):
        """Add new user"""
        reg_window = tk.Toplevel(self.root)
        reg_window.title("Add New User")
        reg_window.geometry("350x200")
        
        ttk.Label(reg_window, text="Add New User", 
                 font=('Helvetica', 11, 'bold')).pack(pady=10)
        
        frame = ttk.Frame(reg_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(frame, width=25)
        username_entry.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(frame, text="Email:").grid(row=1, column=0, sticky=tk.W, pady=5)
        email_entry = ttk.Entry(frame, width=25)
        email_entry.grid(row=1, column=1, pady=5, padx=5)
        
        def do_add():
            username = username_entry.get().strip()
            email = email_entry.get().strip()
            
            if not username or not email:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            success, result = self.user_manager.register_user(username, email)
            if success:
                messagebox.showinfo("Success", f"User {username} added!")
                self.refresh_user_list()
                self.refresh_sharing_users()
                reg_window.destroy()
            else:
                messagebox.showerror("Error", result)
        
        ttk.Button(frame, text="Add User", command=do_add).grid(
            row=2, column=0, columnspan=2, pady=15)
    
    def show_user_stats(self):
        """Show user statistics"""
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a user")
            return
        
        username = self.user_tree.item(selected[0])['values'][0]
        user = self.user_manager.get_user_by_username(username)
        
        if user:
            stats = f"""
User Statistics for {user.username}
═══════════════════════════════════════

Email: {user.email}
User ID: {user.user_id}
Member Since: {datetime.fromisoformat(user.created_date).strftime('%Y-%m-%d')}

Storage Statistics:
• Files: {user.file_count}
• Storage Used: {user.storage_used / (1024*1024):.2f} MB
"""
            messagebox.showinfo("User Statistics", stats)
    
    def switch_user(self):
        """Switch to different user"""
        # Clear current UI
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.current_user = None
        self.show_login()
    
    def show_user_management(self):
        """Show user management window"""
        self.notebook.select(3)  # Switch to Users tab
    
    def refresh_all(self):
        """Refresh all data"""
        self.refresh_file_list()
        self.refresh_user_list()
        self.refresh_key_list()
        self.refresh_sharing_users()
        self.refresh_visualizations()
        self.update_activity_log()
    
    def show_help(self):
        """Show help"""
        help_text = """
SECURE CLOUD STORAGE V2.0 - HELP

NEW FEATURES:
• User Management - Add and manage multiple users
• Visualization - Charts and graphs for statistics
• Simulation - Test multi-user scenarios
• Enhanced Sharing - Select users from list

USAGE:
1. Upload files with encryption
2. Share files with other users
3. View statistics and visualizations
4. Simulate multi-user activity

Check the Users and Visualization tabs for new features!
"""
        messagebox.showinfo("Help", help_text)
    
    def show_about(self):
        """Show about"""
        about_text = """
╔═══════════════════════════════════════════════╗
║  Secure Cloud Storage V2.0 - ENHANCED        ║
╚═══════════════════════════════════════════════╝

Version: 2.0 (Enhanced)
Created by: Dr. Mohammed Tawfik
Institution: Ajloun National University, Jordan
Date: November 9, 2024

NEW IN V2.0:
✓ User Management System
✓ Visual Charts and Graphs
✓ Multi-User Simulation
✓ Enhanced File Sharing
✓ Activity Monitoring

© 2024 Dr. Mohammed Tawfik
Bachelor Degree Cybersecurity Project
"""
        messagebox.showinfo("About", about_text)


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Set theme
    style = ttk.Style()
    style.theme_use('clam')
    
    app = EnhancedCloudStorageGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
