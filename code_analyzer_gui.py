#!/usr/bin/env python3
"""
Interactive GUI for AI/ML-Driven Code Analysis Platform
Allows users to input code by copy/paste or file browsing
Provides access to all analysis features with a modern interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import tkinter.font as tkfont
import os
import sys
import json
import tempfile
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, '.')

class CodeAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 AI/ML Code Analyzer - Interactive Platform")
        self.root.geometry("1400x900")
        
        # Set modern theme colors
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#007ACC"
        self.success_color = "#4CAF50"
        self.warning_color = "#FFC107"
        self.error_color = "#F44336"
        
        # Configure root window
        self.root.configure(bg=self.bg_color)
        
        # Initialize variables
        self.current_file_path = None
        self.analysis_thread = None
        self.temp_files = []
        
        # Setup UI
        self.setup_ui()
        self.setup_styles()
        
        # Bind keyboard shortcuts
        self.setup_shortcuts()
        
    def setup_styles(self):
        """Configure ttk styles for modern look"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Title.TLabel', 
                       background=self.bg_color,
                       foreground=self.accent_color,
                       font=('Arial', 16, 'bold'))
        
        style.configure('Heading.TLabel',
                       background=self.bg_color,
                       foreground=self.fg_color,
                       font=('Arial', 12, 'bold'))
        
        style.configure('Modern.TButton',
                       background=self.accent_color,
                       foreground=self.fg_color,
                       borderwidth=0,
                       focuscolor='none',
                       font=('Arial', 10))
        
        style.map('Modern.TButton',
                 background=[('active', '#005a9e')])
        
        style.configure('Success.TButton',
                       background=self.success_color,
                       foreground=self.fg_color,
                       borderwidth=0)
        
        style.configure('Modern.TFrame',
                       background=self.bg_color,
                       borderwidth=1,
                       relief='solid')
    
    def setup_ui(self):
        """Setup the main UI components"""
        # Create main container
        main_container = ttk.Frame(self.root, style='Modern.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title Section
        self.create_title_section(main_container)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Tab 1: Code Input
        self.input_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.input_tab, text="📝 Code Input")
        self.create_input_tab()
        
        # Tab 2: Analysis Results
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="📊 Analysis Results")
        self.create_results_tab()
        
        # Tab 3: Advanced Options
        self.options_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.options_tab, text="⚙️ Advanced Options")
        self.create_options_tab()
        
        # Tab 4: Real-time Monitor
        self.monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_tab, text="🔄 Real-time Monitor")
        self.create_monitor_tab()
        
        # Status bar
        self.create_status_bar(main_container)
    
    def create_title_section(self, parent):
        """Create the title section with logo and description"""
        title_frame = ttk.Frame(parent, style='Modern.TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(title_frame, 
                                text="🚀 AI/ML-Driven Code Analysis Platform",
                                style='Title.TLabel')
        title_label.pack(side=tk.LEFT, padx=10)
        
        # Quick actions
        quick_frame = ttk.Frame(title_frame)
        quick_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Button(quick_frame, text="📁 Open Project",
                  command=self.browse_folder,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(quick_frame, text="📄 Open File",
                  command=self.browse_file,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(quick_frame, text="▶️ Quick Analyze",
                  command=self.quick_analyze,
                  style='Success.TButton').pack(side=tk.LEFT, padx=2)
    
    def create_input_tab(self):
        """Create the code input tab"""
        # Create three columns
        paned = ttk.PanedWindow(self.input_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Input options
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        # Input method selection
        ttk.Label(left_frame, text="Input Method:", 
                 style='Heading.TLabel').pack(pady=5)
        
        # Buttons frame
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="📋 Paste Code",
                  command=self.paste_code,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(btn_frame, text="📂 Browse File",
                  command=self.browse_file,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(btn_frame, text="📁 Browse Folder",
                  command=self.browse_folder,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(btn_frame, text="🔗 From URL",
                  command=self.load_from_url,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(btn_frame, text="📝 New Code",
                  command=self.new_code,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        # Language selection
        ttk.Label(left_frame, text="Language:", 
                 style='Heading.TLabel').pack(pady=(20, 5))
        
        self.language_var = tk.StringVar(value="python")
        languages = ["python", "javascript", "java", "cpp", "go", "rust", "typescript"]
        self.language_combo = ttk.Combobox(left_frame, 
                                           textvariable=self.language_var,
                                           values=languages,
                                           state="readonly",
                                           width=18)
        self.language_combo.pack(pady=5)
        
        # File info
        ttk.Label(left_frame, text="Current File:", 
                 style='Heading.TLabel').pack(pady=(20, 5))
        
        self.file_info_label = ttk.Label(left_frame, 
                                         text="No file loaded",
                                         foreground="#888888")
        self.file_info_label.pack(pady=5)
        
        # Analysis buttons
        ttk.Label(left_frame, text="Analysis Actions:", 
                 style='Heading.TLabel').pack(pady=(20, 5))
        
        action_frame = ttk.Frame(left_frame)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="🔍 Analyze",
                  command=self.analyze_code,
                  style='Success.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(action_frame, text="🔒 Security Scan",
                  command=self.security_scan,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(action_frame, text="⚡ Performance Check",
                  command=self.performance_check,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        ttk.Button(action_frame, text="📊 Quality Metrics",
                  command=self.quality_metrics,
                  style='Modern.TButton',
                  width=20).pack(pady=2)
        
        # Right panel - Code editor
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)
        
        # Code editor header
        editor_header = ttk.Frame(right_frame)
        editor_header.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(editor_header, text="Code Editor:", 
                 style='Heading.TLabel').pack(side=tk.LEFT)
        
        # Editor buttons
        ttk.Button(editor_header, text="Clear",
                  command=self.clear_editor,
                  style='Modern.TButton').pack(side=tk.RIGHT, padx=2)
        
        ttk.Button(editor_header, text="Format",
                  command=self.format_code,
                  style='Modern.TButton').pack(side=tk.RIGHT, padx=2)
        
        ttk.Button(editor_header, text="Copy",
                  command=self.copy_code,
                  style='Modern.TButton').pack(side=tk.RIGHT, padx=2)
        
        # Code editor
        self.code_editor = scrolledtext.ScrolledText(right_frame,
                                                     wrap=tk.NONE,
                                                     font=('Consolas', 11),
                                                     bg="#2d2d2d",
                                                     fg="#f8f8f2",
                                                     insertbackground="#ffffff",
                                                     selectbackground="#44475a",
                                                     selectforeground="#ffffff",
                                                     undo=True)
        self.code_editor.pack(fill=tk.BOTH, expand=True)
        
        # Add line numbers (simplified)
        self.add_line_numbers()
    
    def create_results_tab(self):
        """Create the results display tab"""
        # Create paned window for results
        paned = ttk.PanedWindow(self.results_tab, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top frame - Summary
        summary_frame = ttk.LabelFrame(paned, text="Analysis Summary")
        paned.add(summary_frame, weight=1)
        
        # Summary text
        self.summary_text = scrolledtext.ScrolledText(summary_frame,
                                                      height=8,
                                                      font=('Arial', 10),
                                                      bg="#2d2d2d",
                                                      fg="#f8f8f2")
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom frame - Detailed results
        results_frame = ttk.LabelFrame(paned, text="Detailed Results")
        paned.add(results_frame, weight=2)
        
        # Results toolbar
        toolbar = ttk.Frame(results_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(toolbar, text="📄 Export HTML",
                  command=self.export_html,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(toolbar, text="📋 Export JSON",
                  command=self.export_json,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(toolbar, text="📊 Show Dashboard",
                  command=self.show_dashboard,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(toolbar, text="🔄 Refresh",
                  command=self.refresh_results,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                      font=('Consolas', 10),
                                                      bg="#2d2d2d",
                                                      fg="#f8f8f2")
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for colored output
        self.results_text.tag_config("critical", foreground="#ff5555")
        self.results_text.tag_config("high", foreground="#ffb86c")
        self.results_text.tag_config("medium", foreground="#f1fa8c")
        self.results_text.tag_config("low", foreground="#50fa7b")
        self.results_text.tag_config("info", foreground="#8be9fd")
        self.results_text.tag_config("success", foreground="#50fa7b")
        self.results_text.tag_config("heading", foreground="#bd93f9", font=('Arial', 11, 'bold'))
    
    def create_options_tab(self):
        """Create the advanced options tab"""
        # Create scrollable frame
        canvas = tk.Canvas(self.options_tab, bg=self.bg_color)
        scrollbar = ttk.Scrollbar(self.options_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Analysis Options
        analysis_frame = ttk.LabelFrame(scrollable_frame, text="Analysis Options")
        analysis_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Checkboxes for features
        self.enable_security = tk.BooleanVar(value=True)
        ttk.Checkbutton(analysis_frame, text="🔒 Security Analysis",
                       variable=self.enable_security).pack(anchor=tk.W, padx=10, pady=2)
        
        self.enable_performance = tk.BooleanVar(value=True)
        ttk.Checkbutton(analysis_frame, text="⚡ Performance Analysis",
                       variable=self.enable_performance).pack(anchor=tk.W, padx=10, pady=2)
        
        self.enable_quality = tk.BooleanVar(value=True)
        ttk.Checkbutton(analysis_frame, text="📊 Quality Metrics",
                       variable=self.enable_quality).pack(anchor=tk.W, padx=10, pady=2)
        
        self.enable_style = tk.BooleanVar(value=True)
        ttk.Checkbutton(analysis_frame, text="✨ Style Checking",
                       variable=self.enable_style).pack(anchor=tk.W, padx=10, pady=2)
        
        self.enable_ml = tk.BooleanVar(value=True)
        ttk.Checkbutton(analysis_frame, text="🤖 AI/ML Analysis",
                       variable=self.enable_ml).pack(anchor=tk.W, padx=10, pady=2)
        
        # Performance Options
        perf_frame = ttk.LabelFrame(scrollable_frame, text="Performance Options")
        perf_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(perf_frame, text="Worker Threads:").pack(anchor=tk.W, padx=10, pady=2)
        self.workers_var = tk.IntVar(value=4)
        ttk.Scale(perf_frame, from_=1, to=16, variable=self.workers_var,
                 orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=2)
        
        ttk.Label(perf_frame, text="Confidence Threshold:").pack(anchor=tk.W, padx=10, pady=2)
        self.confidence_var = tk.DoubleVar(value=0.7)
        ttk.Scale(perf_frame, from_=0.1, to=1.0, variable=self.confidence_var,
                 orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=2)
        
        # Output Options
        output_frame = ttk.LabelFrame(scrollable_frame, text="Output Options")
        output_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(output_frame, text="Output Format:").pack(anchor=tk.W, padx=10, pady=2)
        self.output_format = tk.StringVar(value="html")
        formats = ["html", "json", "markdown", "sarif", "xml"]
        ttk.Combobox(output_frame, textvariable=self.output_format,
                    values=formats, state="readonly").pack(fill=tk.X, padx=10, pady=2)
        
        ttk.Label(output_frame, text="Report Detail Level:").pack(anchor=tk.W, padx=10, pady=2)
        self.detail_level = tk.StringVar(value="normal")
        levels = ["minimal", "normal", "detailed", "verbose"]
        ttk.Combobox(output_frame, textvariable=self.detail_level,
                    values=levels, state="readonly").pack(fill=tk.X, padx=10, pady=2)
        
        # Advanced Settings
        advanced_frame = ttk.LabelFrame(scrollable_frame, text="Advanced Settings")
        advanced_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.enable_cache = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Enable Caching",
                       variable=self.enable_cache).pack(anchor=tk.W, padx=10, pady=2)
        
        self.enable_incremental = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Incremental Analysis",
                       variable=self.enable_incremental).pack(anchor=tk.W, padx=10, pady=2)
        
        self.enable_parallel = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Parallel Processing",
                       variable=self.enable_parallel).pack(anchor=tk.W, padx=10, pady=2)
        
        # Save/Load Configuration
        config_frame = ttk.Frame(scrollable_frame)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(config_frame, text="💾 Save Config",
                  command=self.save_config,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(config_frame, text="📂 Load Config",
                  command=self.load_config,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(config_frame, text="🔄 Reset Defaults",
                  command=self.reset_config,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_monitor_tab(self):
        """Create the real-time monitoring tab"""
        # Monitor controls
        control_frame = ttk.Frame(self.monitor_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Monitor Path:",
                 style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        
        self.monitor_path_var = tk.StringVar()
        self.monitor_entry = ttk.Entry(control_frame, 
                                      textvariable=self.monitor_path_var,
                                      width=50)
        self.monitor_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Browse",
                  command=self.browse_monitor_path,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(control_frame, text="▶️ Start",
                  command=self.start_monitoring,
                  style='Success.TButton').pack(side=tk.LEFT, padx=2)
        
        ttk.Button(control_frame, text="⏹️ Stop",
                  command=self.stop_monitoring,
                  style='Modern.TButton').pack(side=tk.LEFT, padx=2)
        
        # Monitor status
        status_frame = ttk.LabelFrame(self.monitor_tab, text="Monitor Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.monitor_status_label = ttk.Label(status_frame, 
                                             text="⏸️ Not monitoring",
                                             font=('Arial', 11))
        self.monitor_status_label.pack(padx=10, pady=5)
        
        # Monitor log
        log_frame = ttk.LabelFrame(self.monitor_tab, text="Real-time Analysis Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame,
                                                     font=('Consolas', 10),
                                                     bg="#2d2d2d",
                                                     fg="#f8f8f2")
        self.monitor_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_status_bar(self, parent):
        """Create the status bar"""
        self.status_frame = ttk.Frame(parent)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(5, 0))
        
        self.status_label = ttk.Label(self.status_frame, 
                                     text="Ready",
                                     relief=tk.SUNKEN,
                                     anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress = ttk.Progressbar(self.status_frame,
                                       mode='indeterminate',
                                       length=100)
        self.progress.pack(side=tk.RIGHT, padx=5)
    
    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.root.bind('<Control-o>', lambda e: self.browse_file())
        self.root.bind('<Control-s>', lambda e: self.save_code())
        self.root.bind('<Control-v>', lambda e: self.paste_code())
        self.root.bind('<Control-a>', lambda e: self.analyze_code())
        self.root.bind('<F5>', lambda e: self.quick_analyze())
        self.root.bind('<Control-n>', lambda e: self.new_code())
    
    # Action methods
    def paste_code(self):
        """Paste code from clipboard"""
        try:
            clipboard_text = self.root.clipboard_get()
            self.code_editor.delete(1.0, tk.END)
            self.code_editor.insert(1.0, clipboard_text)
            self.update_status("Code pasted from clipboard")
            self.current_file_path = None
            self.file_info_label.config(text="Pasted code (unsaved)")
        except tk.TclError:
            messagebox.showwarning("Clipboard Empty", "No text found in clipboard")
    
    def browse_file(self):
        """Browse and load a code file"""
        file_path = filedialog.askopenfilename(
            title="Select Code File",
            filetypes=[
                ("Python files", "*.py"),
                ("JavaScript files", "*.js"),
                ("Java files", "*.java"),
                ("C++ files", "*.cpp"),
                ("Go files", "*.go"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.load_file(file_path)
    
    def browse_folder(self):
        """Browse and analyze a folder"""
        folder_path = filedialog.askdirectory(title="Select Project Folder")
        
        if folder_path:
            self.analyze_folder(folder_path)
    
    def load_file(self, file_path):
        """Load a file into the editor"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.code_editor.delete(1.0, tk.END)
            self.code_editor.insert(1.0, content)
            
            self.current_file_path = file_path
            self.file_info_label.config(text=os.path.basename(file_path))
            
            # Auto-detect language
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.java': 'java',
                '.cpp': 'cpp',
                '.go': 'go',
                '.rs': 'rust',
                '.ts': 'typescript'
            }
            if ext in lang_map:
                self.language_var.set(lang_map[ext])
            
            self.update_status(f"Loaded: {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def load_from_url(self):
        """Load code from URL"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Load from URL")
        dialog.geometry("500x150")
        
        ttk.Label(dialog, text="Enter URL:").pack(pady=10)
        
        url_var = tk.StringVar()
        url_entry = ttk.Entry(dialog, textvariable=url_var, width=60)
        url_entry.pack(pady=10)
        
        def load():
            url = url_var.get()
            if url:
                try:
                    import urllib.request
                    with urllib.request.urlopen(url) as response:
                        content = response.read().decode('utf-8')
                    
                    self.code_editor.delete(1.0, tk.END)
                    self.code_editor.insert(1.0, content)
                    
                    self.current_file_path = None
                    self.file_info_label.config(text=f"From URL: {url[:30]}...")
                    self.update_status(f"Loaded from URL: {url}")
                    
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load from URL: {str(e)}")
        
        ttk.Button(dialog, text="Load", command=load).pack(pady=10)
    
    def new_code(self):
        """Create new code file"""
        self.code_editor.delete(1.0, tk.END)
        self.current_file_path = None
        self.file_info_label.config(text="New file (unsaved)")
        self.update_status("New file created")
    
    def clear_editor(self):
        """Clear the code editor"""
        self.code_editor.delete(1.0, tk.END)
        self.update_status("Editor cleared")
    
    def copy_code(self):
        """Copy code to clipboard"""
        content = self.code_editor.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.update_status("Code copied to clipboard")
    
    def format_code(self):
        """Format the code (placeholder)"""
        # This would integrate with code formatters
        self.update_status("Code formatting not yet implemented")
    
    def save_code(self):
        """Save the current code"""
        if self.current_file_path:
            file_path = self.current_file_path
        else:
            file_path = filedialog.asksaveasfilename(
                title="Save Code",
                defaultextension=".py",
                filetypes=[
                    ("Python files", "*.py"),
                    ("JavaScript files", "*.js"),
                    ("All files", "*.*")
                ]
            )
        
        if file_path:
            try:
                content = self.code_editor.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                self.current_file_path = file_path
                self.file_info_label.config(text=os.path.basename(file_path))
                self.update_status(f"Saved: {file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def analyze_code(self):
        """Analyze the current code"""
        content = self.code_editor.get(1.0, tk.END).strip()
        
        if not content:
            messagebox.showwarning("No Code", "Please enter or load code to analyze")
            return
        
        # Start analysis in a separate thread
        self.analysis_thread = threading.Thread(target=self._run_analysis, args=(content,))
        self.analysis_thread.start()
    
    def _run_analysis(self, content):
        """Run the actual analysis (in a separate thread)"""
        self.update_status("Analyzing code...")
        self.progress.start()
        
        try:
            # Save content to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', 
                                           delete=False, encoding='utf-8') as tmp:
                tmp.write(content)
                temp_file = tmp.name
                self.temp_files.append(temp_file)
            
            # Build command
            cmd = [sys.executable, 'hack3.py', temp_file]
            
            # Add options based on settings
            if self.output_format.get() != 'html':
                cmd.extend(['--output', self.output_format.get()])
            
            if self.enable_parallel.get():
                cmd.extend(['--workers', str(int(self.workers_var.get()))])
            
            # Run analysis
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Display results
            self.root.after(0, self._display_results, result.stdout, result.stderr)
            
        except subprocess.TimeoutExpired:
            self.root.after(0, self.update_status, "Analysis timed out")
        except Exception as e:
            self.root.after(0, self.update_status, f"Analysis failed: {str(e)}")
        finally:
            self.root.after(0, self.progress.stop)
            # Clean up temp files
            for temp_file in self.temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def _display_results(self, stdout, stderr):
        """Display analysis results"""
        self.results_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        
        # Parse and display results
        if stdout:
            # Extract summary if available
            if "Enhanced Analysis Summary" in stdout:
                summary_start = stdout.find("Enhanced Analysis Summary")
                summary = stdout[summary_start:summary_start+500]
                self.summary_text.insert(1.0, summary)
            elif "Analysis complete" in stdout:
                lines = stdout.split('\n')
                for line in lines:
                    if 'Total issues' in line or 'Score' in line:
                        self.summary_text.insert(tk.END, line + '\n')
            
            # Display full results with syntax highlighting
            self._display_colored_results(stdout)
        
        if stderr and "Error" in stderr:
            self.results_text.insert(tk.END, "\n=== Errors ===\n", "heading")
            self.results_text.insert(tk.END, stderr, "critical")
        
        self.update_status("Analysis complete")
        self.notebook.select(self.results_tab)
    
    def _display_colored_results(self, text):
        """Display results with color coding"""
        lines = text.split('\n')
        
        for line in lines:
            if 'CRITICAL' in line or 'critical' in line.lower():
                self.results_text.insert(tk.END, line + '\n', "critical")
            elif 'HIGH' in line or 'high' in line.lower():
                self.results_text.insert(tk.END, line + '\n', "high")
            elif 'MEDIUM' in line or 'medium' in line.lower():
                self.results_text.insert(tk.END, line + '\n', "medium")
            elif 'LOW' in line or 'low' in line.lower():
                self.results_text.insert(tk.END, line + '\n', "low")
            elif '===' in line or '---' in line:
                self.results_text.insert(tk.END, line + '\n', "heading")
            elif '✓' in line or 'Success' in line:
                self.results_text.insert(tk.END, line + '\n', "success")
            else:
                self.results_text.insert(tk.END, line + '\n')
    
    def quick_analyze(self):
        """Quick analysis with default settings"""
        self.analyze_code()
    
    def security_scan(self):
        """Run security-focused analysis"""
        # Temporarily set options for security
        old_security = self.enable_security.get()
        old_perf = self.enable_performance.get()
        old_quality = self.enable_quality.get()
        
        self.enable_security.set(True)
        self.enable_performance.set(False)
        self.enable_quality.set(False)
        
        self.analyze_code()
        
        # Restore settings
        self.enable_security.set(old_security)
        self.enable_performance.set(old_perf)
        self.enable_quality.set(old_quality)
    
    def performance_check(self):
        """Run performance-focused analysis"""
        # Similar to security_scan but for performance
        self.update_status("Running performance analysis...")
        self.analyze_code()
    
    def quality_metrics(self):
        """Run quality metrics analysis"""
        self.update_status("Calculating quality metrics...")
        self.analyze_code()
    
    def analyze_folder(self, folder_path):
        """Analyze an entire folder"""
        self.update_status(f"Analyzing folder: {folder_path}")
        
        # Run analysis on folder
        def run_folder_analysis():
            self.progress.start()
            try:
                cmd = [sys.executable, 'hack3.py', folder_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                self.root.after(0, self._display_results, result.stdout, result.stderr)
            except Exception as e:
                self.root.after(0, self.update_status, f"Folder analysis failed: {str(e)}")
            finally:
                self.root.after(0, self.progress.stop)
        
        threading.Thread(target=run_folder_analysis).start()
    
    def export_html(self):
        """Export results as HTML"""
        file_path = filedialog.asksaveasfilename(
            title="Export HTML Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")]
        )
        
        if file_path:
            content = self.results_text.get(1.0, tk.END)
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Code Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Code Analysis Report</h1>
                <pre>{content}</pre>
            </body>
            </html>
            """
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.update_status(f"Report exported: {file_path}")
    
    def export_json(self):
        """Export results as JSON"""
        file_path = filedialog.asksaveasfilename(
            title="Export JSON Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if file_path:
            # This would need proper JSON formatting
            content = self.results_text.get(1.0, tk.END)
            json_data = {
                "analysis_results": content,
                "timestamp": datetime.now().isoformat(),
                "language": self.language_var.get()
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2)
            
            self.update_status(f"JSON exported: {file_path}")
    
    def show_dashboard(self):
        """Show analysis dashboard (placeholder)"""
        messagebox.showinfo("Dashboard", "Dashboard feature coming soon!")
    
    def refresh_results(self):
        """Refresh the results display"""
        if self.current_file_path or self.code_editor.get(1.0, tk.END).strip():
            self.analyze_code()
        else:
            self.update_status("No code to analyze")
    
    def save_config(self):
        """Save current configuration"""
        config = {
            "enable_security": self.enable_security.get(),
            "enable_performance": self.enable_performance.get(),
            "enable_quality": self.enable_quality.get(),
            "enable_style": self.enable_style.get(),
            "enable_ml": self.enable_ml.get(),
            "workers": self.workers_var.get(),
            "confidence": self.confidence_var.get(),
            "output_format": self.output_format.get(),
            "detail_level": self.detail_level.get(),
            "enable_cache": self.enable_cache.get(),
            "enable_incremental": self.enable_incremental.get(),
            "enable_parallel": self.enable_parallel.get()
        }
        
        file_path = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=2)
            self.update_status(f"Configuration saved: {file_path}")
    
    def load_config(self):
        """Load configuration from file"""
        file_path = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON files", "*.json")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                
                # Apply configuration
                self.enable_security.set(config.get("enable_security", True))
                self.enable_performance.set(config.get("enable_performance", True))
                self.enable_quality.set(config.get("enable_quality", True))
                self.enable_style.set(config.get("enable_style", True))
                self.enable_ml.set(config.get("enable_ml", True))
                self.workers_var.set(config.get("workers", 4))
                self.confidence_var.set(config.get("confidence", 0.7))
                self.output_format.set(config.get("output_format", "html"))
                self.detail_level.set(config.get("detail_level", "normal"))
                self.enable_cache.set(config.get("enable_cache", True))
                self.enable_incremental.set(config.get("enable_incremental", False))
                self.enable_parallel.set(config.get("enable_parallel", True))
                
                self.update_status(f"Configuration loaded: {file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")
    
    def reset_config(self):
        """Reset configuration to defaults"""
        self.enable_security.set(True)
        self.enable_performance.set(True)
        self.enable_quality.set(True)
        self.enable_style.set(True)
        self.enable_ml.set(True)
        self.workers_var.set(4)
        self.confidence_var.set(0.7)
        self.output_format.set("html")
        self.detail_level.set("normal")
        self.enable_cache.set(True)
        self.enable_incremental.set(False)
        self.enable_parallel.set(True)
        
        self.update_status("Configuration reset to defaults")
    
    def browse_monitor_path(self):
        """Browse for monitoring path"""
        path = filedialog.askdirectory(title="Select Path to Monitor")
        if path:
            self.monitor_path_var.set(path)
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        path = self.monitor_path_var.get()
        
        if not path:
            messagebox.showwarning("No Path", "Please select a path to monitor")
            return
        
        self.monitor_status_label.config(text="▶️ Monitoring active")
        self.monitor_log.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Started monitoring: {path}\n")
        self.update_status(f"Monitoring: {path}")
        
        # Start monitoring thread
        # This would integrate with real-time monitoring functionality
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitor_status_label.config(text="⏸️ Monitoring stopped")
        self.monitor_log.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring stopped\n")
        self.update_status("Monitoring stopped")
    
    def add_line_numbers(self):
        """Add line numbers to the code editor (simplified)"""
        # This is a simplified version - full implementation would be more complex
        pass
    
    def update_status(self, message):
        """Update the status bar"""
        self.status_label.config(text=message)
        self.root.update_idletasks()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = CodeAnalyzerGUI(root)
    
    # Center the window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    main()
