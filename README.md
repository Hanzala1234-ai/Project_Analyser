AI/ML-Driven Code Analyser
An AI/ML-powered code analysis platform that helps developers write cleaner, more efficient, and secure code.

This tool can analyze uploaded files, entire project folders, or pasted code snippets, and provides detailed insights into:
-Error detection
-Performance improvements
-Security vulnerabilities
-Code durability & maintainability
-Multi-language support
It also supports real-time analysis, so you can continuously monitor changes in your project folder.

FEATURES

Upload or Paste Code – Analyze individual files, project folders, or directly pasted snippets
Error and Security Analysis – Detects bugs, vulnerabilities (OWASP Top 10, STRIDE threats), and risks
Performance Suggestions – Identifies bottlenecks, code smells, and complexity issues
Durability and Maintainability – Provides recommendations for sustainable code quality
Language Selection – Supports multiple programming languages
Real-time Monitoring – Add a project folder path, and the analyser will continuously check for updates
Quality Dashboard – Generates visual insights and metrics reports

TECH STACK
Core:
Language: Python 3.x
Libraries: ast, os, re, json, hashlib, sqlite3, logging, threading, dataclasses, collections

Machine Learning and NLP:
Scikit-learn: Random Forest, Isolation Forest, TF-IDF, KMeans
NumPy for numerical operations
Joblib for model persistence
Transformers (HuggingFace) (optional) for advanced NLP models
Sentence-Transformers (optional) for semantic embeddings

Security and Threat Modeling:
Custom OWASP Top 10 vulnerability detection
STRIDE-based threat modeling engine
Advanced security metrics tracker

Performance and Quality Analysis:
Code Smell Detection: long methods, deep nesting, duplicate code
Performance Optimization Engine: algorithm complexity, bottlenecks, I/O inefficiencies
Profiler and Metrics Tracker

Real-time Monitoring:
Watchdog – live folder/file monitoring

Data Storage and Dashboard:
SQLite3 for metrics persistence
Plotly / Chart.js for visualizations
Interactive HTML Dashboard for reports

GETTING STARTED

Prerequisites
Python 3.9+
pip installed

Installation
Clone the repository:
git clone
Navigate to project folder:
cd <repo-name>
Install dependencies:
pip install -r requirements.txt
Run the Application

python hack3.py

USAGE
Upload Code – Select a file/folder or paste your code
Choose Language – Pick the programming language of your code
Get Insights – View error reports, performance metrics, and security issues
Real-time Mode – Add a folder path for continuous monitoring
Dashboard – Generate visual reports and quality metrics

SECURITY AND RELIABILITY
Detects common vulnerabilities (SQL Injection, XSS, insecure API calls, etc.)
Covers OWASP Top 10 and STRIDE threats
Encourages best practices for maintainability
Provides AI-powered suggestions for improvement
