# 🔍 Project Analyser (HACKxTRIBE1)

An **AI/ML-driven Intelligent Software Code Analysis Platform** designed to enhance **code quality, security, and performance**.  
This project uses **Python**, **AST parsing**, **ML/NLP models**, and advanced heuristics to detect:

- ✅ Security vulnerabilities (OWASP Top 10, STRIDE threats)  
- ✅ Code smells & maintainability issues  
- ✅ Performance bottlenecks & complexity  
- ✅ Quality metrics & dashboard insights  

---

## 🚀 Features

- **Security Analysis**
  - OWASP Top 10 vulnerability detection
  - Threat modeling (STRIDE, attack surface)
  - Cryptographic misuse & injection flaws

- **Code Quality & Smells**
  - Long methods, deep nesting, large classes
  - Duplicate code & poor parameter design
  - Cyclomatic complexity metrics

- **Performance Optimization**
  - Detects nested loops, expensive operations
  - Identifies memory inefficiencies
  - Bottleneck detection (DB, network, file I/O in loops)

- **Dashboard & Reports**
  - Interactive metrics dashboard (HTML/JSON)
  - Security & performance scoring
  - Trend analysis stored in SQLite

---

## 🛠️ Tech Stack

- **Core**: Python 3.x, AST (Abstract Syntax Tree)
- **Machine Learning**: scikit-learn, RandomForest, IsolationForest, KMeans
- **NLP/Embeddings**: TF-IDF, Transformers, Sentence-Transformers
- **Database**: SQLite (for metrics & trends)
- **Visualization**: Plotly, Chart.js (HTML dashboard)

---

## 📂 Project Structure

