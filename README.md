# InjectFuzz ⚡

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Focus](https://img.shields.io/badge/focus-Behavioral%20Analysis-orange?style=flat-square)

> **A professional, behavior-driven injection discovery engine.**

**InjectFuzz** is a security research tool designed to find injection vulnerabilities (SQLi, XSS, SSTI) by analyzing **signals**, not just error messages.

I built this because standard scanners are noisy. They often flag a page just because it returns a 500 Error. InjectFuzz is smarter: it learns the target's "normal" state (Baseline) and only alerts you when a payload causes a statistically significant deviation in **Response Size**, **Timing**, or **Status Code**.

---

## 🧠 The Philosophy: Signal over Noise

Most tools use "Pattern Matching" (Regex).
* *Tool:* "Did I see 'syntax error' in the HTML?"
* *Result:* High False Positives.

**InjectFuzz uses "Differential Analysis".**
* *Tool:* "The page is usually 50KB ± 2KB and takes 0.5s to load. This payload made it 4KB and took 4.0s. That is a **Signal**."
* *Result:* High Confidence, Low Noise.

---

## 🏗️ Architecture



The engine operates in 6 strict phases to ensure data integrity and safety:

1.  **Input Streaming:** Payloads are streamed one-by-one (Lazy Evaluation) so it never eats your RAM.
2.  **Baseline Calibration:** We fire 5-10 requests to calculate the standard deviation (The "Noise Floor").
3.  **Non-Destructive Transport:** We inject into the target parameter while preserving all other query params (Session IDs, Filters).
4.  **Differential Analyzer:** Compares the injection response against the Baseline using the Z-Score method.
5.  **Classifier:** A conservative policy engine labels the result (`POSSIBLE_INJECTION`, `ANOMALY`, or `UNINTERESTING`).
6.  **Atomic Writer:** Findings are flushed to disk instantly. **Crash-Safe.**

---

## 🛠️ Installation

### Prerequisites
* Python 3.10 or higher.

### Quick Start
```bash
# 1. Clone the repository
git clone [https://github.com/YOUR_USERNAME/InjectFuzz.git](https://github.com/YOUR_USERNAME/InjectFuzz.git)
cd InjectFuzz

# 2. Install dependencies
pip install -r requirements.txt

# 3. Setup default payloads (if you haven't already)
mkdir payload
echo "' OR '1'='1" > payload/fuzz.txt

🚀 Usage Guide
1. The "Sanity Check" (Basic Scan)
Test a single URL and parameter to see if the tool works.
Bash


python main.py "[http://testphp.vulnweb.com/listproducts.php?cat=1](http://testphp.vulnweb.com/listproducts.php?cat=1)" "cat"

2. The "Hunter" (Advanced Scan)
Use threading, auto-mutations (URL encoding), and a custom timeout for faster scanning.
Bash


python main.py "[http://example.com/search](http://example.com/search)" "query" \
    --threads 25 \
    --mutate \
    --timeout 5

3. The "Professional" (Authenticated & Proxied)
Route traffic through Burp Suite (Proxy) and include session cookies.
Note: Pass cookies/headers directly in the URL if needed, or use the --data flag for POST.
Bash


python main.py "[http://example.com/admin/login](http://example.com/admin/login)" "username" \
    --method POST \
    --data "username=admin&password=123&csrf_token=xyz" \
    --proxy "[http://127.0.0.1:8080](http://127.0.0.1:8080)"

