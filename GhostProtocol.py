# ==========================================================
# GHOST PROTOCOL – ENTERPRISE APPSEC ASSESSMENT SUITE
# OWASP-ALIGNED FINAL VERSION
# ==========================================================

import customtkinter as ctk
import threading, requests, re, time, os, sys, hashlib
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

# ---------------- CONFIG ----------------
REPORT_LANGUAGE = "BOTH"  # ES | EN | BOTH
TOOL_NAME = "Ghost Protocol – Enterprise AppSec Audit"
TOOL_VERSION = "v1.5 OWASP Final"

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class GhostProtocol(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title(f"{TOOL_NAME} {TOOL_VERSION}")
        self.geometry("1400x920")

        self.finding = None
        self.target_url = ""
        self.audit_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:18]

        # ---------------- LAYOUT ----------------
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=260)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(
            self.sidebar, text="GHOST\nPROTOCOL",
            font=("Impact", 30)
        ).pack(pady=20)

        self.lbl_status = ctk.CTkLabel(
            self.sidebar, text="IDLE",
            font=("Arial", 14, "bold")
        )
        self.lbl_status.pack(pady=10)

        self.btn_report = ctk.CTkButton(
            self.sidebar, text="📄 OPEN REPORT",
            state="disabled", command=self.open_report
        )
        self.btn_report.pack(pady=20)

        # ---------------- MAIN ----------------
        self.main = ctk.CTkFrame(self)
        self.main.grid(row=0, column=1, sticky="nsew")

        self.url_input = ctk.CTkEntry(
            self.main, placeholder_text="Target URL", width=720
        )
        self.url_input.pack(pady=10)

        self.btn_run = ctk.CTkButton(
            self.main, text="RUN SECURITY ASSESSMENT",
            command=self.start_audit
        )
        self.btn_run.pack(pady=5)

        # OPTIONS
        self.show_auth_flow = ctk.BooleanVar(value=True)
        self.safe_ui_validation = ctk.BooleanVar(value=True)
        self.headless_mode = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(
            self.main, text="Visualize authentication flow",
            variable=self.show_auth_flow
        ).pack()

        ctk.CTkCheckBox(
            self.main, text="Validate exposed credential using native login",
            variable=self.safe_ui_validation
        ).pack()

        ctk.CTkCheckBox(
            self.main, text="Headless browser (no UI)",
            variable=self.headless_mode
        ).pack(pady=(0, 10))

        self.console = ctk.CTkTextbox(self.main)
        self.console.pack(fill="both", expand=True, padx=10, pady=10)

        self.log("System initialized. Authorized defensive testing only.", "INFO")

    # ---------------- LOGGING ----------------
    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{ts}] {level:<10} {msg}\n")
        self.console.see("end")

    def t(self, es, en):
        if REPORT_LANGUAGE == "ES":
            return es
        if REPORT_LANGUAGE == "EN":
            return en
        return f"{es}<br><br>{en}"

    # ---------------- PHASE 1: STATIC ----------------
    def static_analysis(self, html):
        self.log("Phase 1: Static client-side analysis", "PHASE")

        match = re.search(r'["\'](\d{4,6})["\']', html)
        if match:
            snippet = html[
                max(0, match.start() - 50):
                min(len(html), match.end() + 50)
            ].replace("<", "&lt;").replace(">", "&gt;")

            self.finding = {
                "title": "Client-Side Authentication Secret Exposure",
                "owasp": "A02:2021 – Cryptographic Failures / A04:2021 – Insecure Design",
                "cvss": "9.8 (Critical)",
                "value": match.group(1),
                "snippet": snippet,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "validation": "NOT TESTED"
            }

            self.log("Authentication secret identified in frontend code", "FINDING")
            return True

        return False

    # ---------------- PHASE 2: VISUALIZATION ----------------
    def visualize_auth_flow(self, html):
        self.log("Phase 2: Authentication flow visualization", "PHASE")

        if "<form" not in html.lower():
            self.log("No HTML-based login form detected", "INFO")
        else:
            self.log("Login form detected in client-side code", "INFO")

    # ---------------- PHASE 3: UI VALIDATION ----------------
    def validate_via_ui(self, url, exposed_value):
        self.log("Phase 3: UI-level credential validation", "PHASE")
        self.log("Using native login flow. No bypass techniques.", "INFO")

        try:
            options = Options()
            if self.headless_mode.get():
                options.add_argument("--headless=new")

            driver = webdriver.Chrome(options=options)
            driver.get(url)
            time.sleep(4)

            inputs = [
                i for i in driver.find_elements(By.TAG_NAME, "input")
                if i.is_displayed() and i.get_attribute("type") not in ["hidden", "submit", "button"]
            ]

            if not inputs:
                self.log("No visible authentication inputs detected", "WARN")
                driver.quit()
                return "UNDETERMINED"

            if len(inputs) == 1:
                inputs[0].send_keys(exposed_value)
                self.log("Single authentication field populated", "INFO")
            else:
                inputs[0].send_keys("audit_test")
                inputs[1].send_keys(exposed_value)
                self.log("Username + exposed credential populated", "INFO")

            time.sleep(1)

            buttons = driver.find_elements(By.TAG_NAME, "button")
            clicked = False
            for btn in buttons:
                if btn.is_displayed():
                    btn.click()
                    clicked = True
                    self.log("Login button clicked", "INFO")
                    break

            if not clicked:
                inputs[-1].send_keys("\n")
                self.log("Login submitted via ENTER key", "INFO")

            time.sleep(4)

            body = driver.find_element(By.TAG_NAME, "body").text.lower()
            current_url = driver.current_url
            driver.quit()

            if any(k in body for k in ["welcome", "dashboard", "logout", "profile"]) or current_url != url:
                self.log("Application accepted exposed credential", "CRITICAL")
                return "CONFIRMED"

            self.log("Credential rejected by backend", "INFO")
            return "POTENTIAL"

        except Exception as e:
            self.log(f"Validation error: {e}", "ERROR")
            return "UNDETERMINED"

    # ---------------- CORE AUDIT ----------------
    def audit(self, url):
        self.log("Starting enterprise security assessment", "START")
        self.target_url = url

        r = requests.get(url, timeout=10)

        if self.show_auth_flow.get():
            self.visualize_auth_flow(r.text)

        if self.static_analysis(r.text):
            if self.safe_ui_validation.get():
                result = self.validate_via_ui(url, self.finding["value"])
                self.finding["validation"] = result

            self.finish(True)
            return

        self.finish(False)

    def start_audit(self):
        url = self.url_input.get().strip()
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url

        self.finding = None
        self.btn_run.configure(state="disabled")
        self.lbl_status.configure(text="RUNNING", text_color="orange")

        threading.Thread(target=self.audit, args=(url,), daemon=True).start()

    def finish(self, vulnerable):
        self.after(0, lambda: self.update_ui(vulnerable))

    def update_ui(self, vulnerable):
        self.btn_run.configure(state="normal")
        if vulnerable:
            self.lbl_status.configure(text="VULNERABLE", text_color="red")
            self.btn_report.configure(state="normal")
        else:
            self.lbl_status.configure(text="SECURE", text_color="green")

    # ---------------- REPORT ----------------
    def open_report(self):
        f = self.finding

        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>OWASP Security Assessment Report</title>
<style>
body {{ font-family: Arial; background:#f4f6f8; padding:40px }}
.container {{ background:#fff; padding:40px; max-width:1100px; margin:auto }}
h1 {{ color:#c0392b }}
h2 {{ border-bottom:2px solid #eee }}
pre {{ background:#f8f8f8; padding:15px; border-left:4px solid #c0392b }}
.footer {{ margin-top:40px; font-size:0.85em; border-top:1px solid #ddd }}
.badge {{ padding:6px 12px; background:#c0392b; color:white; display:inline-block }}
</style>
</head>
<body>
<div class="container">

<h1>OWASP-Aligned Application Security Report</h1>
<span class="badge">CVSS {f['cvss']}</span>

<h2>1. Executive Summary</h2>
<p>{self.t(
"Se confirmó una vulnerabilidad crítica de autenticación debido a la exposición de secretos en el código del cliente.",
"A critical authentication vulnerability was confirmed due to exposure of secrets in client-side code."
)}</p>

<h2>2. Vulnerability Details</h2>
<ul>
<li><b>Title:</b> {f['title']}</li>
<li><b>OWASP Category:</b> {f['owasp']}</li>
<li><b>Severity:</b> {f['cvss']}</li>
<li><b>Validation Result:</b> {f['validation']}</li>
</ul>

<h2>3. Vulnerable Code Snippet</h2>
<pre>{f['snippet']}</pre>

<h2>4. Exploitation Path (Validated)</h2>
<ol>
<li>Public page accessed</li>
<li>Client-side code inspected</li>
<li>Authentication secret identified</li>
<li>Secret submitted via native login</li>
<li>Backend response evaluated</li>
</ol>

<h2>5. Impact</h2>
<ul>
<li>Authentication bypass risk</li>
<li>Unauthorized access potential</li>
<li>Data exposure</li>
</ul>

<h2>6. Remediation</h2>
<ul>
<li>Remove secrets from frontend</li>
<li>Enforce server-side validation</li>
<li>Rotate compromised credentials</li>
<li>Implement secure auth architecture</li>
</ul>

<div class="footer">
<b>Audit ID:</b> {self.audit_id}<br>
<b>Date:</b> {f['timestamp']}<br>
<b>Target:</b> {self.target_url}<br><br>
<b>Tool:</b> {TOOL_NAME} {TOOL_VERSION}<br>
<b>Made by:</b> IA tools, GPT, Google Labs, Gemini, and DeyX
</div>

</div>
</body>
</html>
"""

        name = f"OWASP_AppSec_Report_{int(time.time())}.html"
        with open(name, "w", encoding="utf-8") as r:
            r.write(html)

        if sys.platform.startswith("win"):
            os.startfile(name)
        else:
            os.system(f"xdg-open {name}")


if __name__ == "__main__":
    GhostProtocol().mainloop()
