# 🛡️ Website Watchdog – Defacement & Attack Monitor

A Python-based desktop application for continuous website monitoring and detection of suspicious changes, potential defacement, malicious code injection, phishing indicators, SSL certificate issues, unexpected redirects, and website availability problems.

Website Watchdog uses passive HTTP/HTTPS requests to inspect publicly accessible web pages and compares their current state against a previously recorded baseline. It provides a graphical dashboard, severity-based alerts, monitoring history, and HTML report generation.

## ✨ Features

### 1. Website Monitoring
- Monitor multiple websites continuously.
- Configure an individual monitoring interval for each website.
- Track HTTP response status and response time.
- Detect network errors and unreachable websites.
- Record website status and monitoring history.

### 2. Defacement Detection
Detects suspicious page content using predefined patterns, including:
- `hacked by`
- `owned by`
- `pwned by`
- `defaced by`
- Hacker group tags and suspicious injected headings.

### 3. Malicious Code and Phishing Indicators
Checks page content for predefined suspicious patterns associated with:
- Obfuscated JavaScript and encoded payloads.
- Cryptocurrency-mining scripts.
- Hidden iframes.
- Suspicious external scripts.
- Potential cross-site scripting (XSS) and SQL injection artifacts.
- PHP shell-command artifacts.
- Credential-harvesting and phishing messages.

### 4. Change Detection
Compares the current website state with its saved baseline to identify:
- SHA-256 content hash changes.
- Website title changes.
- HTTP status-code changes.
- Significant content-size deviations.
- Redirect destination changes.
- New external domains in page resources.
- SSL certificate expiry and fingerprint changes.
- Unusually slow response times.

### 5. Alert Management
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW, and informational status.
- In-application alert dashboard.
- Desktop alert bell.
- Search and filter alerts.
- Acknowledge individual alerts or all alerts.
- Optional SMTP email notifications.

### 6. Database and Reporting
- SQLite database for website records, baselines, alerts, checks, and settings.
- Monitoring history for each website.
- Export monitoring information as an HTML report.
- Generate a report containing site status, risk level, and recent alert history.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.9+ | Application development |
| Tkinter | Desktop graphical interface |
| SQLite | Local database and persistence |
| `urllib` | HTTP/HTTPS requests |
| `hashlib` | SHA-256 content hashing |
| `ssl` and `socket` | Certificate inspection |
| `re` | Pattern-based detection |
| `threading` | Background monitoring |
| `smtplib` | Optional email alerts |
| HTML/CSS | Monitoring report generation |

**Dependencies:** Python standard library only; no third-party Python packages are required by the supplied script.

## 📋 Requirements

- Python 3.9 or later.
- Windows, Linux, or macOS with a working Tkinter installation.
- Internet connectivity to access monitored websites.
- SMTP account and credentials if email notifications are required.

## 🚀 Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/website-watchdog.git
```

Replace `YOUR-USERNAME/website-watchdog` with your actual GitHub repository URL.

### Step 2: Open the project directory

```bash
cd website-watchdog
```

### Step 3: Verify Python

```bash
python --version
```

On some Linux systems, use:

```bash
python3 --version
```

### Step 4: Run the application

Save the Python source file as `website_watchdog.py`, then execute:

```bash
python website_watchdog.py
```

On Linux or macOS:

```bash
python3 website_watchdog.py
```

The Website Watchdog desktop dashboard should open.

## 🖥️ How to Use

### Step 1: Add a Website
1. Click **Add Site**.
2. Enter the website URL, such as `https://example.com`.
3. Provide a label for identification.
4. Set the monitoring interval in seconds.
5. Click **Add Site**.

The configured website is added to the monitoring list.

### Step 2: Establish the Baseline
During the initial successful check, the application records the website's baseline information, including its content hash, page title, HTTP status, content size, redirect destination, SSL details, and external domains.

Subsequent checks compare the current state against this baseline.

### Step 3: Review Alerts
Open the **Alerts** tab to review detected issues.

Use the filter field to search alerts and select **Unacknowledged only** to focus on alerts requiring review. Acknowledge alerts after investigation.

### Step 4: Review Monitoring History
Open the **History** tab and select a website to review previous checks, HTTP status codes, response times, and alert counts.

### Step 5: Reset a Baseline
Select a website and click **Reset Baseline** when an intentional website change means the previous baseline is no longer appropriate.

Reset baselines only after verifying that the current website state is trusted.

### Step 6: Export a Report
Click **Export Report**, select a destination, and save the generated HTML report. The report can be opened in a web browser for review or documentation.

## 📧 SMTP Email Configuration

1. Open **Settings** in the application.
2. Enter the SMTP server hostname.
3. Configure the SMTP port.
4. Enter the SMTP username and password.
5. Specify the recipient email address.
6. Save the settings.

Example configuration for a Gmail account:

| Setting | Example |
|---|---|
| SMTP Host | `smtp.gmail.com` |
| SMTP Port | `587` |
| SMTP Username | Your authorized email account |
| SMTP Password | App password, where supported |
| Alert Recipient | Your monitoring email address |

Use an authorized SMTP account and the provider's recommended authentication method. Do not commit passwords or other secrets to GitHub.

## 🧠 Detection Workflow

1. **Fetch:** Retrieve the publicly accessible website page.
2. **Extract:** Calculate the content hash and extract relevant page metadata.
3. **Analyze:** Check the page for suspicious patterns and compare it with the saved baseline.
4. **Classify:** Assign severity levels to detected findings.
5. **Store:** Record website status, check history, and alerts in SQLite.
6. **Notify:** Display alerts in the dashboard and send email notifications when configured.
7. **Report:** Export monitoring results as an HTML report.

## 📁 Project Structure

```text
website-watchdog/
├── website_watchdog.py    # Main application
├── watchdog.db            # Created automatically at runtime
├── README.md              # Project documentation
└── .gitignore             # Recommended Git exclusions
```

The database file is created when the application initializes. The Python source file and README are the main files required to get started.

## 🔐 Security and Limitations

- This application performs passive page retrieval and pattern-based inspection; it is not a complete vulnerability scanner or malware sandbox.
- A changed content hash does not necessarily mean a website has been compromised. Legitimate dynamic content can also trigger alerts.
- Detection relies on predefined patterns and can produce false positives or miss previously unknown threats.
- SSL inspection in the supplied implementation disables certificate verification for the page-fetching request. Therefore, that request does **not** provide reliable protection against invalid certificates or man-in-the-middle attacks. Certificate inspection is performed separately. Review and correct this behavior before using the tool for security-sensitive monitoring.
- The application does not automatically remove malicious content, block attackers, or remediate compromised websites.
- Monitoring intervals should be configured responsibly to avoid excessive requests.
- Monitor only websites you own or are explicitly authorized to monitor.
- Protect the local database and SMTP credentials. The application stores its settings in SQLite; do not publish the live database or secrets.

## 🔮 Future Enhancements

Potential improvements include:
- Verified TLS certificate handling and stronger certificate validation.
- Configurable detection rules and trusted-domain allowlists.
- More detailed alert evidence and incident timelines.
- JSON snapshot export.
- Improved baseline management and alert deduplication.
- Authentication and role-based access controls.
- Integration with SIEM platforms and centralized logging.
- Unit tests and automated security checks.

## 🎯 Use Cases

- Website integrity monitoring.
- Detection of potential website defacement.
- Identification of suspicious page modifications.
- Basic phishing and malicious-content indicators.
- SSL certificate expiry monitoring.
- Cybersecurity laboratory demonstrations and defensive security learning.

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Submit a pull request describing your improvements.

## 📄 License

Choose a suitable open-source license before distributing the project. If you select the MIT License, include a `LICENSE` file containing the appropriate license text.

## ⚠️ Disclaimer

Website Watchdog is intended for authorized defensive monitoring, educational use, and security research. Alerts indicate suspicious patterns or deviations and should be validated by a security analyst before concluding that a website has been compromised.

---

**Developed with Python for website integrity monitoring and defensive cybersecurity operations.**
