# 🛡️ OWASP Top 10 Attack Detection and Risk Assessment through Splunk Log Analysis

## 📘 Overview

This project focuses on detecting and assessing OWASP Top 10 web application vulnerabilities by analyzing log data using **Splunk**.
It demonstrates how real-time log monitoring can identify security threats such as brute-force attacks, SQL injections, XSS attempts, and sensitive data exposure through automated **SPL (Search Processing Language)** queries and dashboards.

---

## 🎯 Objectives

* Detect and analyze security attacks using **Splunk log data**.
* Map detected threats to **OWASP Top 10** and **MITRE ATT&CK** frameworks.
* Evaluate overall system risk and recommend **preventive, detection, and response** measures.
* Build real-time **Splunk dashboards** for visualization and alerting.

---

## 🧠 Scope of Analysis

| Component        | Description                                                                             |
| ---------------- | --------------------------------------------------------------------------------------- |
| **Time Range**   | Last 24 hours of collected logs                                                         |
| **Index Used**   | `practice`                                                                              |
| **Source Types** | `linux_secure (auth.log)`, `access_combined (apache_access.log)`, `_json (webapp.json)` |

---

## 🔍 Log Sources & Key Findings

### 1️⃣ Authentication Logs (`auth.log`)

| Attack Type                        | Description                        | OWASP Mapping                                  | MITRE ATT&CK              | Severity       |
| ---------------------------------- | ---------------------------------- | ---------------------------------------------- | ------------------------- | -------------- |
| **Brute-Force Attack**             | Multiple failed SSH login attempts | A07 – Identification & Authentication Failures | T1110 – Brute Force       | 🔴 High        |
| **Username Enumeration**           | Invalid user probing attempts      | A07 – Auth Failures                            | T1087 – Account Discovery | 🟠 Medium–High |
| **Credential Stuffing**            | Use of breached credentials        | A07 – Auth Failures                            | T1110.004                 | 🔴 High        |
| **Successful Unauthorized Access** | Valid but unauthorized logins      | A07 – Auth Failures                            | T1078 – Valid Accounts    | 🔴 Critical    |

---

### 2️⃣ Web Server Logs (`apache_access.log`)

| Attack Type                              | Description                               | OWASP Mapping                   | Severity       |
| ---------------------------------------- | ----------------------------------------- | ------------------------------- | -------------- |
| **SQL Injection (SQLi)**                 | Database manipulation via malicious input | A03 – Injection                 | 🔴 High        |
| **Cross-Site Scripting (XSS)**           | Script injection attempts                 | A07 – XSS                       | 🟠 Medium–High |
| **Path Traversal / LFI/RFI**             | Accessing restricted files                | A05 – Broken Access Control     | 🔴 High        |
| **Sensitive Data Exposure**              | Secrets/tokens in URLs                    | A02 – Sensitive Data Exposure   | 🔴 High        |
| **Security Misconfiguration (Scanners)** | Automated vulnerability scans             | A05 – Security Misconfiguration | 🟡 Medium      |

---

### 3️⃣ Application Logs (`webapp.json`)

| Attack Type                                     | Description                                    | OWASP Mapping | Severity  |
| ----------------------------------------------- | ---------------------------------------------- | ------------- | --------- |
| **Unhandled Exceptions (500)**                  | Backend failures exposing stack traces         | A06, A09      | 🔴 High   |
| **Unauthorized / Forbidden Access (401/403)**   | Invalid login or privilege escalation attempts | A02, A05      | 🟠 Medium |
| **Attack Attempts (SQLi, XSS, Path Traversal)** | Multiple malicious payloads targeting APIs     | A01, A03, A07 | 🔴 High   |

---

## 📊 Splunk Dashboard Highlights

* 🔐 **Authentication Monitoring** – Detect brute-force and credential stuffing attempts.
* 🌐 **Web Attack Detection** – Identify SQLi, XSS, and LFI payloads.
* 🧱 **Application Behavior Analysis** – Visualize 500/401/403 trends and attack endpoints.
* ⚙️ **Risk Assessment View** – Consolidated dashboard to show overall system risk level.

---

## 🧩 Tools & Technologies

* **Splunk Enterprise** (for log analysis and dashboard visualization)
* **SPL (Search Processing Language)**
* **OWASP Top 10 Framework**
* **MITRE ATT&CK Framework**
* **Linux auth logs, Apache access logs, Application JSON logs**

---

## ⚠️ Risk Assessment Summary

* **Overall Risk Level:** **HIGH**

  * Multiple exploitation attempts detected (SQLi, XSS, Path Traversal).
  * Several brute-force and credential stuffing attempts.
  * Unauthorized access and system misconfigurations observed.

---

## 🛠️ Recommendations

* Enable **Multi-Factor Authentication (MFA)**.
* Implement **rate limiting** and **lockout policies**.
* Enforce **input validation** and **parameterized queries**.
* Configure **Web Application Firewall (WAF)** rules.
* Sanitize logs and remove sensitive information.
* Regularly patch systems and update dependencies.

---


