Communication_LTD Web Application

This web-based management system for the fictional telecom company Communication_LTD manages customer, product, and market sector data. The project includes two versions, demonstrating security principles with both a vulnerable and a secure codebase.

Overview
Database: Supports SQL Express or MySQL.
Web Interface: Developed using Django, Java, or C#.
Key Features
User Management:
Registration: Secure new user setup with HMAC + Salt password storage.
Login: Credential validation with access control.
Forgot Password: Secure reset flow using a SHA-1 token via email.
Customer Data Management: Enables adding and viewing customer info.
Security Highlights
Password Policy: Configurable rules for password complexity.
Flash Notifications: Displays confirmation messages for actions.
XSS and SQL Injection Vulnerabilities: Demonstrated in a vulnerable version with remediation in the secure version.
Two versions are available:

Vulnerable Version: For learning about security weaknesses.
Secure Version: With defenses against XSS and SQL injection.
