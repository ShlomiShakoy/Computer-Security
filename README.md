Communication_LTD Web Application
This project is a web-based management system for the fictional telecom company Communication_LTD, which offers internet packages and manages customer, product, and market sector data. The project includes a secure user management interface with registration, login, and password reset capabilities, and demonstrates security principles through two versions: a vulnerable and a secure version.

Project Requirements
Relational Database: Supports either SQL Express or MySQL for storing user and company data.
Web Interface: Developed using a framework of choice (e.g., Django, Java, or C#).
User Authentication and Security:
Registration: New user setup with strong passwords stored using HMAC + Salt, managed via a configuration file.
Forgot Password: Allows users to securely reset their password, ensuring compliance with password requirements.
Login: Validates user credentials and grants access to authorized users.
User Management: Enables creating and displaying customer data within the system.
Security Implementation (Part A)
Password Requirements: Password complexity enforced through configurable rules, stored securely.
Forgot Password Flow: Sends a SHA-1 generated token to users via email for password reset.
Flash Notifications: Displays confirmation messages upon successful customer entry.
Vulnerability Demonstration (Part B)
Stored XSS: Demonstrates an attack example on user-generated content.
SQL Injection: Examples and remediation steps applied to registration, login, and user management features.
Mitigation: The secure version uses character encoding for XSS prevention and parameterized queries or stored procedures for SQL injection defense.
Deployment
Two versions of the project are available:

Vulnerable Version: For educational purposes, demonstrating security weaknesses.
Secure Version: Implemented with proper defenses against XSS and SQL injection.
