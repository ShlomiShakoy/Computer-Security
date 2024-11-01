# Communication_LTD Web Application

This project is a web-based management system for the fictional telecom company Communication_LTD, designed to manage customer, product, and market sector data. The project integrates cybersecurity concepts learned in the cyber course, along with programming principles, to develop a secure, relational database-backed system. Two versions of the project demonstrate security practices, showcasing both a vulnerable and a secure version.

## Overview
- **Database**: Supports MySQL.
- **Web Interface**: Developed using Python.

### Key Features
- **User Management**:
  - **Registration**: Secure user setup with HMAC + Salt password storage.
  - **Login**: Credential validation and access control.
  - **Forgot Password**: Secure reset flow using a SHA-1 token sent to users by email.
  - **Customer Data Management**: Enables adding and viewing customer information.

### Security Highlights
- **Password Policy**: Configurable complexity rules for password enforcement.
- **Flash Notifications**: Provides real-time confirmation messages.
- **XSS and SQL Injection Demonstrations**: Vulnerable version highlights security flaws with secure version showcasing proper defenses.

Two versions are available:
- **Vulnerable Version**: Illustrates common security weaknesses.
- **Secure Version**: Implements defenses against XSS and SQL injection.
