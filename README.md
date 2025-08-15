<div align="center">
  
# 📧 Professional SMTP Server

![SMTP Server Banner](https://img.shields.io/badge/SMTP-Server-blue?style=for-the-badge&logo=gmail&logoColor=white)

### 🚀 A Full-Featured SMTP Server with Web Dashboard

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/navaranjithsai/SMTP_Client?style=flat-square)](https://github.com/yourusername/smtp-server/stargazers)
[![Issues](https://img.shields.io/github/issues/navaranjithsai/SMTP_Client?style=flat-square)](https://github.com/yourusername/smtp-server/issues)
[![Contributors](https://img.shields.io/github/contributors/navaranjithsai/SMTP_Client?style=flat-square)](https://github.com/yourusername/smtp-server/graphs/contributors)

<p align="center">
  <strong>Build your own SMTP server with authentication, SSL/TLS support, and a beautiful web dashboard!</strong>
</p>

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Contributing](#-contributing)

<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" width="100%">

</div>


## 🌟 Features

<table>
<tr>
<td width="33%">

### 📮 Core SMTP
- ✅ Full SMTP Protocol Support
- ✅ ESMTP Extensions
- ✅ Email Queuing System
- ✅ Multi-domain Support
- ✅ Email Relay Capabilities

</td>
<td width="33%">

### 🔐 Security
- ✅ User Authentication (PLAIN/LOGIN)
- ✅ SSL/TLS Encryption
- ✅ STARTTLS Support
- ✅ Anti-relay Protection
- ✅ Certificate Management

</td>
<td width="33%">

### 📊 Dashboard
- ✅ Real-time Monitoring
- ✅ Email Statistics
- ✅ Error Tracking
- ✅ User Management
- ✅ DNS Verification Tools

</td>
</tr>
</table>

## 🚀 Quick Start

### Prerequisites

<div align="center">

| Requirement | Version |
|------------|---------|
| Python | 3.8+ |
| pip | Latest |
| OS | Windows/Linux/macOS |

</div>

### 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/navaranjithsai/SMTP_Client.git
   cd SMTP_Client

## 🎯 Usage
🔧 Basic Configuration
<details> <summary><b>1. Starting the Server</b></summary>
Open the web dashboard at http://localhost:5000
Click the power button to start the SMTP server
The server will start on port 2525 by default
</details><details> <summary><b>2. Adding a Domain</b></summary>
Navigate to the Domains tab
Click Add Domain
Enter your domain name
Configure DNS records as shown in the dashboard
</details><details> <summary><b>3. Creating Users</b></summary>
Go to the Users tab
Click Add User
Enter username and password
Set email quota (optional)
</details>

## 🤝 Contributing
We love contributions! Please see our Contributing Guidelines for details.

How to Contribute
🍴 Fork the repository
🌿 Create a feature branch

   ```bash
   git checkout -b feature/AmazingFeature
```
💻 Make your changes
✅ Commit your changes
 ```Bash
  git commit -m 'Add some AmazingFeature'
```
📤 Push to the branch
```Bash
git push origin feature/AmazingFeature
```
🎉 Open a Pull Request
<br>
### 🎯 Areas for Contribution

We're looking for help in these areas:

- 🔐 **Security Enhancements**: Implement DKIM, SPF validation
- 🎨 **UI/UX Improvements**: Enhance dashboard design
- 📱 **Mobile Responsiveness**: Improve mobile experience
- 🌍 **Internationalization**: Add language support
- 📚 **Documentation**: Improve guides and tutorials
- 🧪 **Testing**: Add unit and integration tests
- 🔧 **Features**: Add new functionality
- 🐛 **Bug Fixes**: Help squash bugs

API Endpoints
<details> <summary><b>Server Control</b></summary>

  ```http

POST /api/toggle
Content-Type: application/json

{
  "action": "start" | "stop"
}
```
</details><details> <summary><b>User Management</b></summary>

  ```http

GET /api/users
POST /api/users
DELETE /api/users

# Create user
{
  "username": "john",
  "password": "secure_password",
  "quota": "unlimited"
}
```
</details><details> <summary><b>Domain Management</b></summary>

  ```http

GET /api/domains
POST /api/domains
DELETE /api/domains

# Add domain
{
  "domain": "example.com"
}
```
</details>
## 🐛 Troubleshooting

<details>
<summary><b>Port Already in Use</b></summary>

Change the port in Settings or kill the process using the port:
```bash
# Windows
netstat -ano | findstr :2525
taskkill /PID <PID> /F

# Linux/Mac
lsof -i :2525
kill -9 <PID>
```

</details>

<details>
<summary><b>Permission Denied</b></summary>

- Run as administrator (Windows)
- Use sudo (Linux/Mac)
- Use ports above 1024

</details>

<details>
<summary><b>SSL/TLS Issues</b></summary>

Generate new certificates:
1. Go to Certificates tab
2. Click Generate Certificate
3. Restart the server

</details>
📊 Project Stats
<div align="center">
  
![Code Size](https://img.shields.io/github/languages/code-size/navaranjithsai/SMTP_Client?style=flat-square)
![Lines of Code](https://img.shields.io/tokei/lines/github/navaranjithsai/SMTP_Client?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/navaranjithsai/SMTP_Client?style=flat-square)
![Open Issues](https://img.shields.io/github/issues-raw/navaranjithsai/SMTP_Client?style=flat-square)
![Closed Issues](https://img.shields.io/github/issues-closed-raw/navaranjithsai/SMTP_Client?style=flat-square)

</div>

## 🌟 Star History


<div align="center">
  <a href="https://star-history.com/#navaranjithsai/SMTP_Client&Date">
    <img src="https://api.star-history.com/svg?repos=navaranjithsai/SMTP_Client&type=Date" alt="Star History Chart">
  </a>
</div>

## 👥 Contributors

Thanks to these wonderful people who have contributed to this project:

<a href="https://github.com/navaranjithsai/SMTP_Client/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=navaranjithsai/SMTP_Client" />
</a>
