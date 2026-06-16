# .NET 2FA Email OTP Service

A robust, high-performance .NET Minimal API designed for Two-Factor Authentication (2FA). This service handles secure OTP generation, database-level restriction tracking, and secure cryptographic validation.

## 🚀 Key Features
- **Secure Architecture:** Implements SHA-256 cryptographic hashing for OTP tokens in production.
- **Race-Condition Prevention:** Utilizes SQL Server transaction locks (`WITH (UPDLOCK, HOLDLOCK)`) during validation pipelines.
- **Anti-Spam Control:** Implements a 1-minute database cooldown constraint per email address.
- **Clean Infrastructure:** Built using Dapper ORM for micro-optimization and raw SQL control.
- **Adaptive Notifications:** Integrated with SMTP using custom responsive HTML email templates.

## 🛠️ Tech Stack
- **Framework:** .NET Web API (Minimal APIs)
- **Database:** Microsoft SQL Server
- **Data Access:** Dapper ORM
- **Network Protocol:** SMTP Client with STARTTLS (Port 587)
