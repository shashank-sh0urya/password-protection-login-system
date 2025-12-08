**🔐 Secure Login System in C (with MFA)**

A secure HTTP-based login system written in C that implements strong password policies, salted password hashing, and multi-factor authentication (OTP).
This project is built using libmicrohttpd and tested using Postman.

**🚀 Features**

✅ User Registration API

✅ Secure Password Storage (Salt + SHA-256 Hashing)

✅ Strong Password Policy Enforcement

✅ Login Authentication API

✅ One Time Password (OTP) Based Multi-Factor Authentication

✅ Clean JSON API Responses

✅ Compatible with Postman

**🛠️ Technologies Used**

Language: C

HTTP Server: libmicrohttpd

Cryptography: OpenSSL (SHA-256)

Testing Tool: Postman

**⚙️ Installation**
1. Install Dependencies (Linux)
sudo apt update
sudo apt install libmicrohttpd-dev libssl-dev

2. Clone the Repository
git clone https://github.com/your-username/secure-login-system-c.git
cd secure-login-system-c

3. Compile the Server
gcc secure_server.c -o secure_server -lmicrohttpd -lssl -lcrypto

▶️ Running the Server
./secure_server


Server will start at:

http://localhost:8080

**🔐 Password Policy**

Passwords must include:

✅ Minimum 12 characters
✅ At least 1 uppercase letter
✅ At least 1 lowercase letter
✅ At least 1 number
✅ At least 1 special character

**⚠️ Security Disclaimer**

This project is designed for educational purposes only.
OTP is returned in API response and credentials are stored in memory, not in a production-safe database.

**For real-world applications:**

Use a database

Use HTTPS

Use real SMS/Email OTP delivery

Future Enhancements

Token-based authentication (JWT)

SQLite/MySQL database support

Real email/SMS OTP delivery

Rate limiting and brute-force protection

**👨‍💻 Author**

Shashank BC
Cybersecurity Enthusiast & Developer
