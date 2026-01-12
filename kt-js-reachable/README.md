# Vulnerable Test Application

This is a deliberately vulnerable npm project created for testing security scanning tools, dependency checkers, and vulnerability detection systems.

## ⚠️ WARNING
**DO NOT use this in production or deploy it publicly.** This application contains known security vulnerabilities and is intended for testing purposes only.

## Vulnerabilities Included

### 1. **Lodash 4.17.19** - Prototype Pollution
- **CVE-2019-10744**
- The `_.merge()` function is vulnerable to prototype pollution
- Exploited in `app.js` to demonstrate pollution of Object prototype

### 2. **Minimist 1.2.5** - Prototype Pollution
- **CVE-2020-7598**
- Command-line argument parsing can pollute Object prototype
- Demonstrated with `__proto__` injection

### 3. **Axios 0.21.1** - SSRF and other vulnerabilities
- **CVE-2021-3749** (Server-Side Request Forgery)
- Used for HTTP requests with known vulnerabilities

### 4. **Node-serialize 0.0.4** - Remote Code Execution
- **CVE-2017-5941**
- Unsafe deserialization can lead to arbitrary code execution
- Demonstrated with serialized function execution

### 5. **Marked 0.3.19** - XSS Vulnerability
- **CVE-2022-21680**, **CVE-2022-21681**
- Cross-site scripting (XSS) vulnerability
- Markdown parsing with insufficient sanitization

### 6. **Express 4.17.1** - Multiple vulnerabilities
- Open redirect vulnerability in `/redirect` endpoint
- XSS vulnerability in `/greet` endpoint
- Missing security headers

### 7. **jsonwebtoken 8.5.1** - Algorithm Confusion
- **CVE-2022-23529**
- Vulnerable to algorithm confusion attacks
- Improper JWT verification

### 8. **xmldom 0.5.0** - XXE and Prototype Pollution
- **CVE-2021-21366**, **CVE-2021-32796**
- XML External Entity (XXE) injection vulnerability
- Prototype pollution vulnerability

## Installation

```bash
npm install
```

## Running the Application

```bash
npm start
```

The server will start on `http://localhost:3000`

## Testing Endpoints

- `http://localhost:3000/` - Main page
- `http://localhost:3000/redirect?url=http://evil.com` - Open redirect vulnerability
- `http://localhost:3000/greet?name=<script>alert('XSS')</script>` - XSS vulnerability

## Use Cases

This project can be used to test:
- Dependency vulnerability scanners (npm audit, Snyk, etc.)
- Static Application Security Testing (SAST) tools
- Software Composition Analysis (SCA) tools
- Security training and education
- CI/CD security pipeline validation

## Detecting Vulnerabilities

Run these commands to detect the vulnerabilities:

```bash
# npm's built-in audit
npm audit

# Check for outdated packages
npm outdated
```

## License

ISC - For testing purposes only
