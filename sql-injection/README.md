## SQL Injection

### 1. Vulnerable Endpoints

#### 1.1 String Formatting Vulnerability

```bash
# Normal request
curl -X POST http://localhost:5000/insecure/login_string_format \
-H "Content-Type: application/json" \
-d '{"username":"admin", "password":"Admin@123"}'

# SQL Injection attack (always logs in as admin)
curl -X POST http://localhost:5000/insecure/login_string_format \
-H "Content-Type: application/json" \
-d '{"username":"admin'\'' --", "password":"anything"}'
```

#### 1.2 String Concatenation Vulnerability

```bash
# Normal request
curl -X POST http://localhost:5000/insecure/login_sqlite_concatenate \
-H "Content-Type: application/json" \
-d '{"username":"alice", "password":"Alice@123"}'

# SQL Injection attack
curl -X POST http://localhost:5000/insecure/login_sqlite_concatenate \
-H "Content-Type: application/json" \
-d '{"username":"'\'' OR 1=1 --", "password":""}'
```

### 2. Protected Endpoints

#### 2.1 Parameterized Queries

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_parameterized \
-H "Content-Type: application/json" \
-d '{"username":"bob", "password":"Bob@123"}'

# SQL Injection attempt (will fail)
curl -X POST http://localhost:5000/secure/login_parameterized \
-H "Content-Type: application/json" \
-d '{"username":"bob'\'' --", "password":""}'
```

#### 2.2 ORM Protection (SQLAlchemy)

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_orm \
-H "Content-Type: application/json" \
-d '{"username":"testuser", "password":"Test@123"}'

# Malformed input
curl -X POST http://localhost:5000/secure/login_orm \
-H "Content-Type: application/json" \
-d '{"username":"testuser; DROP TABLE users; --", "password":"Test@123"}'
```

#### 2.3 Query Builder (Peewee)

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_peewee \
-H "Content-Type: application/json" \
-d '{"username":"admin", "password":"Admin@123"}'

# Injection attempt
curl -X POST http://localhost:5000/secure/login_peewee \
-H "Content-Type: application/json" \
-d '{"username":"admin'\'' OR '\''1'\''=\''1", "password":"anything"}'
```

#### 2.4 Input Validation

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_input_validation \
-H "Content-Type: application/json" \
-d '{"username":"alice", "password":"Alice@123"}'

# Invalid characters (will be rejected)
curl -X POST http://localhost:5000/secure/login_input_validation \
-H "Content-Type: application/json" \
-d '{"username":"alice;", "password":"Alice@123"}'
```

#### 2.5 Stored Procedure (Conceptual)

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_stored_procedure \
-H "Content-Type: application/json" \
-d '{"username":"bob", "password":"Bob@123"}'
```

#### 2.6 Read-Only DB User

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_readonly_user \
-H "Content-Type: application/json" \
-d '{"username":"testuser", "password":"Test@123"}'
```

#### 2.7 Combined Protections

```bash
# Normal request
curl -X POST http://localhost:5000/secure/login_combined \
-H "Content-Type: application/json" \
-d '{"username":"admin", "password":"Admin@123"}'

# Complex attack attempt (will be blocked by WAF)
curl -X POST http://localhost:5000/secure/login_combined \
-H "Content-Type: application/json" \
-d '{"username":"admin'\'' UNION SELECT * FROM users --", "password":""}'
```

### 3. Other Utility Endpoints

#### 3.1 Root Endpoint

```bash
curl http://localhost:5000/
```

### Test Scenarios

#### 1. Successful Login

```bash
curl -X POST http://localhost:5000/secure/login_parameterized \
-H "Content-Type: application/json" \
-d '{"username":"admin", "password":"Admin@123"}'
```

#### 2. Failed Login Attempt

```bash
curl -X POST http://localhost:5000/secure/login_parameterized \
-H "Content-Type: application/json" \
-d '{"username":"admin", "password":"wrongpassword"}'
```

#### 3. SQL Injection

```bash
# Classic ' OR 1=1 -- attack
curl -X POST http://localhost:5000/insecure/login_string_format \
-H "Content-Type: application/json" \
-d '{"username":"'\'' OR 1=1 --", "password":""}'

# UNION SELECT attack
curl -X POST http://localhost:5000/insecure/login_string_format \
-H "Content-Type: application/json" \
-d '{"username":"'\'' UNION SELECT 1, '\''hacker'\'', '\''hacker@example.com'\'', '\''pass'\'' --", "password":""}'
```

#### 4. WAF

```bash
curl -X POST http://localhost:5000/secure/login_combined \
-H "Content-Type: application/json" \
-d '{"username":"SELECT * FROM users", "password":"test"}'
```