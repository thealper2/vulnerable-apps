# Insecure Direct Object Reference (IDOR)

| Technique | Description |
|---------- | ----------- |
| `Direct Authorization Check` | Verifies user has explicit rights to the requested resource |
| `ID Obfuscation` | Uses encoded/transformed IDs to prevent enumeration |
| `Query Constraint Filtering` | Only searches within user-accessible resources |
| `Session-Based Access` | Maintains access list in user session |
| `Access Control List (ACL)` | Explicit permissions list for each resource |
| `Token-Based Access` | Requires unique per-resource access token |
| `Attribute-Based Access Control (ABAC)` | Complex rules based on multiple attributes |


## Test

### 1. Vulnerable Endpoint

```html
# Alice accessing her own document (should work)
curl -u alice:alice123 http://localhost:8000/vulnerable/document/1

# Alice trying to access Bob's document (IDOR vulnerability - works when it shouldn't)
curl -u alice:alice123 http://localhost:8000/vulnerable/document/2
```

### 2. Direct Authorization Check

```html
# Alice accessing her own document (should work)
curl -u alice:alice123 http://localhost:8000/secure/direct-auth/document/1

# Alice trying to access Bob's document (should fail with 403)
curl -u alice:alice123 http://localhost:8000/secure/direct-auth/document/2
```

### 3. ID Obfuscation

```html
# Alice accessing her own document with obfuscated ID
curl -u alice:alice123 http://localhost:8000/secure/obfuscation/document/MQ==

# Trying to guess another document (will fail)
curl -u alice:alice123 http://localhost:8000/secure/obfuscation/document/Mg==
```

### 4. Resource Ownership Filtering

```html
# Alice accessing her document (in her allowed list)
curl -u alice:alice123 http://localhost:8000/secure/query-filter/document/1

# Alice trying to access document not in her list (fails)
curl -u alice:alice123 http://localhost:8000/secure/query-filter/document/2
```

### 5. Session-Based Access

```html
# Alice accessing her document (in session list)
curl -u alice:alice123 http://localhost:8000/secure/session-based/document/1

# Alice trying to access document not in session list (fails)
curl -u alice:alice123 http://localhost:8000/secure/session-based/document/2
```

### 6. Access Control List (ACL)

```html
# Alice accessing her own document
curl -u alice:alice123 http://localhost:8000/secure/acl/document/1

# Alice trying to access Bob's document (fails)
curl -u alice:alice123 http://localhost:8000/secure/acl/document/2

# Admin accessing shared document (works as admin is in shared_with)
curl -u admin:admin123 http://localhost:8000/secure/acl/document/1
```

### 7. Token-Based Access

```html
# Alice generates token for her document
curl -u alice:alice123 -X POST http://localhost:8000/secure/token-based/document/1/generate-token

# Successful access with valid token
curl -u alice:alice123 "http://localhost:8000/secure/token-based/document/1?access_token=a1b2c3..."

# Failed access without token
curl -u alice:alice123 http://localhost:8000/secure/token-based/document/1

# Failed access with wrong token
curl -u alice:alice123 "http://localhost:8000/secure/token-based/document/1?access_token=wrongtoken"
```

### 8. Attribute-Based Access Control (ABAC)

```html
# Alice accessing her non-confidential document
curl -u alice:alice123 http://localhost:8000/secure/abac/document/1

# Admin accessing confidential document (fails unless owner)
curl -u admin:admin123 http://localhost:8000/secure/abac/document/4

# Admin accessing non-confidential document (works)
curl -u admin:admin123 http://localhost:8000/secure/abac/document/2
```