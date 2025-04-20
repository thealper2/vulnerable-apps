# Insecure File Upload

| Endpoint | Description |
| -------- | ----------- |
| `/upload-insecure` | Accepts any file without validation |
| `/upload-secure/mime-type` | Checks the Content-Type header and actual file content |
| `/upload-secure/extension` | Only allows specific file extensions |
| `/upload-secure/magic-number` | Verifies file signatures match expected types | 
| `/upload-secure/size-limit` | Enforces maximum file size (2MB) |
| `/upload-secure/random-filename` | Uses UUIDs for stored filenames |
| `/upload-secure/malware-scan` | Basic content scanning for malicious patterns |
| `/upload-secure/sanitize-filename` | Prevents path traversal and special characters |
| `/upload-secure/multipart-validation` | Ensures proper request formatting |

## Test

### Insecure File Upload (No Validation)

```bash
# Upload any file without validation
curl -X POST \
  http://localhost:5000/upload-insecure \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/any/file.exe'
```

### MIME Type Validation

```bash
# Upload with MIME type validation (only allowed types)
curl -X POST \
  http://localhost:5000/upload-secure/mime-type \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/image.jpg;type=image/jpeg'
```

### File Extension Validation

```bash
# Upload with extension validation (.jpg, .png, etc.)
curl -X POST \
  http://localhost:5000/upload-secure/extension \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/document.pdf'
```

### Magic Number Validation

```bash
# Upload with magic number validation (actual file content)
curl -X POST \
  http://localhost:5000/upload-secure/magic-number \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/real.png;type=image/png'
```

### Size Limit Validation

```bash
# Upload with size limit (max 2MB)
curl -X POST \
  http://localhost:5000/upload-secure/size-limit \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/small-image.jpg'
```

### Random Filename Generation

```bash
# Upload with randomized filename
curl -X POST \
  http://localhost:5000/upload-secure/random-filename \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/profile.jpg'
```

### Malware Scanning

```bash
# Upload with basic malware scanning
curl -X POST \
  http://localhost:5000/upload-secure/malware-scan \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/clean-file.txt'
```

### Filename Sanitization

```bash
# Upload with filename sanitization (try malicious filename)
curl -X POST \
  http://localhost:5000/upload-secure/sanitize-filename \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/clean-file.txt;filename=../../malicious.php'
```

### Multipart Validation

```bash
# Upload with multipart validation
curl -X POST \
  http://localhost:5000/upload-secure/multipart-validation \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@/path/to/normal-file.png'
```