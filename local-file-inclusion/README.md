# Local File Inclusion (LFI)

| Method | Description |
|----------| ------------|
| `/vulnerable` | No protection at all |
| `/allowlist` | Only allow files from predefined whitelist |
| `/extension_check` | Only allow specific file extensions |
| `/path_traversal_block` | Block path traversal attempts |
| `/absolute_path_required` | Require files in allowed directories |
| `/path_normalization` | Normalize path and check allowed directory |
| `/blacklist` | Block known dangerous patterns |
| `/regex_validation` | Validate filename with strict regex |
| `/mime_check` | Check file MIME type before serving |
| `/symlink_check` | Check for symlinks outside allowed dirs |
| `/file_size_limit` | Enforce maximum file size (1MB) |
| `/read_limit` | Basic implementation of read limit |

## Test

```html
http://127.0.0.1:5000/vulnerable/lfi?file=Makefile
http://localhost:5000/protected/lfi?file=allowed_files/data.csv&method=allowlist
```