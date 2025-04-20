# Command Injection

| Technique | Description |
|---------- | ----------- |
| `Whitelist` | Very secure when properly implemented |
| `Regex Filtering` | Flexible pattern matching |
| `Shell Escaping` | Properly handles most cases |
| `Subprocess (shell=False)` | Avoids shell entirely |
| `Length Restriction` | Simple to implement |
| `Blacklist` | Easy to add new patterns |
| `Command Mapping` | Most secure approach |


## Test

### 1. Vulnerable Endpoint (/vulnerable/exec)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls -l"}' http://localhost:5000/vulnerable/exec
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls; whoami"}' http://localhost:5000/vulnerable/exec
```

### 2. Whitelist Validation (/secure/whitelist)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls"}' http://localhost:5000/secure/whitelist
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls /etc"}' http://localhost:5000/secure/whitelist
```

### 3. Regex Filter (/secure/regex_filter)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"echo hello"}' http://localhost:5000/secure/regex_filter
curl -X POST -H "Content-Type: application/json" -d '{"command":"echo hello; whoami"}' http://localhost:5000/secure/regex_filter
```

### 4. Shell Escaping (/secure/escape_shell)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"echo test"}' http://localhost:5000/secure/escape_shell
curl -X POST -H "Content-Type: application/json" -d '{"command":"echo test; ls"}' http://localhost:5000/secure/escape_shell
```

### 5. Subprocess Safe (/secure/subprocess_safe)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls -l"}' http://localhost:5000/secure/subprocess_safe
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls && whoami"}' http://localhost:5000/secure/subprocess_safe
```

### 6. Length Restriction (/secure/length_restriction)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"whoami"}' http://localhost:5000/secure/length_restriction
curl -X POST -H "Content-Type: application/json" -d '{"command":"cat /etc/passwd"}' http://localhost:5000/secure/length_restriction
```

### 7. Blacklist Keywords (/secure/blacklist_keywords)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command":"ls -l"}' http://localhost:5000/secure/blacklist_keywords
curl -X POST -H "Content-Type: application/json" -d '{"command":"rm /tmp/test"}' http://localhost:5000/secure/blacklist_keywords
```

### 8. Command Mapping (/secure/command_mapping)

```html
curl -X POST -H "Content-Type: application/json" -d '{"command_type":"ls"}' http://localhost:5000/secure/command_mapping
curl -X POST -H "Content-Type: application/json" -d '{"command_type":"ping", "args":"localhost"}' http://localhost:5000/secure/command_mapping
curl -X POST -H "Content-Type: application/json" -d '{"command_type":"cat", "args":"/etc/passwd"}' http://localhost:5000/secure/command_mapping
```