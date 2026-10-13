# Password generation

[Documentation](../README.md) › [Security](README.md)

Users can generate their own bcrypt hash and provide it to an admin. The admin never sees the plaintext password.

Admins can print these same client-side commands on demand with:
```bash
tacctl hash commands
```

**On the server (if available):**
```bash
tacctl hash generate
```

**Linux / macOS:**
```bash
python3 -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
```

**Windows (Python):**
```powershell
python -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
```

**Windows (PowerShell, no Python):**
```powershell
Install-Module -Name BcryptNet -Scope CurrentUser
[BCrypt.Net.BCrypt]::HashPassword((Read-Host -AsSecureString "Password" | ConvertFrom-SecureString -AsPlainText))
```

**Admin adds with pre-generated hash:**
```bash
tacctl user add jsmith superuser --hash '$2b$12$...'
```

**Admin rotates an existing user's password with a pre-generated hash:**
```bash
tacctl user passwd jsmith --hash '$2b$12$...'
```

The same hash serves TACACS+ and RADIUS.
