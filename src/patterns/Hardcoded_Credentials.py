# Patterns for Hardcoded Credentials (expanded and well-commented)
hardcoded_credentials_patterns = [
    r'(?i)(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # Generic hardcoded secrets
    r'(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+', # Basic Auth header
    r'(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9._~+/=-]+', # Bearer Auth header
    r'(?i)(?:access_key|access_token|secret_key|api_key|apikey)\s*[=:]\s*[\'\"][^\'\"]{8,}[\'\"]', # Hardcoded API/secret keys
    r'(?i)const\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # JS const secret
    r'(?i)var\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # JS var secret
    r'(?i)let\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # JS let secret
    r'(?i)private\s+(?:final\s+)?String\s+(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # Java private String secret
    r'(?i)env\.(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # env. secret
    r'(?i)config\.(?:password|passwd|pwd|token|secret|api_key|apikey)\s*=\s*[\'\"][^\'\"]+[\'\"]', # config. secret
    r'(?i)useradd\s+-p\s+[\'\"][^\'\"]+[\'\"]', # useradd with password
    r'(?i)echo\s+[\'\"][^\'\"]+[\'\"]\s*\|\s*passwd', # echo password to passwd
    r'(?i)aws_access_key_id\s*=\s*[A-Z0-9]{20}', # AWS access key
    r'(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}', # AWS secret key
    r'(?i)sshpass\s+-p\s+[\'\"][^\'\"]+[\'\"]', # sshpass with password
    r'(?i)PGPASSWORD=\S+', # PGPASSWORD env var
    r'(?i)mongodb://[^:]+:[^@]+@', # MongoDB URI with creds
    r'(?i)mysql://[^:]+:[^@]+@', # MySQL URI with creds
    r'(?i)postgres://[^:]+:[^@]+@', # Postgres URI with creds
    r'(?i)redis://[^:]+:[^@]+@', # Redis URI with creds
    r'(?i)amqp://[^:]+:[^@]+@', # AMQP URI with creds
    r'(?i)ftp://[^:]+:[^@]+@', # FTP URI with creds
    r'(?i)smtp://[^:]+:[^@]+@', # SMTP URI with creds
    r'(?i)git://[^:]+:[^@]+@', # Git URI with creds
    r'(?i)http[s]?://[^:]+:[^@]+@', # HTTP URI with creds
    r'(?i)"auth"\s*:\s*"[^"]+"', # JSON auth field
    r'(?i)"password"\s*:\s*"[^"]+"', # JSON password field
    r'(?i)"token"\s*:\s*"[^"]+"', # JSON token field
    r'(?i)"secret"\s*:\s*"[^"]+"', # JSON secret field
    r'(?i)"api_key"\s*:\s*"[^"]+"', # JSON api_key field
    r'(?i)"apikey"\s*:\s*"[^"]+"', # JSON apikey field
    r'(?i)\.env', # .env file
    r'(?i)AWS_ACCESS_KEY_ID\s*=\s*[A-Z0-9]{20}', # AWS_ACCESS_KEY_ID env
    r'(?i)AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]{40}', # AWS_SECRET_ACCESS_KEY env
]
