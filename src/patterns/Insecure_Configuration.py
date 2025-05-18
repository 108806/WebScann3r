# Patterns for Insecure Configuration (expanded and well-commented)
insecure_config_patterns = [
    r'(?i)allow_url_include\s*=\s*On', # PHP allow_url_include On
    r'(?i)allow_url_fopen\s*=\s*On', # PHP allow_url_fopen On
    r'(?i)display_errors\s*=\s*On', # PHP display_errors On
    r'(?i)expose_php\s*=\s*On', # PHP expose_php On
    r'(?i)disable_functions\s*=\s*', # PHP disable_functions
    r'(?i)safe_mode\s*=\s*Off', # PHP safe_mode Off
    r'(?i)X-XSS-Protection:\s*0', # X-XSS-Protection disabled
    r'(?i)Access-Control-Allow-Origin:\s*\*', # CORS allow all
    r'(?i)helmet.noCache\(\s*false\s*\)', # helmet.noCache false
    r'(?i)helmet.noSniff\(\s*false\s*\)', # helmet.noSniff false
    r'(?i)helmet.xssFilter\(\s*false\s*\)', # helmet.xssFilter false
    r'(?i)secureConnection\s*=\s*false', # secureConnection false
    r'(?i)validateCertificates\s*=\s*false', # validateCertificates false
    r'(?i)verify\s*=\s*False', # verify False
    r'(?i)DEBUG\s*=\s*True', # DEBUG True
    r'(?i)ENV\s*=\s*[\'\"]?development[\'\"]?', # ENV=development
    r'(?i)NODE_ENV\s*=\s*development', # NODE_ENV=development
    r'(?i)FLASK_ENV\s*=\s*development', # FLASK_ENV=development
    r'(?i)DJANGO_DEBUG\s*=\s*True', # DJANGO_DEBUG True
    r'(?i)SECRET_KEY\s*=\s*[\'\"]?changeme[\'\"]?', # SECRET_KEY changeme
    r'(?i)ALLOWED_HOSTS\s*=\s*\*', # ALLOWED_HOSTS *
    r'(?i)CORS_ORIGIN_ALLOW_ALL\s*=\s*True', # CORS_ORIGIN_ALLOW_ALL True
    r'(?i)CORS_ALLOW_CREDENTIALS\s*=\s*True', # CORS_ALLOW_CREDENTIALS True
    r'(?i)SESSION_COOKIE_SECURE\s*=\s*False', # SESSION_COOKIE_SECURE False
    r'(?i)CSRF_COOKIE_SECURE\s*=\s*False', # CSRF_COOKIE_SECURE False
    r'(?i)SECURE_SSL_REDIRECT\s*=\s*False', # SECURE_SSL_REDIRECT False
    r'(?i)SECURE_HSTS_SECONDS\s*=\s*0', # SECURE_HSTS_SECONDS 0
    r'(?i)SECURE_BROWSER_XSS_FILTER\s*=\s*False', # SECURE_BROWSER_XSS_FILTER False
    r'(?i)SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False', # SECURE_CONTENT_TYPE_NOSNIFF False
    r'(?i)SECURITY_HEADERS\s*=\s*False', # SECURITY_HEADERS False
    r'(?i)X-Frame-Options:\s*ALLOWALL', # X-Frame-Options ALLOWALL
    r'(?i)X-Content-Type-Options:\s*none', # X-Content-Type-Options none
    r'(?i)Strict-Transport-Security:\s*', # Strict-Transport-Security missing
    r'(?i)ssl\s*=\s*off', # SSL off
    r'(?i)listen\s+80;', # listen 80 (no HTTPS)
    r'(?i)server_tokens\s*on', # server_tokens on
    r'(?i)autoindex\s*on', # autoindex on
    r'(?i)root\s*/var/www/html', # root /var/www/html
    r'(?i)DirectoryIndex\s+index\.php', # DirectoryIndex index.php
    r'(?i)Options\s+Indexes',
    r'(?i)PermitRootLogin\s+yes',
    r'(?i)PasswordAuthentication\s+yes',
    r'(?i)UsePAM\s+yes',
    r'(?i)AllowTcpForwarding\s+yes',
    r'(?i)HostbasedAuthentication\s+yes',
    r'(?i)ChallengeResponseAuthentication\s+yes',
    r'(?i)LogLevel\s+debug',
    r'(?i)log_errors\s*=\s*Off',
    r'(?i)error_reporting\s*=\s*E_ALL',
    r'(?i)session\.use_trans_sid\s*=\s*1',
    r'(?i)session\.cookie_httponly\s*=\s*0',
    r'(?i)session\.cookie_secure\s*=\s*0',
    r'(?i)session\.use_only_cookies\s*=\s*0',
    r'(?i)httpOnly\s*:\s*false',
    r'(?i)secure\s*:\s*false',
    r'(?i)SameSite\s*:\s*None',
    r'(?i)cookie\s*:\s*{[^}]*secure\s*:\s*false',
    r'(?i)cookie\s*:\s*{[^}]*httpOnly\s*:\s*false',
    r'(?i)cookie\s*:\s*{[^}]*sameSite\s*:\s*none',
    r'(?i)admin:admin', # admin:admin default
    r'(?i)root:root', # root:root default
    r'(?i)default\s*password', # default password
]
