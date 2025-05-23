# Patterns for Unrestricted File Upload (expanded and well-commented)
unrestricted_file_upload_patterns = [
    # Common multipart/form-data and file upload indicators
    r'(?i)multipart/form-data',
    r'(?i)Content-Disposition: form-data; name=[\'\"]?file[\'\"]?',
    r'(?i)upload\s*\(',
    r'(?i)file_upload',
    r'(?i)\bmove_uploaded_file\b',
    r'(?i)\bopen\s*\(.*file',
    r'(?i)\bwrite\s*\(.*file',
    r'(?i)saveAs\s*\(',
    r'(?i)storeAs\s*\(',
    r'(?i)copy\s*\(.*file',
    r'(?i)shutil\.copy\s*\(',
    r'(?i)shutil\.move\s*\(',
    r'(?i)os\.rename\s*\(',
    r'(?i)os\.replace\s*\(',
    r'(?i)fopen\s*\(.*\$_(?:FILES|POST|GET|REQUEST|COOKIE)',
    r'(?i)file_put_contents\s*\(.*\$_(?:FILES|POST|GET|REQUEST|COOKIE)',
    r'(?i)fwrite\s*\(.*\$_(?:FILES|POST|GET|REQUEST|COOKIE)',
    r'(?i)readfile\s*\(.*\$_(?:FILES|POST|GET|REQUEST|COOKIE)',
    r'(?i)input\s+type=[\'\"]file[\'\"]',
    r'(?i)enctype=[\'\"]multipart/form-data[\'\"]',
    r'(?i)accept\s*=\s*[\'\"]\.[a-z0-9]+[\'\"]',
    r'(?i)accept\s*=\s*[\'\"]\*\/\*[\'\"]',
    r'(?i)accept\s*=\s*[\'\"]image\/\*[\'\"]',
    r'(?i)accept\s*=\s*[\'\"]application\/octet-stream[\'\"]',
    r'(?i)upload\.php',
    r'(?i)upload\.asp',
    r'(?i)upload\.aspx',
    r'(?i)upload\.jsp',
    r'(?i)upload\.py',
    r'(?i)upload\.rb',
    r'(?i)upload\.cgi',
    r'(?i)upload\.do',
    r'(?i)upload\.action',
    r'(?i)upload\.pl',
    r'(?i)upload\.go',
    r'(?i)upload\.exe',
    r'(?i)upload\.dll',
    r'(?i)upload\.sh',
    r'(?i)upload\.bat',
    r'(?i)upload\.cmd',
    r'(?i)upload\.ps1',
    r'(?i)upload\.vbs',
    r'(?i)upload\.js',
    r'(?i)upload\.html',
    r'(?i)upload\.htm',
    r'(?i)upload\.xml',
    r'(?i)upload\.json',
    r'(?i)upload\.csv',
    r'(?i)upload\.zip',
    r'(?i)upload\.tar',
    r'(?i)upload\.gz',
    r'(?i)upload\.rar',
    r'(?i)upload\.7z',
    r'(?i)upload\.pdf',
    r'(?i)upload\.doc',
    r'(?i)upload\.docx',
    r'(?i)upload\.xls',
    r'(?i)upload\.xlsx',
    r'(?i)upload\.ppt',
    r'(?i)upload\.pptx',
    r'(?i)upload\.jpg',
    r'(?i)upload\.jpeg',
    r'(?i)upload\.png',
    r'(?i)upload\.gif',
    r'(?i)upload\.bmp',
    r'(?i)upload\.svg',
    r'(?i)upload\.webp',
    r'(?i)upload\.mp3',
    r'(?i)upload\.mp4',
    r'(?i)upload\.avi',
    r'(?i)upload\.mov',
    r'(?i)upload\.wmv',
    r'(?i)upload\.flv',
    r'(?i)upload\.mkv',
    r'(?i)upload\.ogg',
    r'(?i)upload\.wav',
    r'(?i)upload\.midi',
    r'(?i)upload\.ico',
    r'(?i)upload\.svg',
    r'(?i)upload\.ttf',
    r'(?i)upload\.woff',
    r'(?i)upload\.woff2',
    r'(?i)upload\.eot',
    r'(?i)upload\.otf',
    r'(?i)upload\.psd',
    r'(?i)upload\.ai',
    r'(?i)upload\.eps',
    r'(?i)upload\.sketch',
    r'(?i)upload\.indd',
    r'(?i)upload\.xd',
    r'(?i)upload\.apk',
    r'(?i)upload\.ipa',
    r'(?i)upload\.deb',
    r'(?i)upload\.rpm',
    r'(?i)upload\.msi',
    r'(?i)upload\.cab',
    r'(?i)upload\.bin',
    r'(?i)upload\.dat',
    r'(?i)upload\.bak',
    r'(?i)upload\.tmp',
    r'(?i)upload\.log',
    r'(?i)upload\.bak',
    # Bypass tricks and suspicious patterns
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+\\x00[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%00[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%252e[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%2e[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%2e%2e[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%2e%2e%2f[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%2e%2e%5c[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+%00[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+\\x00[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+\\u0000[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+\\0[\'\"]',
    r'(?i)filename\s*=\s*[\'\"][^\'\"]+\.[a-z0-9]+\\Z[\'\"]',
    # API endpoints
    r'(?i)/api/upload',
    r'(?i)/api/file',
    r'(?i)/api/files',
    r'(?i)/api/image',
    r'(?i)/api/images',
    r'(?i)/api/attachment',
    r'(?i)/api/attachments',
    r'(?i)/api/media',
    r'(?i)/api/photos',
    r'(?i)/api/picture',
    r'(?i)/api/pictures',
    r'(?i)/api/avatar',
    r'(?i)/api/avatars',
    r'(?i)/api/document',
    r'(?i)/api/documents',
    r'(?i)/api/resource',
    r'(?i)/api/resources',
    r'(?i)/api/import',
    r'(?i)/api/export',
    # Suspicious file extension checks
    r'(?i)if\s*file\.endswith\([\'\"][.][a-z0-9]+[\'\"]\)',
    r'(?i)if\s*filename\.endswith\([\'\"][.][a-z0-9]+[\'\"]\)',
    r'(?i)if\s*file\.split\([\'\"]\.[\'\"]\)\[-1\]',
    r'(?i)if\s*filename\.split\([\'\"]\.[\'\"]\)\[-1\]',
    r'(?i)if\s*file\.lower\(\)\.endswith\([\'\"][.][a-z0-9]+[\'\"]\)',
    r'(?i)if\s*filename\.lower\(\)\.endswith\([\'\"][.][a-z0-9]+[\'\"]\)',
    # Weak file type/content checks
    r'(?i)if\s*\"image\".*in.*file\.content_type',
    r'(?i)if\s*\"application\".*in.*file\.content_type',
    r'(?i)if\s*\"text\".*in.*file\.content_type',
    r'(?i)if\s*file\.content_type\s*==\s*[\'\"][^\'\"]+[\'\"]',
    r'(?i)if\s*file\.mimetype\s*==\s*[\'\"][^\'\"]+[\'\"]',
    r'(?i)if\s*file\.type\s*==\s*[\'\"][^\'\"]+[\'\"]',
    # Misc
    r'(?i)allowAllFileTypes\s*=\s*true',
    r'(?i)allowed_file_types\s*=\s*\*',
    r'(?i)allowedExtensions\s*=\s*\*',
    r'(?i)accept\s*=\s*\*',
    r'(?i)accept\s*=\s*all',
    r'(?i)accept\s*=\s*any',
    r'(?i)accept\s*=\s*file',
    r'(?i)accept\s*=\s*files',
    r'(?i)accept\s*=\s*binary',
    r'(?i)accept\s*=\s*octet-stream',
]