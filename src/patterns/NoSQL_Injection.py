patterns = [
    r'(?i)db\..*\.find\(.*\$.*\)',
    r'(?i)\$where\s*:\s*["\']?.*',
    r'(?i)\$ne\s*:\s*["\']?.*',
    r'(?i)\$gt\s*:\s*["\']?.*',
    r'(?i)\$lt\s*:\s*["\']?.*',
    r'(?i)\$regex\s*:\s*["\']?.*',
    r'(?i)\bMongoClient\b',
    r'(?i)\bmongoose\.model\(',
    r'(?i)\bcollection\.find\(',
    r'(?i)\bcollection\.aggregate\(',
]
