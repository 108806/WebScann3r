patterns = [
    # TLDR: Detects MongoDB find() with $-prefixed operator (potential injection)
    r'(?i)db\..*\.find\(.*\$.*\)',
    # TLDR: Detects $where operator in NoSQL queries
    r'(?i)\$where\s*:\s*["\']?.*',
    # TLDR: Detects $ne (not equal) operator in NoSQL queries
    r'(?i)\$ne\s*:\s*["\']?.*',
    # TLDR: Detects $gt (greater than) operator in NoSQL queries
    r'(?i)\$gt\s*:\s*["\']?.*',
    # TLDR: Detects $lt (less than) operator in NoSQL queries
    r'(?i)\$lt\s*:\s*["\']?.*',
    # TLDR: Detects $regex operator in NoSQL queries
    r'(?i)\$regex\s*:\s*["\']?.*',
    # TLDR: Detects MongoClient usage (potential for NoSQL injection)
    r'(?i)\bMongoClient\b',
    # TLDR: Detects mongoose.model() usage (potential for NoSQL injection)
    r'(?i)\bmongoose\.model\(',
    # TLDR: Detects collection.find() usage (potential for NoSQL injection)
    r'(?i)\bcollection\.find\(',
    # TLDR: Detects collection.aggregate() usage (potential for NoSQL injection)
    r'(?i)\bcollection\.aggregate\(',
]
