# Patterns for File Inclusion (expanded and well-commented)
file_inclusion_patterns = [
    r'(?i)(?:include|require|include_once|require_once)\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # PHP file include with user input
    r'(?i)fopen\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # fopen with user input
    r'(?i)file_get_contents\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # file_get_contents with user input
    r'(?i)readfile\s*\(\s*.*\$_(?:GET|POST|REQUEST|COOKIE)', # readfile with user input
    r'(?i)new\s+FileReader\(.*\$_(?:GET|POST|REQUEST|COOKIE)', # JS FileReader with user input
    r'(?i)fs\.readFile\(.*\+', # Node.js fs.readFile with concat
    r'(?i)java\.io\.File\(.*\+', # Java File with concat
    r'(?i)open\(.*\+.*', # open() with concat
    r'(?i)include\s*[\'\"]?\s*\$\w+', # include with variable
    r'(?i)require\s*[\'\"]?\s*\$\w+', # require with variable
    r'(?i)importlib\.import_module\s*\(\s*.*\)', # Python importlib with variable
    r'(?i)__import__\s*\(\s*.*\)', # Python __import__ with variable
    r'(?i)open\s*\(\s*.*\)', # open() any input
    r'(?i)load\s*\(\s*.*\)', # load() any input
    r'(?i)File\.open\s*\(\s*.*\)', # Ruby File.open any input
    r'(?i)require_relative\s*\(\s*.*\)', # Ruby require_relative any input
    r'(?i)fs\.readFileSync\s*\(\s*.*\)', # Node.js fs.readFileSync any input
    r'(?i)fs\.createReadStream\s*\(\s*.*\)', # Node.js fs.createReadStream any input
    r'(?i)java\.nio\.file\.Files\.readAllBytes\s*\(\s*.*\)', # Java Files.readAllBytes
    r'(?i)java\.nio\.file\.Files\.lines\s*\(\s*.*\)', # Java Files.lines
    r'(?i)java\.nio\.file\.Files\.newBufferedReader\s*\(\s*.*\)', # Java Files.newBufferedReader
    r'(?i)java\.nio\.file\.Files\.newInputStream\s*\(\s*.*\)', # Java Files.newInputStream
    r'(?i)java\.nio\.file\.Files\.readString\s*\(\s*.*\)', # Java Files.readString
    r'(?i)path\.join\s*\(\s*.*\)', # Node.js path.join any input
    r'(?i)path\.resolve\s*\(\s*.*\)', # Node.js path.resolve any input
    r'(?i)os\.open\s*\(\s*.*\)', # Python os.open any input
    r'(?i)os\.fdopen\s*\(\s*.*\)', # Python os.fdopen any input
    r'(?i)os\.read\s*\(\s*.*\)', # Python os.read any input
    r'(?i)os\.popen\s*\(\s*.*\)', # Python os.popen any input
    r'(?i)os\.system\s*\(\s*.*\)', # Python os.system any input
    r'(?i)openSync\s*\(\s*.*\)', # Node.js openSync any input
    r'(?i)readFileSync\s*\(\s*.*\)', # Node.js readFileSync any input
    r'(?i)readlink\s*\(\s*.*\)', # readlink any input
    r'(?i)fscanf\s*\(\s*.*\)', # fscanf any input
    r'(?i)fgets\s*\(\s*.*\)', # fgets any input
    r'(?i)fread\s*\(\s*.*\)', # fread any input
    r'(?i)ifstream\s*\(\s*.*\)', # C++ ifstream any input
    r'(?i)fstream\s*\(\s*.*\)', # C++ fstream any input
    r'(?i)ifstream\.open\s*\(\s*.*\)', # C++ ifstream.open any input
    r'(?i)file://', # file:// wrapper
    r'(?i)php://', # php:// wrapper
    r'(?i)data://', # data:// wrapper
]
