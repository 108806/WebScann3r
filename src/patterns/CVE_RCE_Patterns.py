# Historical CVE/RCE Patterns that our scanner should detect
# Based on real-world exploits and AJAX-based vulnerabilities

cve_rce_patterns = [
    # CVE-2017-5638 - Apache Struts2 (Jakarta Multipart parser)
    r'(?i)Content-Type:.*multipart/form-data.*ognl:',
    r'(?i)%{.*}.*ognl',
    r'(?i)#_memberAccess\[.*allowStaticMethodAccess.*\]',
    r'(?i)#context\[.*xwork\.MethodAccessor\.denyMethodExecution.*\]',
    
    # CVE-2018-11776 - Apache Struts2 (Namespace handling)
    r'(?i)redirect:\${.*}',
    r'(?i)redirectAction:\${.*}',
    r'(?i)namespace.*\${.*}',
    
    # CVE-2019-0232 - Apache Tomcat CGI (Windows)
    r'(?i)cgi-bin.*\.bat.*&',
    r'(?i)cgi-bin.*\.cmd.*&',
    r'(?i)cgi-bin.*\|',
    
    # CVE-2020-1938 - Apache Tomcat AJP
    r'(?i)ajp13:',
    r'(?i)AJP/1\.3',
    r'(?i):8009',  # Default AJP port
    
    # CVE-2021-44228 - Log4j JNDI injection
    r'(?i)\${jndi:',
    r'(?i)\${jndi:ldap://',
    r'(?i)\${jndi:rmi://',
    r'(?i)\${jndi:dns://',
    r'(?i)\${jndi:nis://',
    r'(?i)\${jndi:nds://',
    r'(?i)\${jndi:corba://',
    r'(?i)\${jndi:iiop://',
    
    # CVE-2021-45046 - Log4j followup
    r'(?i)\${jndi:.*\$\{lower:.*\}',
    r'(?i)\${jndi:.*\$\{upper:.*\}',
    
    # Apache Struts2 OGNL Expression injection patterns
    r'(?i)%\{.*#.*=.*new.*java\.lang\.ProcessBuilder',
    r'(?i)%\{.*#.*\.exec\(',
    r'(?i)%\{.*@java\.lang\.Runtime@getRuntime\(\)\.exec\(',
    r'(?i)%\{.*#application\[.*\].*=.*new.*',
    
    # Java Deserialization RCE patterns
    r'(?i)rO0AB.*',  # Java serialization magic bytes (base64)
    r'(?i)aced0005.*',  # Java serialization magic bytes (hex)
    r'(?i)ObjectInputStream.*readObject',
    r'(?i)ysoserial',
    
    # Spring Expression Language (SpEL) injection
    r'(?i)\#{.*T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec\(',
    r'(?i)\#{.*new.*java\.lang\.ProcessBuilder',
    r'(?i)\#{.*T\(java\.lang\.System\)\.getProperty\(',
    
    # Server-Side Template Injection (SSTI)
    r'(?i)\{\{.*\.__class__\.__bases__.*\}\}',  # Python SSTI
    r'(?i)\{\{.*config\.from_object.*\}\}',  # Flask SSTI
    r'(?i)\{\{.*\[\]\.constructor\.constructor\(.*\)\(\).*\}\}',  # JavaScript SSTI
    
    # Node.js specific RCE patterns
    r'(?i)child_process\.exec.*shell:.*true',
    r'(?i)require\(["\']child_process["\']\)\.exec\(',
    r'(?i)vm\.runInNewContext\(',
    r'(?i)Function\(.*\)\(\)',
    
    # PHP specific RCE patterns (often via AJAX)
    r'(?i)assert\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)create_function\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)call_user_func\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)call_user_func_array\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)array_map\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)usort\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)preg_replace.*\/e.*\$_(?:GET|POST|REQUEST|COOKIE)',
    
    # Serialization/Deserialization patterns
    r'(?i)unserialize\(.*\$_(?:GET|POST|REQUEST|COOKIE)',
    r'(?i)pickle\.loads\(',
    r'(?i)yaml\.load\(',
    r'(?i)json\.loads\(',
    
    # AJAX-specific patterns for RCE delivery
    r'(?i)xhr\.setRequestHeader\(.*X-Forwarded-For.*\${jndi:',
    r'(?i)fetch\(.*headers:.*User-Agent.*\${jndi:',
    r'(?i)axios\.post\(.*\${jndi:',
    r'(?i)\.ajax\(.*data:.*\${jndi:',
    
    # Expression Language injection
    r'(?i)\${.*Runtime\.getRuntime\(\)\.exec\(',
    r'(?i)\${.*ProcessBuilder\(',
    r'(?i)\${.*\.getClass\(\)\.forName\(',
    
    # XXE via AJAX (can lead to RCE)
    r'(?i)<!ENTITY.*SYSTEM.*file:',
    r'(?i)<!ENTITY.*SYSTEM.*http:',
    r'(?i)<!ENTITY.*SYSTEM.*expect:',
    
    # LDAP injection (can chain to RCE)
    r'(?i)ldap://.*\${jndi:',
    r'(?i)ldaps://.*\${jndi:',
    
    # Ruby specific RCE
    r'(?i)eval\(.*params\[',
    r'(?i)instance_eval\(.*params\[',
    r'(?i)class_eval\(.*params\[',
    r'(?i)send\(.*params\[',
    
    # Python specific RCE
    r'(?i)exec\(.*request\.GET',
    r'(?i)exec\(.*request\.POST',
    r'(?i)eval\(.*request\.GET',
    r'(?i)eval\(.*request\.POST',
    r'(?i)compile\(.*request\.(?:GET|POST)',
    
    # ASP.NET specific patterns
    r'(?i)Response\.WriteFile\(.*Request\.',
    r'(?i)Server\.Execute\(.*Request\.',
    r'(?i)ProcessStartInfo.*FileName.*Request\.',
]

# CVE-specific endpoint patterns
cve_endpoint_patterns = [
    # Struts2 vulnerable endpoints
    r'(?i)/struts2?/',
    r'(?i)\.action$',
    r'(?i)\.do$',
    
    # Tomcat manager/CGI
    r'(?i)/manager/html',
    r'(?i)/manager/text',
    r'(?i)/cgi-bin/',
    
    # Common Java webapp paths
    r'(?i)/admin/',
    r'(?i)/console/',
    r'(?i)/api/',
    r'(?i)/rest/',
    
    # Log4j vulnerable services
    r'(?i)/api/log',
    r'(?i)/log',
    r'(?i)/logging',
    r'(?i)/solr/',
    r'(?i)/elasticsearch/',
]

# Version patterns for vulnerable software
vulnerable_versions = {
    'struts': [
        r'(?i)struts-2\.([0-4]\.|5\.0\.|5\.1[0-2]\.)',  # Struts 2.0-2.5.12
    ],
    'tomcat': [
        r'(?i)tomcat-([6-8]\.|9\.0\.[0-2][0-9]\.)',  # Various vulnerable Tomcat versions
    ],
    'log4j': [
        r'(?i)log4j-([01]\.|2\.([0-9]|1[0-5])\.)',  # Log4j 2.0-2.15
    ],
    'spring': [
        r'(?i)spring-([0-4]\.|5\.[0-2]\.)',  # Various Spring versions
    ]
}
