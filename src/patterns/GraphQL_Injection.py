# Patterns for GraphQL Security Issues
graphql_injection_patterns = [
    # Schema introspection — enabled by default, should be disabled in production
    r'(?i)\b__schema\s*\{',
    r'(?i)\b__type\s*\(',
    r'(?i)\bintrospection\s*:\s*true\b',
    r'(?i)graphql\.introspection\s*=\s*true',
    r'(?i)disableIntrospection\s*:\s*false\b',

    # GraphQL endpoint exposure
    r'(?i)/graphql(?:/|\?|["\'\s])',
    r'(?i)/graphiql(?:/|\?|["\'\s])',
    r'(?i)/graph(?:ql)?-?playground',
    r'(?i)/api/graphql\b',

    # Missing depth/complexity limiting (allows nested query DoS)
    r'(?i)depthLimit\s*:\s*(?:\d{3,}|undefined|null|false)\b',
    r'(?i)complexityLimit\s*:\s*(?:\d{5,}|undefined|null|false)\b',
    r'(?i)maxDepth\s*:\s*(?:\d{3,}|undefined|null|false)\b',

    # Batched HTTP requests enabled (amplification/DoS risk)
    r'(?i)allowBatchedHttpRequests\s*:\s*true\b',
    r'(?i)batching\s*:\s*true\b',

    # String concatenation in GraphQL query construction (injection risk)
    r'(?i)gql`[^`]*\$\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)',
    r'(?i)["\'](?:query|mutation)\s+\w+.*["\']\s*\+',

    # GraphQL mutation with destructive operation names
    r'(?i)\bmutation\s+\w*(?:Delete|Remove|Destroy|Drop|Truncate)\w*\s*\{',

    # Unauthenticated resolver (async resolver arrow function without auth check on same line)
    r'(?i)resolve\s*:\s*async\s*\(?[^)]*\)\s*=>\s*(?!\{[^}]*(?:auth|token|permission|role|user\b))',

    # Field-level authorization missing (returning sensitive fields without check)
    r'(?i)(?:password|secret|token|ssn|creditCard|credit_card)\s*:\s*\{\s*type\s*:\s*GraphQLString',

    # Apollo/urql/relay client over unencrypted transport
    r'(?i)ApolloClient\s*\([^)]*uri\s*:\s*["\']http://',
    r'(?i)createClient\s*\([^)]*url\s*:\s*["\']http://',
]
