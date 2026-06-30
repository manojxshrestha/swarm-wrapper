## Source Code Analysis Template

### 1. Architecture & Technology Stack
- Language & framework versions
- Dependencies (critical CVEs)
- Build/deploy configuration

### 2. Authentication & Authorization
- Session management implementation
- Role-based access control
- JWT/OAuth token handling
- Password policies and storage

### 3. Data Security & Storage
- Encryption at rest and in transit
- Secret/key management
- Database query patterns (SQL/NoSQL injection surface)
- File upload handling

### 4. Attack Surface
- Entry points and API endpoints
- Input validation patterns
- Error handling and information disclosure
- Debug/development endpoints

### 5. XSS Sinks & Render Contexts
- Template rendering (SSTI)
- HTML/JS/DOM injection points
- Content-Security-Policy headers

### 6. SSRF Sinks
- URL fetching/download functionality
- File inclusion/open operations
- DNS/network request patterns

### 7. Critical File Paths
- Configuration files with secrets
- Database files
- Backup/deployment artifacts
- Environment variable files
