# TechVault Solutions - Infrastructure Plan

**Fictional Company for Security Testing**

---

## Company Overview

**Company Name:** TechVault Solutions  
**Industry:** Cloud Security & Data Management SaaS  
**Purpose:** Realistic fictional company infrastructure for penetration testing and security research

---

## Phase 1: Company Identity & Branding

### 1.1 Define Company Profile
- **Industry Sector:** Cloud Security & Data Management SaaS
- **Company Name:** TechVault Solutions
- **Backstory:**
  - Founded: 2019
  - Mission: "Securing your digital assets with enterprise-grade cloud solutions"
  - Services: Cloud backup, encryption services, compliance monitoring, secure file sharing
  - Company Size: 25-50 employees
  - Revenue Tier: $5M-$10M ARR (simulated)
  
- **Organizational Structure:**
  - Executive Team: CEO, CTO, CFO, VP Sales
  - Engineering: Dev team (5-7), DevOps (2-3)
  - Sales & Marketing: Sales team (3-4), Marketing (2-3)
  - Operations: Customer Success (3-4), Support (2-3)

### 1.2 Visual Identity
- Design logo and color scheme (blues/greens for tech/security feel)
- Create brand guidelines document
- Generate company assets:
  - Logo (SVG and PNG variants)
  - Favicon
  - Social media headers
  - Email signatures

---

## Phase 2: Domain & Online Presence

### 2.1 Domain Registration
- **Primary Domain:** techvault-solutions.com (or similar available)
- **Email Setup:** 
  - info@techvault-solutions.com
  - support@techvault-solutions.com
  - Individual employee emails (firstname.lastname@)
  
- **DNS Configuration:**
  - SPF record: `v=spf1 include:amazonses.com ~all`
  - DKIM: AWS SES configuration
  - DMARC: `v=DMARC1; p=quarantine; rua=mailto:dmarc@techvault-solutions.com`

### 2.2 Website Development
- **Platform:** Static site (Hugo/Jekyll) or WordPress
- **Essential Pages:**
  - Home (hero section, value props, CTA)
  - About Us (company story, mission)
  - Products/Services (detailed offerings)
  - Team (employee profiles with photos)
  - Contact (form, address, phone)
  - Careers (job listings)
  - Blog (industry insights, company news)
  - Resources (white papers, case studies)
  - Privacy Policy & Terms of Service
  
- **Features:**
  - Customer login portal
  - Live chat widget (simulated)
  - Newsletter signup
  - Google Analytics or Matomo
  - Intentional vulnerabilities for testing (documented separately)

### 2.3 SSL/TLS Configuration
- AWS Certificate Manager for free SSL
- Force HTTPS redirects
- HSTS headers enabled
- TLS 1.2+ only

---

## Phase 3: AWS Infrastructure Setup

### 3.1 Core Infrastructure

**Network Layer:**
- VPC: 10.0.0.0/16
- Public Subnets: 10.0.1.0/24, 10.0.2.0/24 (us-east-1a, us-east-1b)
- Private Subnets: 10.0.10.0/24, 10.0.11.0/24
- NAT Gateway for private subnet internet access
- Internet Gateway for public subnets

**Compute:**
- EC2 Web Servers (2x t3.small) - Public subnets
- EC2 App Servers (2x t3.small) - Private subnets
- EC2 Admin/Bastion (1x t3.micro) - Public subnet
- Auto Scaling Group for web tier

**Database:**
- RDS PostgreSQL (db.t3.micro)
- Multi-AZ deployment
- Automated backups enabled
- Located in private subnets

**Storage:**
- S3 Buckets:
  - `techvault-website-assets` (public read)
  - `techvault-customer-data` (private, with intentional misconfig)
  - `techvault-backups` (private)
  - `techvault-logs` (private)

**CDN & DNS:**
- CloudFront distribution for website
- Route 53 hosted zone for DNS
- ALB (Application Load Balancer) for web tier

**Monitoring & Logging:**
- CloudWatch Logs (all services)
- CloudTrail (API audit logging)
- VPC Flow Logs
- CloudWatch Alarms for critical metrics

### 3.2 Intentionally Vulnerable Infrastructure

**For Penetration Testing:**

- **Misconfigured S3 Buckets:**
  - `techvault-public-backups` - Public read/write enabled
  - Bucket policy allowing anonymous access
  - Unencrypted data at rest
  
- **Weak EC2 Configurations:**
  - Instance with SSH open to 0.0.0.0/0
  - Outdated software (Ubuntu 18.04 with known CVEs)
  - Web server with directory listing enabled
  - Exposed .git directory
  
- **Security Group Issues:**
  - RDS security group allowing 0.0.0.0/0 on port 5432
  - Application server with unnecessary ports open
  - No egress filtering
  
- **Application Vulnerabilities:**
  - Admin panel at /admin with weak credentials (admin/Admin123!)
  - API endpoints without rate limiting
  - Unvalidated redirects
  - Exposed environment variables
  
- **IAM Misconfigurations:**
  - User with AdministratorAccess but no MFA
  - Service account with overly broad S3 permissions
  - Access keys in code repositories
  - Unused but active credentials

### 3.3 Security Controls (Some Intentionally Weak)

- **AWS WAF:**
  - Deployed but with limited rules
  - SQL injection protection (disabled for testing)
  - Rate limiting (set high for testing)
  
- **GuardDuty:** Enabled (to detect testing activities)
- **AWS Config:** Enabled (to track misconfigurations)
- **Secrets Manager:** For some credentials (not all - some hardcoded)

### 3.4 IAM Configuration

**IAM Users (Fictional Employees):**
- `sarah.mitchell` (CEO) - AdministratorAccess
- `james.rodriguez` (CTO) - PowerUserAccess
- `emily.chen` (DevOps Lead) - EC2, RDS, S3 full access
- `michael.thompson` (Developer) - Limited EC2, S3 read
- `jessica.williams` (Support) - S3 read-only, CloudWatch read
- `contractor-temp` (External) - Overly permissive, no MFA

**IAM Roles:**
- EC2WebServerRole - Access to S3 assets bucket
- EC2AppServerRole - Access to RDS, S3 data buckets
- LambdaExecutionRole - CloudWatch Logs, limited S3

---

## Phase 4: Realistic Content Generation

### 4.1 Employee Personas

**Executive Team:**

1. **Sarah Mitchell** - CEO & Co-Founder
   - Bio: 15 years in enterprise software, former VP at major cloud provider
   - Email: sarah.mitchell@techvault-solutions.com
   - LinkedIn: Full profile with connections
   - Photo: Professional headshot (AI-generated or stock)

2. **James Rodriguez** - CTO & Co-Founder
   - Bio: Former security architect, 3 patents in encryption tech
   - Email: james.rodriguez@techvault-solutions.com
   - GitHub: Active account with contributions

3. **Lisa Chang** - VP of Sales
   - Bio: 10+ years in SaaS sales, expertise in enterprise deals
   - Email: lisa.chang@techvault-solutions.com

**Engineering Team:**

4. **Emily Chen** - DevOps Lead
   - Email: emily.chen@techvault-solutions.com
   - GitHub: Repos showing infrastructure work

5. **Michael Thompson** - Senior Developer
   - Email: michael.thompson@techvault-solutions.com

6. **David Kim** - Security Engineer
   - Email: david.kim@techvault-solutions.com

**Sales & Marketing:**

7. **Jessica Williams** - Customer Success Manager
   - Email: jessica.williams@techvault-solutions.com

8. **Robert Martinez** - Marketing Manager
   - Email: robert.martinez@techvault-solutions.com

### 4.2 Company Content

**Blog Posts (5-10 articles):**
- "5 Cloud Security Mistakes Companies Make in 2024"
- "Understanding Zero-Trust Architecture"
- "TechVault Q3 Product Updates"
- "Compliance Made Easy: SOC 2 Best Practices"
- "Why Encryption Keys Management Matters"

**Resources:**
- White paper: "The State of Cloud Security 2024"
- Case study: "How FinanceCorp Secured 10TB of Data"
- Product documentation and API docs
- Integration guides

**Press Releases:**
- Company founding announcement
- Series A funding (fictional)
- New product launch
- Customer milestone reached

### 4.3 Operational Details

- **Physical Address:** 
  - 123 Innovation Drive, Suite 400
  - San Francisco, CA 94103
  - (Use virtual office service or clearly fictional)

- **Phone Number:** 
  - Main: (555) 847-2683 (spells VAULT on keypad)
  - Support: (555) 847-2684
  - (Google Voice or VoIP.ms)

- **Business Hours:** Mon-Fri 9AM-6PM PST
- **Support Hours:** 24/7 (simulated via chatbot)

---

## Phase 5: Social Media & External Presence

### 5.1 LinkedIn

**Company Page:**
- Complete profile with logo, banner, description
- 500+ followers (can boost with small budget)
- Regular posts (2-3x per week):
  - Company updates
  - Industry news shares
  - Employee spotlights
  - Job postings

**Employee Profiles:**
- All 8-10 key employees with complete profiles
- Work history (can be partial fiction)
- Skills and endorsements
- Connections to each other
- Recommendations between team members
- Regular activity (posts, comments, shares)

### 5.2 Other Platforms

**Twitter/X (@TechVaultSec):**
- Company bio and branding
- 200+ followers
- Regular tweets about cloud security
- Engagement with industry content
- Customer support responses

**GitHub (techvault-solutions):**
- Public repos:
  - techvault-cli (CLI tool for API)
  - techvault-docs (documentation site)
  - techvault-examples (integration examples)
- Some intentional vulnerabilities in code
- Realistic commit history

**Optional:**
- Facebook business page
- YouTube channel (product demos)
- Medium publication (blog mirror)

### 5.3 External References

**Business Directories:**
- Crunchbase profile
- AngelList listing
- G2 or Capterra (if possible)
- Better Business Bureau (local listing)

**Community Presence:**
- Stack Overflow answers from employees
- Reddit comments on relevant subreddits (subtle)
- HackerNews profile and comments
- Comments on industry blogs

---

## Phase 6: Technical Services & Applications

### 6.1 Simulated Services

**Customer Portal (portal.techvault-solutions.com):**
- Login system (username/password)
- Dashboard showing "usage metrics"
- File upload/download functionality
- Account settings
- Billing information page
- Support ticket system

**API (api.techvault-solutions.com):**
- RESTful API with documentation
- Endpoints:
  - `/v1/auth/login`
  - `/v1/files/upload`
  - `/v1/files/download/:id`
  - `/v1/users/profile`
  - `/v1/backups/list`
- API keys for authentication
- Rate limiting (weak for testing)

**Admin Dashboard (admin.techvault-solutions.com):**
- Internal tools interface
- User management
- System monitoring dashboard
- Configuration panel
- Intentionally weak authentication

### 6.2 Backend Systems

**Database Schema:**
```sql
Tables:
- users (id, email, password_hash, created_at)
- files (id, user_id, filename, s3_key, size)
- backups (id, user_id, backup_date, status)
- api_keys (id, user_id, key_hash, permissions)
- audit_logs (id, user_id, action, timestamp)
```

**Application Stack:**
- Frontend: React or Vue.js
- Backend: Node.js/Express or Python/Flask
- Database: PostgreSQL
- Cache: Redis (optional)
- Queue: SQS for async jobs

**CI/CD Pipeline:**
- GitHub Actions or GitLab CI
- Automated tests (some)
- Deployment to EC2 via CodeDeploy
- Slack notifications

---

## Phase 7: Vulnerability Implementation (For Testing)

### 7.1 Web Application Vulnerabilities

**SQL Injection:**
- Login form: `' OR '1'='1`
- Search functionality
- API parameter: `/api/user?id=1 OR 1=1`

**Cross-Site Scripting (XSS):**
- Comment/feedback forms
- Profile fields (stored XSS)
- Search results page (reflected XSS)

**Authentication Issues:**
- Weak password policy (no complexity requirements)
- No account lockout after failed attempts
- Predictable session tokens
- Password reset token doesn't expire

**Authorization Issues:**
- IDOR: `/api/files/123` (access other users' files)
- Missing function-level access control
- Horizontal privilege escalation

**File Upload Vulnerabilities:**
- No file type validation
- Executable files allowed
- No size limit enforcement
- Path traversal in filename

**API Vulnerabilities:**
- No rate limiting
- Verbose error messages with stack traces
- API keys in URL parameters
- JWT with weak secret

**Information Disclosure:**
- `.git` directory exposed
- `phpinfo()` or debug pages
- Directory listing enabled
- Comments in HTML with sensitive info
- `.env` file accessible

### 7.2 Infrastructure Vulnerabilities

**Network:**
- SSH open to 0.0.0.0/0 on port 22
- RDP open (if Windows instance)
- Unnecessary services running (FTP, Telnet)
- No network segmentation

**EC2 Instances:**
- Default credentials on admin interfaces
- Outdated OS and packages (known CVEs)
- IMDSv1 enabled (metadata service)
- User data with credentials

**S3 Buckets:**
- Public read/write access
- No bucket versioning
- No encryption at rest
- Predictable bucket names

**RDS:**
- Public accessibility enabled
- Weak master password
- No encryption in transit
- Publicly accessible backup

**IAM:**
- Access keys in GitHub repo
- Overly permissive policies (`*` on `*`)
- Unused credentials not rotated
- No MFA on privileged accounts

### 7.3 Cloud-Specific Vulnerabilities

**AWS-Specific:**
- EC2 instance profile with excessive permissions
- Lambda function with hardcoded credentials
- API Gateway with no authorization
- Cognito with weak password policy
- CloudFormation templates with secrets

**Container Issues (if using ECS/EKS):**
- Privileged containers
- Secrets in environment variables
- No resource limits
- Outdated base images

---

## Phase 8: Documentation & Testing Scope

### 8.1 Rules of Engagement

**In-Scope:**
- All techvault-solutions.com domains and subdomains
- AWS resources tagged with `Project: TechVault`
- IP ranges: [specify CIDR blocks]
- Social engineering (email only, no phone)

**Out-of-Scope:**
- Physical security testing
- Denial of Service attacks
- Third-party services (LinkedIn, GitHub, etc.)
- Other AWS accounts

**Testing Guidelines:**
- Business hours: Any time
- Notification: Required for critical findings
- Data exfiltration: Maximum 10MB sample
- Credential usage: Document all compromised creds

**Communication:**
- Primary: security-test@techvault-solutions.com
- Slack channel: #pentest-findings
- Emergency: [phone number]

### 8.2 Internal Documentation

**Architecture Diagrams:**
- Network topology (VPC, subnets, routing)
- Application architecture (components, data flow)
- AWS services map
- Security controls layout

**Credential Repository:**
```
Location: AWS Secrets Manager or 1Password
Format:
- Service: EC2 Web Server
  - User: ubuntu
  - Password: [stored securely]
  - SSH Key: techvault-web-key.pem
  - IP: 54.x.x.x
```

**Known Vulnerabilities Inventory:**
```
ID | Type | Location | Severity | Remediation
1  | SQLi | /login   | Critical | Parameterized queries
2  | XSS  | /search  | High     | Input sanitization
...
```

**Deployment Procedures:**
- Infrastructure as Code (Terraform scripts)
- Application deployment steps
- Database migration process
- SSL certificate renewal
- Backup and restore procedures

**Rollback Procedures:**
- Application rollback steps
- Infrastructure state recovery
- Database restore process
- DNS failover process

---

## Phase 9: Maintenance & Realism

### 9.1 Ongoing Activities

**Content Updates (Weekly):**
- 1-2 blog posts per month
- Social media posts (2-3x per week)
- LinkedIn activity (daily check-ins)
- Twitter engagement

**Infrastructure Maintenance:**
- Update SSL certificates (automated)
- Rotate some credentials (not all - for testing)
- Apply security patches (selectively)
- Monitor AWS costs

**Realism Touch-ups:**
- Update copyright year
- Add new team members occasionally
- Post job listings
- Send email newsletters (to test list)
- Update product "features"

### 9.2 Monitoring

**Attack Detection:**
- CloudWatch Logs analysis
- GuardDuty findings review
- VPC Flow Logs monitoring
- Failed login attempt tracking
- API abuse detection

**Logging Strategy:**
```
Log Type               | Retention | Location
--------------------- | --------- | -------------------
Web access logs       | 90 days   | CloudWatch
Application logs      | 30 days   | CloudWatch
Database query logs   | 30 days   | RDS logs
CloudTrail           | 1 year    | S3
VPC Flow Logs        | 30 days   | CloudWatch
```

**Cost Monitoring:**
- AWS Budget alerts ($50, $100, $150)
- Daily cost reports
- Resource utilization tracking
- Optimization recommendations

**Service Health:**
- CloudWatch dashboards
- Uptime monitoring (UptimeRobot)
- Performance metrics
- Error rate tracking

---

## Implementation Considerations

### Cost Management

**Estimated Monthly Costs:**
```
Service              | Configuration        | Est. Cost
-------------------- | -------------------- | ----------
EC2 (5 instances)    | t3.micro/small      | $30-50
RDS                  | db.t3.micro         | $15-20
S3                   | < 100GB             | $3-5
Data Transfer        | < 100GB             | $5-10
Route 53             | 1 hosted zone       | $0.50
CloudFront           | < 50GB              | $5
Domain               | Annual              | $12/year
Total:               |                     | ~$70-100/mo
```

**Cost Optimization:**
- Use AWS Free Tier (first 12 months)
- Reserved Instances for long-term resources
- S3 Lifecycle policies (move old data to Glacier)
- CloudWatch Logs retention limits
- Auto Scaling based on time (scale down nights/weekends)
- Budget alerts and automated shutdowns

### Legal & Ethical Considerations

**Compliance:**
- **AWS Acceptable Use Policy:** Ensure pentesting complies
- **AWS Penetration Testing:** Fill out request form if needed (not always required for own resources)
- **Domain Registration:** Use privacy protection
- **Fictitious Business:** Don't impersonate real companies
- **Trademark:** Ensure company name doesn't infringe

**Disclaimers:**
- Add "This is a test environment" in robots.txt comment
- Internal documentation clearly marked as fictional
- No real customer data
- No real financial transactions

**Data Protection:**
- Don't collect real emails (use + trick: youremail+test@gmail.com)
- Any form submissions go to controlled addresses
- GDPR-like privacy policy (even though fictional)
- Clear data retention policies

### Scalability & Automation

**Infrastructure as Code:**
```
terraform/
├── modules/
│   ├── vpc/
│   ├── ec2/
│   ├── rds/
│   └── s3/
├── environments/
│   ├── dev/
│   └── prod/
├── main.tf
├── variables.tf
└── outputs.tf
```

**CI/CD Pipeline:**
- GitHub repo for all code
- Automated testing (basic)
- Terraform Cloud or GitLab CI
- Automated deployments on merge to main
- Rollback capability

**Configuration Management:**
- Ansible playbooks for server configuration
- Docker containers for applications (optional)
- Secrets in AWS Secrets Manager
- Environment-specific configs

**Version Control:**
- All code in Git
- Infrastructure code in separate repo
- Documentation in wiki or separate repo
- Version tags for releases

---

## Quick Start Implementation Order

### Week 1: Foundation
1. ✅ Choose company name and industry
2. ✅ Register domain name
3. ✅ Create AWS account (separate from production)
4. ✅ Set up VPC and basic networking
5. ✅ Deploy first EC2 instance
6. ✅ Set up Route 53 and SSL certificate

### Week 2: Website & Content
7. ✅ Design logo and basic branding
8. ✅ Create website structure (static site)
9. ✅ Write company content (About, Services, etc.)
10. ✅ Create 5-8 employee personas
11. ✅ Deploy website to EC2/S3+CloudFront
12. ✅ Set up email (AWS SES)

### Week 3: Infrastructure & Apps
13. ✅ Deploy RDS database
14. ✅ Create customer portal (basic login)
15. ✅ Set up API endpoints
16. ✅ Configure S3 buckets
17. ✅ Implement basic vulnerabilities
18. ✅ Set up monitoring and logging

### Week 4: Online Presence
19. ✅ Create LinkedIn company page
20. ✅ Create LinkedIn profiles for employees
21. ✅ Set up Twitter/GitHub accounts
22. ✅ Post initial content
23. ✅ Submit to business directories
24. ✅ Create testing documentation

### Week 5+: Polish & Testing
25. ✅ Test all vulnerabilities
26. ✅ Document findings
27. ✅ Add more content (blog posts)
28. ✅ Increase social media activity
29. ✅ Run first pentest
30. ✅ Iterate based on findings

---

## Next Steps

Choose a starting point based on priority:

1. **Company Identity** - Finalize name, industry, backstory
2. **AWS Setup** - Create Terraform configuration for infrastructure
3. **Website Development** - Choose platform and create initial pages
4. **Employee Personas** - Generate realistic profiles with photos
5. **Vulnerability Mapping** - Document specific vulns to implement

---

## Resources & Tools

**Infrastructure:**
- Terraform (IaC)
- AWS CLI
- AWS Console

**Website:**
- Hugo or Jekyll (static site generator)
- WordPress (if CMS preferred)
- Bootstrap or Tailwind CSS

**Content Generation:**
- ChatGPT/Claude for text content
- DALL-E or Midjourney for images
- This Person Does Not Exist (AI faces)
- Unsplash (stock photos)

**Social Media:**
- Buffer or Hootsuite (scheduling)
- Canva (graphics)

**Monitoring:**
- AWS CloudWatch
- UptimeRobot
- Google Analytics

**Testing:**
- Burp Suite
- Metasploit
- Nmap
- OWASP ZAP
- Custom scripts

---

**Project Status:** Planning Phase  
**Last Updated:** 2024  
**Owner:** Security Research Team  
**Classification:** Internal Testing Environment
