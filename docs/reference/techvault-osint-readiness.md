# TechVault Solutions - MVP for OSINT/Recon Demos

**Purpose:** Minimal web presence to demonstrate AI agent OSINT and reconnaissance capabilities

---

## What We Need for OSINT Demos

The goal is to create enough realistic online presence that an AI agent can:
- Discover the company through searches
- Find employee information
- Enumerate email addresses
- Discover technology stack
- Map organizational structure
- Find potential attack vectors through public information

---

## Phase 1: Minimal Web Presence (Week 1)

### Domain & Hosting
- **Domain:** techvault-solutions.com (~$12/year)
- **Hosting:** AWS (S3 + CloudFront or single t3.micro EC2)
- **SSL:** Let's Encrypt or AWS Certificate Manager (free)
- **Email:** AWS SES or Google Workspace ($6/user/mo for 3-4 key addresses)

### Static Website (Essential Pages Only)

**Home Page:**
```
- Hero: "Securing Your Digital Assets with Enterprise Cloud Solutions"
- 3-4 value props
- CTA: Contact Us / Request Demo
- Footer with address, phone, email, social links
```

**About Us:**
```
- Company founding story (2019)
- Mission statement
- Brief company overview
- Office location (123 Innovation Drive, San Francisco, CA)
```

**Team Page:**
```
5-6 key employees with:
- Professional headshot (AI-generated face)
- Name and title
- Email address (firstname.lastname@techvault-solutions.com)
- Brief bio (2-3 sentences)
- LinkedIn link

Example Team:
1. Sarah Mitchell - CEO & Co-Founder
2. James Rodriguez - CTO & Co-Founder  
3. Emily Chen - Lead DevOps Engineer
4. Michael Thompson - Senior Developer
5. Jessica Williams - Customer Success Manager
```

**Contact Page:**
```
- Contact form (can go to your email)
- Company address
- Phone: (555) 847-2683
- Email: info@techvault-solutions.com, support@
- Map embed (Google Maps)
```

**Products/Services (Simple):**
```
- Cloud Backup Solutions
- Enterprise Encryption
- Compliance Monitoring
- Secure File Sharing

Each with 1 paragraph description
```

### Technology Stack (Visible for Recon)

**Intentionally Discoverable:**
- HTML comments with framework hints
- Server headers showing nginx or Apache version
- Cookies revealing session management
- JavaScript libraries (jQuery, React, etc.) in source
- robots.txt with interesting paths
- sitemap.xml
- `.git` directory (exposed for recon)
- Security.txt file in /.well-known/

**Example Reveals:**
```html
<!-- Built with React 18.2.0 -->
<!-- Backend: Node.js -->
<!-- Deployed: 2024-01-15 -->

Server: nginx/1.18.0
X-Powered-By: Express
```

### DNS Configuration
```
techvault-solutions.com
├── A record → EC2 IP or CloudFront
├── MX records → AWS SES or Google
├── TXT (SPF) → v=spf1 include:amazonses.com ~all
├── TXT (DMARC) → v=DMARC1; p=none;
└── Subdomains:
    ├── www → same as root
    ├── mail → email server
    ├── portal → coming soon page
    └── api → 503 or coming soon
```

---

## Phase 2: LinkedIn Presence (Week 1-2)

### Company Page
- Complete profile
- Logo and banner image
- 200-300 word description
- Website link
- Industry: Computer & Network Security
- Company size: 11-50 employees
- Founded: 2019
- Location: San Francisco, CA

**Initial Posts:**
- Welcome post announcing LinkedIn presence
- Share relevant industry article
- Job posting (fake but realistic)

### Employee Profiles (5-6 people)

**Essential Info Per Profile:**
- Full name
- Current position at TechVault Solutions
- Professional headshot
- Headline (e.g., "CTO at TechVault Solutions | Cloud Security Expert")
- About section (3-4 sentences)
- Work experience (current + 1-2 previous roles)
- Education (1-2 schools)
- Skills (5-10 relevant skills)
- Connections to other TechVault employees

**Profile Connection Strategy:**
- All employees connected to each other
- CEO has 500+ connections (can boost)
- Others have 100-300 connections each
- Some mutual connections for realism

---

## Phase 3: Minimal Online Footprint (Week 2)

### GitHub Organization
```
github.com/techvault-solutions

Repositories:
1. techvault-docs (public)
   - Basic documentation site
   - Installation guides
   - API reference placeholder

2. techvault-cli (public)
   - Command-line tool (basic)
   - README with usage
   - Some code examples

3. internal-tools (private, discoverable via commits/refs)
```

### Twitter/X Account
- @TechVaultSec
- Bio: "Securing digital assets with enterprise cloud solutions. San Francisco, CA"
- Profile pic: Company logo
- 5-10 tweets:
  - Company announcements
  - Industry article shares
  - Welcome message
  - Hiring post
- Follow 50-100 relevant accounts

### Business Listings
- **Google Business Profile** (if using real address, skip if virtual)
- **Crunchbase** - Basic company profile (free)
- **LinkedIn** (already covered)

---

## Phase 4: Information Leakage (For OSINT Discovery)

### Email Address Patterns (Discoverable)
```
firstname.lastname@techvault-solutions.com
- sarah.mitchell@
- james.rodriguez@
- emily.chen@
- michael.thompson@
- jessica.williams@

Also:
- info@
- support@
- careers@
- security@
- admin@ (for discovery)
```

### Employee Information (Findable)
```
Via LinkedIn and website:
- Full names
- Job titles
- Email addresses (guessable pattern)
- Professional photos
- Brief work history
- Skills and expertise areas
- Connection to other employees
```

### Technical Information (Discoverable)
```
From website source, headers, and robots.txt:

robots.txt:
User-agent: *
Disallow: /admin
Disallow: /api/internal
Disallow: /backup
Disallow: /.git
Allow: /

.git/config (if exposed):
[remote "origin"]
    url = https://github.com/techvault-solutions/website.git

security.txt:
Contact: security@techvault-solutions.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: en

Headers:
Server: nginx/1.18.0
X-Powered-By: Express
X-Frame-Options: SAMEORIGIN
```

### Organizational Structure (Inferrable)
```
From job titles and LinkedIn:

Executive Team:
├── Sarah Mitchell (CEO)
└── James Rodriguez (CTO)

Engineering:
├── Emily Chen (DevOps Lead)
├── Michael Thompson (Senior Dev)
└── [others implied]

Operations:
└── Jessica Williams (Customer Success)
```

---

## Implementation: Quick Start

### Step 1: Domain & AWS Setup (Day 1)
```bash
# Register domain
Domain: techvault-solutions.com

# AWS Setup
- Create AWS account (new or separate)
- Set up billing alerts ($50, $100)
- Create S3 bucket: techvault-website
- Enable static website hosting
- Create CloudFront distribution
- Request ACM certificate for domain
- Update domain DNS to CloudFront
```

### Step 2: Build Static Website (Day 2-3)
```bash
# Simple structure
website/
├── index.html          # Home
├── about.html          # About Us
├── team.html           # Team
├── services.html       # Services/Products
├── contact.html        # Contact
├── css/
│   └── style.css
├── js/
│   └── main.js
├── images/
│   ├── logo.png
│   ├── team/
│   └── bg-hero.jpg
├── robots.txt
├── sitemap.xml
└── .well-known/
    └── security.txt
```

**Tech Stack Option 1 (Simplest):**
- Plain HTML/CSS/JavaScript
- Bootstrap for styling
- Deploy to S3

**Tech Stack Option 2 (More Realistic):**
- Static site generator (Hugo, Jekyll, Gatsby)
- React for contact form
- Deploy to S3 or t3.micro EC2

### Step 3: Create Employee Personas (Day 3-4)
```bash
# Generate content
- Use AI for headshots (thispersondoesnotexist.com)
- Write bios (ChatGPT/Claude)
- Create email addresses in AWS SES
- Set up email forwarding to your address

# Key employees:
1. Sarah Mitchell - CEO
2. James Rodriguez - CTO
3. Emily Chen - DevOps Lead
4. Michael Thompson - Developer
5. Jessica Williams - Customer Success
```

### Step 4: LinkedIn Setup (Day 5-7)
```bash
# Company Page
- Create with business email
- Upload logo and banner
- Complete all profile sections
- Post 2-3 initial updates

# Employee Profiles
- Create 5 personal profiles
- Use employee names and photos
- Connect all to each other
- Connect to company page
- Add work history, skills
- Set privacy to public
```

### Step 5: Additional Footprint (Day 7-10)
```bash
# GitHub
- Create organization: techvault-solutions
- Create 2 public repos with basic READMEs
- Add 5-10 commits with realistic messages
- Link from website footer

# Twitter/X
- Create account @TechVaultSec
- Post 5-10 tweets
- Follow relevant accounts
- Link from website

# Business Listings
- Crunchbase basic profile
- Update LinkedIn with more detail
```

---

## Cost Breakdown (MVP)

```
Service                  | Cost/Month | Notes
----------------------- | ---------- | -------------------------
Domain                   | $1         | $12/year amortized
AWS (S3 + CloudFront)    | $5-10      | Minimal traffic
Email (AWS SES)          | $1-2       | Low volume
LinkedIn                 | Free       | Organic growth
Twitter                  | Free       |
GitHub                   | Free       | Public repos
AI Headshots             | Free       | One-time generation
----------------------- | ---------- | -------------------------
Total:                   | ~$10-15/mo | Minimal footprint

Optional adds:
Virtual Office           | $20-50/mo  | Real address for Google
Google Workspace         | $18/mo     | 3 email addresses
Phone Number (VoIP)      | $5/mo      | Google Voice or VoIP.ms
```

**Note:** Can keep it under $20/mo for pure OSINT demo purposes, or go up to $50-70/mo for more realism with email and phone.

---

## What This Enables for OSINT Demos

### Agent Can Discover:

1. **Company Information:**
   - Company name, industry, location
   - Founding date, size, mission
   - Services offered
   - Contact information

2. **Employee Enumeration:**
   - Names and titles from Team page
   - Email pattern: firstname.lastname@domain
   - LinkedIn profiles with more details
   - Organizational structure
   - Employee connections and relationships

3. **Technical Footprint:**
   - Technology stack (from headers, source)
   - Domain configuration (DNS records)
   - Subdomains (portal, api, mail)
   - Email server configuration (SPF, DMARC)
   - Potential endpoints (/admin, /api, etc.)

4. **Attack Surface:**
   - Email addresses for phishing
   - Employee names for social engineering
   - Technology versions for vulnerability research
   - Organizational relationships for targeting
   - Hidden directories from robots.txt

5. **OSINT Correlation:**
   - Cross-reference LinkedIn with website
   - GitHub activity linked to employees
   - Social media presence
   - Business listings confirmation
   - Domain registration details

### Example Agent Recon Flow:

```
1. Agent searches "TechVault Solutions"
   → Finds website, LinkedIn, Twitter

2. Agent scrapes website
   → Discovers 5 employees, email pattern, services

3. Agent checks LinkedIn
   → Finds more employee details, connections, work history

4. Agent enumerates subdomains
   → Finds portal.techvault-solutions.com (coming soon)
   → Finds api.techvault-solutions.com (503)

5. Agent checks DNS records
   → Discovers email configuration (SPF → AWS SES)
   → Finds MX records

6. Agent reviews robots.txt
   → Discovers /admin, /api/internal, /.git paths

7. Agent searches GitHub
   → Finds organization with 2 repos
   → Reviews commit history for info

8. Agent generates report:
   - 5 employees identified
   - Email addresses confirmed
   - Tech stack: nginx, Node.js/Express, React
   - AWS infrastructure (inferred from DNS)
   - Potential targets: admin panel, API endpoints
```

---

## Next Steps

**Choose implementation approach:**

**Option A: Fastest (1-2 days)**
- Use static HTML template
- Deploy to S3 + CloudFront
- Create LinkedIn company page only
- 3 employee personas

**Option B: Realistic (1 week)**
- Custom static site with Hugo/Jekyll
- Full LinkedIn presence (company + 5 employees)
- GitHub organization with repos
- Twitter account
- All information leakage points

**Option C: Full MVP (2 weeks)**
- Everything in Option B
- Google Business Profile
- Crunchbase listing
- Phone number setup
- Email actually works (AWS SES)
- More polished content

---

## Files Needed to Start

If you want to begin implementation, I can generate:

1. **HTML templates** (index, about, team, services, contact)
2. **Terraform config** for AWS infrastructure
3. **Employee personas** (names, bios, photos)
4. **Content** (company description, service descriptions, blog posts)
5. **Setup scripts** (DNS, email, etc.)

Let me know which option you prefer and I'll start building it out.
