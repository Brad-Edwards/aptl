-- TechVault Solutions Seed Data
-- Passwords use MD5 (intentionally weak for testing - vulnerability)
-- Real app would use bcrypt/argon2

-- Admin user: admin / admin123 (weak admin creds - vulnerability)
INSERT INTO users (username, email, password_hash, role, department, api_key) VALUES
('admin', 'admin@techvault.local', md5('admin123'), 'admin', 'IT', 'tvk_admin_a1b2c3d4e5f6g7h8i9j0'),
('sarah.mitchell', 'sarah.mitchell@techvault.local', md5('S3cur3C30!'), 'admin', 'Executive', 'tvk_ceo_k1l2m3n4o5p6q7r8s9t0'),
('james.rodriguez', 'james.rodriguez@techvault.local', md5('R0dr1gu3z#CTO'), 'admin', 'Executive', NULL),
('emily.chen', 'emily.chen@techvault.local', md5('DevOps#2024'), 'user', 'Engineering', 'tvk_dev_u1v2w3x4y5z6a7b8c9d0'),
('michael.thompson', 'michael.thompson@techvault.local', md5('Summer2024'), 'user', 'Engineering', NULL),
('david.kim', 'david.kim@techvault.local', md5('K1mS3c!Eng'), 'user', 'Engineering', NULL),
('jessica.williams', 'jessica.williams@techvault.local', md5('password123'), 'user', 'Operations', NULL),
('robert.martinez', 'robert.martinez@techvault.local', md5('M@rketing2024'), 'user', 'Sales', NULL),
('svc-web', 'svc-web@techvault.local', md5('WebApp2024'), 'service', 'IT', 'tvk_svc_e1f2g3h4i5j6k7l8m9n0'),
('contractor.temp', 'contractor@techvault.local', md5('Welcome1!'), 'user', 'Engineering', NULL)
ON CONFLICT (username) DO NOTHING;

-- Customer data (realistic but fictional)
INSERT INTO customers (company_name, contact_name, contact_email, phone, plan_tier, monthly_revenue) VALUES
('Meridian Financial Group', 'Tom Harrison', 'tom@meridianfg.com', '(555) 234-5678', 'enterprise', 4500.00),
('Apex Manufacturing', 'Linda Chen', 'linda.chen@apexmfg.com', '(555) 345-6789', 'professional', 2200.00),
('Coastal Healthcare Systems', 'Dr. Maria Santos', 'msantos@coastalhealth.org', '(555) 456-7890', 'enterprise', 6800.00),
('NorthStar Logistics', 'Kevin O''Brien', 'kobrien@northstarlog.com', '(555) 567-8901', 'basic', 800.00),
('Summit Education Corp', 'Patricia Kumar', 'pkumar@summitedu.com', '(555) 678-9012', 'professional', 1500.00),
('Redwood Legal Partners', 'James Wright', 'jwright@redwoodlegal.com', '(555) 789-0123', 'enterprise', 5200.00),
('Atlas Consulting Group', 'Rachel Fernandez', 'rfernandez@atlascg.com', '(555) 890-1234', 'basic', 600.00),
('Pinnacle Insurance', 'Steve Morrison', 'smorrison@pinnacleins.com', '(555) 901-2345', 'professional', 3100.00)
ON CONFLICT DO NOTHING;

-- Backup config with exposed AWS credentials (vulnerability)
INSERT INTO backup_config (backup_type, s3_bucket, aws_access_key, aws_secret_key, schedule, is_active) VALUES
('full', 'techvault-backups-prod', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '0 2 * * *', true),
('incremental', 'techvault-backups-prod', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '0 */6 * * *', true)
ON CONFLICT DO NOTHING;

-- Some audit log entries
INSERT INTO audit_log (user_id, action, resource, ip_address) VALUES
(1, 'login', '/auth/login', '172.20.1.20'),
(1, 'view', '/admin/users', '172.20.1.20'),
(4, 'upload', '/files/upload', '172.20.2.20'),
(5, 'login', '/auth/login', '172.20.2.20'),
(7, 'login_failed', '/auth/login', '172.20.1.20')
ON CONFLICT DO NOTHING;

-- API keys table
INSERT INTO api_keys (user_id, key_hash, key_prefix, description, permissions) VALUES
(1, md5('tvk_admin_a1b2c3d4e5f6g7h8i9j0'), 'tvk_admi', 'Admin API key', 'read,write,admin'),
(2, md5('tvk_ceo_k1l2m3n4o5p6q7r8s9t0'), 'tvk_ceo_', 'CEO dashboard key', 'read'),
(4, md5('tvk_dev_u1v2w3x4y5z6a7b8c9d0'), 'tvk_dev_', 'CI/CD pipeline key', 'read,write'),
(9, md5('tvk_svc_e1f2g3h4i5j6k7l8m9n0'), 'tvk_svc_', 'Web service key', 'read,write')
ON CONFLICT DO NOTHING;

-- Comments (some with stored XSS payloads for testing detection)
INSERT INTO comments (user_id, content, page) VALUES
(5, 'Great new feature in the dashboard!', '/dashboard'),
(7, 'Can we get a dark mode option?', '/dashboard'),
(4, 'Deployed new build v2.4.1 to staging', '/releases')
ON CONFLICT DO NOTHING;
