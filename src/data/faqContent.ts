export interface FAQItem {
  id: string;
  question: string;
  answer: string;
  category: 'common' | 'misconfig' | 'quirks' | 'interview';
  cloudProvider?: 'AWS' | 'Azure' | 'GCP' | 'All';
  tags: string[];
  relatedControlIds?: string[];
}

export const faqContent: FAQItem[] = [
  // COMMON AUDIT QUESTIONS
  {
    id: 'common-1',
    question: 'How do I start a cloud security audit?',
    answer: `**Pre-Audit Phase:**
1. Define scope (which cloud accounts, services, regions)
2. Gather necessary credentials and access permissions
3. Select the audit framework (CIS, ISO 27001, SOC 2, etc.)
4. Review previous audit reports if available

**Execution Phase:**
1. Use the Guided Audit mode for step-by-step process
2. Document findings with evidence (screenshots, logs)
3. Prioritize findings by severity

**Post-Audit:**
1. Create remediation recommendations
2. Present findings to stakeholders
3. Schedule follow-up review`,
    category: 'common',
    cloudProvider: 'All',
    tags: ['getting-started', 'audit-process', 'methodology']
  },
  {
    id: 'common-2',
    question: 'What credentials/access do I need for a cloud audit?',
    answer: `**AWS:**
- ReadOnly IAM role or SecurityAudit managed policy
- Access to CloudTrail, Config, and IAM consoles
- CLI access with appropriate credentials

**Azure:**
- Reader role at subscription level minimum
- Security Reader for Microsoft Defender
- Access to Azure AD for identity review

**GCP:**
- Viewer role at organization/project level
- Security Reviewer role for security findings
- Access to Cloud Asset Inventory

**Best Practice:** Use temporary, time-limited credentials and document all access granted.`,
    category: 'common',
    cloudProvider: 'All',
    tags: ['access', 'credentials', 'permissions', 'iam']
  },
  {
    id: 'common-3',
    question: 'How long does a typical cloud security audit take?',
    answer: `**Factors affecting duration:**
- Number of cloud accounts/subscriptions
- Number of services in scope
- Complexity of the environment
- Depth of audit required

**Typical timelines:**
- Small environment (1-2 accounts, basic services): 1-2 weeks
- Medium environment (5-10 accounts, multiple services): 3-4 weeks
- Large enterprise (50+ accounts, multi-cloud): 6-8 weeks

**Time breakdown:**
- Planning & scoping: 10-15%
- Data collection & testing: 50-60%
- Analysis & documentation: 25-30%
- Reporting & presentation: 10-15%`,
    category: 'common',
    cloudProvider: 'All',
    tags: ['timeline', 'planning', 'scope']
  },
  {
    id: 'common-4',
    question: 'What is the difference between CIS Benchmarks and ISO 27001?',
    answer: `**CIS Benchmarks:**
- Technical, prescriptive controls
- Cloud-provider specific (separate for AWS, Azure, GCP)
- Free and publicly available
- Focus: "How to configure securely"
- Easily automated and measurable

**ISO 27001:**
- Management system standard
- Technology-agnostic
- Requires certification audit
- Focus: "What security processes to have"
- Broader scope including policies, procedures

**When to use which:**
- CIS: Technical security hardening, baseline configurations
- ISO 27001: Compliance requirements, security program maturity
- Both can be used together for comprehensive coverage`,
    category: 'common',
    cloudProvider: 'All',
    tags: ['frameworks', 'cis', 'iso-27001', 'compliance']
  },
  {
    id: 'common-5',
    question: 'What evidence should I collect during an audit?',
    answer: `**Configuration Evidence:**
- Screenshots of security settings
- Exported policies (JSON/YAML)
- CLI command outputs
- API responses

**Log Evidence:**
- CloudTrail/Activity Logs exports
- Access logs samples
- Audit trail exports

**Documentation Evidence:**
- Security policies and procedures
- Architecture diagrams
- Previous audit reports
- Incident response plans

**Best Practices:**
- Use consistent naming conventions
- Include timestamps on all evidence
- Store securely with appropriate access controls
- Maintain chain of custody documentation`,
    category: 'common',
    cloudProvider: 'All',
    tags: ['evidence', 'documentation', 'audit-trail']
  },
  {
    id: 'common-6',
    question: 'How do I prioritize audit findings?',
    answer: `**Severity Factors:**
1. **Exploitability** - How easy is it to exploit?
2. **Impact** - What's the potential damage?
3. **Exposure** - Is it internet-facing?
4. **Data sensitivity** - What data is at risk?

**Priority Matrix:**
- **Critical:** Immediate action required (public data exposure, no MFA on root)
- **High:** Address within 1 week (overly permissive IAM, disabled logging)
- **Medium:** Address within 1 month (non-compliant configurations)
- **Low:** Address in next quarter (best practice improvements)

**Quick Wins:**
Prioritize items that are high-impact but easy to fix first.`,
    category: 'common',
    cloudProvider: 'All',
    tags: ['prioritization', 'severity', 'risk-assessment']
  },

  // MISCONFIGURATION GUIDANCE
  {
    id: 'misconfig-s3-public',
    question: 'What if I find a publicly accessible S3 bucket?',
    answer: `**Immediate Actions:**
1. Document the finding with screenshots
2. Check bucket policy and ACLs for public access grants
3. Identify what data is exposed (PII, credentials, backups?)

**Risk Assessment:**
- Review S3 access logs for unauthorized access
- Check for sensitive file types (.env, .pem, database dumps)
- Assess data classification level

**Remediation Steps:**
1. Enable S3 Block Public Access at account level
2. Review and update bucket policies
3. Remove public ACL grants
4. Enable S3 access logging
5. Consider enabling S3 Object Lock for critical data

**Prevention:**
- Enable AWS Config rules for S3 public access
- Use Service Control Policies to prevent public buckets`,
    category: 'misconfig',
    cloudProvider: 'AWS',
    tags: ['s3', 'public-access', 'data-exposure', 'storage'],
    relatedControlIds: ['CIS-AWS-2.1.1', 'CIS-AWS-2.1.2']
  },
  {
    id: 'misconfig-root-no-mfa',
    question: 'What if root account has no MFA enabled?',
    answer: `**Severity: CRITICAL**

**Immediate Actions:**
1. Escalate to account owner immediately
2. Document current state with evidence
3. Check CloudTrail for root account usage

**Risk Assessment:**
- Root account has unrestricted access
- Cannot be limited by IAM policies
- Single point of compromise for entire account

**Remediation Steps:**
1. Enable MFA on root account immediately
2. Use hardware MFA token (preferred) or virtual MFA
3. Store MFA device securely (separate from password)
4. Document MFA recovery procedures

**Best Practices:**
- Never use root for daily operations
- Set up billing alerts on root
- Enable root account activity alerts in CloudWatch`,
    category: 'misconfig',
    cloudProvider: 'AWS',
    tags: ['root-account', 'mfa', 'authentication', 'critical'],
    relatedControlIds: ['CIS-AWS-1.5', 'CIS-AWS-1.6']
  },
  {
    id: 'misconfig-iam-overpermissive',
    question: 'What if I find overly permissive IAM policies?',
    answer: `**Common Issues:**
- Policies with "Action": "*" and "Resource": "*"
- Unused permissions (permission creep)
- Inline policies instead of managed policies

**Assessment Steps:**
1. Use IAM Access Analyzer to identify unused access
2. Review last accessed information for services
3. Check for cross-account access grants

**Remediation Approach:**
1. Identify minimum required permissions
2. Create new least-privilege policy
3. Test in non-production first
4. Apply and monitor for access issues

**Tools:**
- AWS IAM Access Analyzer
- Azure AD Access Reviews
- GCP IAM Recommender

**Prevention:**
- Implement regular access reviews
- Use permission boundaries
- Enforce tagging for policy owners`,
    category: 'misconfig',
    cloudProvider: 'All',
    tags: ['iam', 'permissions', 'least-privilege', 'access-control'],
    relatedControlIds: ['CIS-AWS-1.16', 'CIS-Azure-1.21']
  },
  {
    id: 'misconfig-logging-disabled',
    question: 'What if logging is disabled or incomplete?',
    answer: `**Impact:**
- No visibility into security events
- Cannot investigate incidents
- Compliance failures

**What to Check:**
- CloudTrail (AWS) / Activity Logs (Azure) / Audit Logs (GCP)
- VPC Flow Logs / NSG Flow Logs
- Application and access logs
- DNS query logging

**Remediation by Provider:**

**AWS:**
- Enable CloudTrail in all regions
- Enable multi-region trail
- Enable log file validation
- Store in separate account (recommended)

**Azure:**
- Enable Activity Log export
- Configure Diagnostic Settings
- Enable NSG Flow Logs

**GCP:**
- Enable Data Access audit logs
- Configure log sinks
- Enable VPC Flow Logs

**Retention:** Ensure logs are retained for compliance requirements (typically 1-7 years)`,
    category: 'misconfig',
    cloudProvider: 'All',
    tags: ['logging', 'monitoring', 'cloudtrail', 'audit-logs'],
    relatedControlIds: ['CIS-AWS-3.1', 'CIS-Azure-5.1.1']
  },
  {
    id: 'misconfig-encryption-disabled',
    question: 'What if I find unencrypted data at rest?',
    answer: `**Common Locations:**
- Storage buckets/blobs
- Database instances
- EBS volumes / Managed disks
- Backups and snapshots

**Risk Assessment:**
- What data is stored unencrypted?
- Who has physical/logical access?
- Compliance requirements (HIPAA, PCI, GDPR)

**Remediation by Service:**

**Storage:**
- Enable default encryption (SSE-S3, Azure Storage encryption)
- Use customer-managed keys for sensitive data

**Databases:**
- Enable TDE (Transparent Data Encryption)
- Encrypt existing databases (may require migration)

**Block Storage:**
- New volumes: Enable encryption by default
- Existing volumes: Create encrypted snapshot, restore to new volume

**Important:** Some encryption changes require data migration - plan carefully!`,
    category: 'misconfig',
    cloudProvider: 'All',
    tags: ['encryption', 'data-at-rest', 'storage', 'compliance'],
    relatedControlIds: ['CIS-AWS-2.1.1', 'CIS-Azure-4.1.1']
  },
  {
    id: 'misconfig-security-groups',
    question: 'What if I find overly permissive security groups?',
    answer: `**Critical Findings:**
- 0.0.0.0/0 on SSH (22) or RDP (3389)
- 0.0.0.0/0 on database ports (3306, 5432, 1433)
- "All traffic" rules from any source

**Assessment:**
1. Identify what resources use the security group
2. Check if resources are actually internet-facing
3. Review need for the open ports

**Remediation:**
1. Restrict to specific IP ranges or security groups
2. Use bastion hosts/jump servers for admin access
3. Implement VPN or AWS Systems Manager Session Manager
4. Remove unused rules

**Quick Wins:**
- Enable VPC Flow Logs to understand traffic patterns
- Use AWS Firewall Manager or Azure Firewall for centralized management

**Prevention:**
- Use infrastructure as code with security reviews
- Implement automated security group auditing`,
    category: 'misconfig',
    cloudProvider: 'All',
    tags: ['security-groups', 'network', 'firewall', 'nsg'],
    relatedControlIds: ['CIS-AWS-5.2', 'CIS-Azure-6.1']
  },
  {
    id: 'misconfig-public-ip',
    question: 'What if I find resources with unnecessary public IPs?',
    answer: `**Risk:**
- Increased attack surface
- Direct exposure to internet threats
- Potential for data exfiltration

**Assessment:**
1. List all public IPs in the environment
2. Identify purpose of each public IP
3. Determine if public access is required

**Resources That Often Don't Need Public IPs:**
- Database servers
- Application servers (use load balancer)
- Internal tools and admin interfaces
- Backup storage

**Remediation Options:**
1. Remove public IP if not needed
2. Use NAT Gateway for outbound-only access
3. Place behind load balancer or API gateway
4. Use Private Link / Private Endpoints
5. Implement VPN or Direct Connect

**Documentation:**
Create inventory of justified public IPs with business justification`,
    category: 'misconfig',
    cloudProvider: 'All',
    tags: ['public-ip', 'network', 'exposure', 'attack-surface']
  },
  {
    id: 'misconfig-secrets-hardcoded',
    question: 'What if I find hardcoded secrets or credentials?',
    answer: `**Severity: HIGH/CRITICAL**

**Common Locations:**
- Environment variables in plain text
- Configuration files in repositories
- Lambda/Function environment variables
- Container image layers
- CloudFormation/Terraform templates

**Immediate Actions:**
1. Rotate the exposed credentials immediately
2. Check for unauthorized usage of the credentials
3. Document the exposure timeline

**Remediation:**
1. Remove secrets from code/config
2. Use secrets management service:
   - AWS Secrets Manager / Parameter Store
   - Azure Key Vault
   - GCP Secret Manager
3. Update application to fetch secrets at runtime
4. Scan repositories for historical secrets

**Prevention:**
- Pre-commit hooks with secret scanning
- CI/CD secret scanning
- Regular repository scanning with tools like truffleHog, git-secrets`,
    category: 'misconfig',
    cloudProvider: 'All',
    tags: ['secrets', 'credentials', 'hardcoded', 'security'],
    relatedControlIds: ['CIS-AWS-1.20']
  },

  // CLOUD-SPECIFIC QUIRKS
  {
    id: 'quirk-aws-regions',
    question: 'AWS: Why do some regions not support all services?',
    answer: `**Reason:**
AWS launches new services in select regions first, then expands globally over time.

**Impact on Audits:**
- Some security services may not be available
- GuardDuty, Security Hub availability varies
- Some compliance programs limited to specific regions

**Workarounds:**
1. Check AWS Regional Services List before auditing
2. Use centralized security services where possible
3. Document regional limitations in audit scope

**Common Gaps:**
- Newer AI/ML services often US-only initially
- Some compliance features (GovCloud, China) are isolated
- Wavelength and Outposts have different service availability

**Best Practice:**
Include a region availability check in your audit planning phase.`,
    category: 'quirks',
    cloudProvider: 'AWS',
    tags: ['regions', 'service-availability', 'planning']
  },
  {
    id: 'quirk-azure-subscriptions',
    question: 'Azure: How do I handle multiple subscriptions?',
    answer: `**Azure Hierarchy:**
Management Groups → Subscriptions → Resource Groups → Resources

**Audit Approach:**
1. Get list of all subscriptions under management groups
2. Check if Azure Policies are applied at management group level
3. Review subscription-level settings individually

**Common Pitfalls:**
- Orphaned subscriptions outside management groups
- Inconsistent policies across subscriptions
- Different Azure AD tenants (more complex)

**Tools:**
- Azure Resource Graph for cross-subscription queries
- Azure Policy for compliance assessment
- Microsoft Defender for Cloud for security posture

**CLI Tips:**
\`\`\`bash
# List all subscriptions
az account list --output table

# Set subscription context
az account set --subscription "subscription-name"
\`\`\`

**Best Practice:**
Create a matrix of subscriptions vs. security controls for systematic review.`,
    category: 'quirks',
    cloudProvider: 'Azure',
    tags: ['subscriptions', 'management-groups', 'hierarchy']
  },
  {
    id: 'quirk-gcp-projects',
    question: 'GCP: What is the difference between projects and folders?',
    answer: `**GCP Hierarchy:**
Organization → Folders → Projects → Resources

**Projects:**
- Container for resources
- Billing boundary
- IAM boundary
- Required for all resources

**Folders:**
- Organizational grouping
- Policy inheritance
- Can nest up to 10 levels
- Optional but recommended

**Audit Implications:**
- Policies can be set at org, folder, or project level
- IAM bindings inherit down the hierarchy
- Check for policy exceptions at lower levels

**Common Issues:**
- Projects outside folder structure
- Inconsistent naming conventions
- Shadow IT projects

**CLI for Discovery:**
\`\`\`bash
# List all projects
gcloud projects list

# List folders
gcloud resource-manager folders list --organization=ORG_ID
\`\`\``,
    category: 'quirks',
    cloudProvider: 'GCP',
    tags: ['projects', 'folders', 'organization', 'hierarchy']
  },
  {
    id: 'quirk-shared-responsibility',
    question: 'What is the shared responsibility model and how does it affect audits?',
    answer: `**Core Concept:**
Cloud provider secures "of" the cloud; customer secures "in" the cloud.

**Provider Responsibility:**
- Physical security
- Network infrastructure
- Hypervisor security
- Managed service infrastructure

**Customer Responsibility:**
- Data encryption and classification
- Identity and access management
- Network controls (security groups, NACLs)
- Application security
- OS patching (for IaaS)

**Audit Focus:**
Only audit what you're responsible for. Request provider certifications (SOC 2, ISO 27001) for their responsibilities.

**Varies by Service Type:**
- **IaaS (EC2/VMs):** Customer manages OS and above
- **PaaS (RDS/App Service):** Customer manages data and access
- **SaaS (S3/Blob):** Customer manages data and access policies

**Documentation:**
Include shared responsibility boundaries in audit scope.`,
    category: 'quirks',
    cloudProvider: 'All',
    tags: ['shared-responsibility', 'scope', 'provider-responsibility']
  },
  {
    id: 'quirk-eventual-consistency',
    question: 'How does eventual consistency affect security audits?',
    answer: `**What is it?**
Cloud control plane changes may take time to propagate globally.

**Impact on Audits:**
- IAM policy changes may not be immediately effective
- DNS and CDN changes can take minutes to hours
- Replication across regions has delay

**Examples:**
- S3 bucket policy changes: Usually immediate, but can take minutes
- IAM policy changes: Typically <1 minute
- Azure AD changes: Can take up to 30 minutes
- GCP IAM: Can take up to 7 minutes

**Audit Best Practices:**
1. Wait appropriate time after changes before testing
2. Test from multiple locations/regions
3. Document the time gap between change and verification
4. Re-test critical controls at end of audit

**Why it matters:**
A control may appear compliant during audit but not be fully enforced yet.`,
    category: 'quirks',
    cloudProvider: 'All',
    tags: ['eventual-consistency', 'propagation', 'timing']
  },
  {
    id: 'quirk-service-limits',
    question: 'How do cloud service limits affect security?',
    answer: `**Security-Relevant Limits:**

**AWS:**
- CloudTrail: 5 trails per region (can affect logging coverage)
- Security Groups: 2,500 per VPC (rule limit per SG)
- IAM: 5,000 roles per account

**Azure:**
- NSG rules: 1,000 per NSG
- Azure Policy assignments: 200 per scope
- Key Vault: 500 keys per vault

**GCP:**
- Firewall rules: 500 per VPC
- IAM bindings: 1,500 per policy

**Audit Considerations:**
1. Check if limits are being approached
2. Verify workarounds don't bypass security
3. Document limit-related architectural decisions

**Common Issues:**
- Consolidated security groups due to limits
- Shared service accounts to avoid IAM limits
- Reduced logging due to storage costs

**Request increases when needed for security requirements.`,
    category: 'quirks',
    cloudProvider: 'All',
    tags: ['service-limits', 'quotas', 'architecture']
  },
  {
    id: 'quirk-default-settings',
    question: 'What dangerous default settings should I always check?',
    answer: `**AWS:**
- EBS volumes: Not encrypted by default
- S3 buckets: Block Public Access off by default (older accounts)
- RDS: Not encrypted by default
- Default VPC: Often has permissive settings

**Azure:**
- Storage accounts: Allow public blob access by default
- SQL Database: Not always TDE enabled by default
- VMs: May have public IP assigned

**GCP:**
- Compute instances: Default service account with broad permissions
- Cloud Storage: Uniform bucket-level access not default
- APIs: Many disabled but easily enabled

**Audit Checklist:**
1. Run default configuration checks first
2. Compare against CIS Level 1 benchmarks
3. Check for account-level defaults that should be set

**Recommendation:**
Create a "first day" security baseline that addresses all dangerous defaults.`,
    category: 'quirks',
    cloudProvider: 'All',
    tags: ['defaults', 'hardening', 'baseline']
  },

  // INTERVIEW/DISCUSSION POINTS
  {
    id: 'interview-admin-questions',
    question: 'Key questions to ask cloud administrators?',
    answer: `**Access Management:**
- How do you provision and deprovision access?
- What's your process for access reviews?
- How do you handle privileged access?

**Change Management:**
- How are changes deployed to production?
- What approval process exists for infrastructure changes?
- How do you track changes?

**Incident Response:**
- What's your process when a security incident occurs?
- When was the last security incident?
- How do you detect security anomalies?

**Monitoring & Logging:**
- Where are logs centralized?
- How long are logs retained?
- Who reviews logs and how often?

**Backup & Recovery:**
- What's your backup strategy?
- When did you last test disaster recovery?
- What's your RTO/RPO?

**Compliance:**
- What compliance frameworks do you follow?
- How do you track compliance status?
- Who is responsible for compliance?`,
    category: 'interview',
    cloudProvider: 'All',
    tags: ['interview', 'administrators', 'questions']
  },
  {
    id: 'interview-security-culture',
    question: 'How to assess security culture during an audit?',
    answer: `**Observable Indicators:**

**Positive Signs:**
- Security training is regular and tracked
- Team members can explain security controls
- Security is discussed in architecture decisions
- Incidents are treated as learning opportunities
- Security team is involved early in projects

**Warning Signs:**
- "Security slows us down" attitude
- No security representation in development
- Exceptions are common and long-standing
- Security findings from previous audits not addressed
- Blame culture around security incidents

**Questions to Assess:**
1. "Tell me about your last security incident"
2. "How does security fit into your development process?"
3. "What security training have you completed recently?"
4. "Who do you go to with security questions?"

**Documentation:**
Include qualitative observations about security culture in your audit report. It often predicts future security posture.`,
    category: 'interview',
    cloudProvider: 'All',
    tags: ['culture', 'assessment', 'organizational']
  },
  {
    id: 'interview-red-flags',
    question: 'Red flags to watch for during audit interviews?',
    answer: `**Process Red Flags:**
- "We don't have time for that"
- "We've always done it this way"
- "That's not my responsibility"
- "We trust our developers"
- "We'll fix it after launch"

**Technical Red Flags:**
- Shared credentials among team members
- No documentation of infrastructure
- Manual processes for critical operations
- No separation of environments
- Production access for all developers

**Organizational Red Flags:**
- Security team is understaffed or absent
- No executive sponsor for security
- Security budget is non-existent
- Previous audit findings not addressed
- No security incident history (may mean no detection)

**What to Do:**
1. Document observations objectively
2. Ask follow-up questions to understand context
3. Include in findings with appropriate severity
4. Provide constructive recommendations

**Remember:** Red flags are symptoms - look for root causes.`,
    category: 'interview',
    cloudProvider: 'All',
    tags: ['red-flags', 'warning-signs', 'assessment']
  },
  {
    id: 'interview-evidence-collection',
    question: 'Best practices for evidence collection during interviews?',
    answer: `**Preparation:**
- Prepare question list in advance
- Review previous audit findings
- Understand the environment beforehand
- Have evidence collection tools ready

**During Interview:**
1. Ask permission before recording/screenshots
2. Take notes with timestamps
3. Verify understanding by summarizing
4. Request documentation to be shared

**Evidence Types:**
- **Verbal statements:** Note who said what, when
- **Demonstrations:** Record or screenshot with permission
- **Documents:** Request copies, note versions
- **System outputs:** CLI commands with full output

**Chain of Custody:**
- Date and time of collection
- Source of evidence
- Who collected it
- How it was stored

**Post-Interview:**
1. Send summary to interviewee for confirmation
2. Organize evidence by control/finding
3. Secure storage with appropriate access
4. Cross-reference with technical findings`,
    category: 'interview',
    cloudProvider: 'All',
    tags: ['evidence', 'documentation', 'best-practices']
  },
  {
    id: 'interview-scope-discussions',
    question: 'How to handle scope discussions and pushback?',
    answer: `**Common Pushback:**
- "That system is out of scope"
- "We don't have access to that"
- "That's managed by another team"
- "We can't share that information"

**Response Strategies:**

**For "Out of Scope":**
1. Refer to audit charter/agreement
2. Explain risk if excluded
3. Document the exclusion formally
4. Get written acknowledgment

**For "No Access":**
1. Explain minimum access needed
2. Offer alternative approaches (read-only, paired review)
3. Document access limitations
4. Note impact on audit coverage

**For "Another Team":**
1. Request introduction/contact
2. Schedule separate interview
3. Document communication chain

**Documentation:**
Always document scope limitations and their impact on audit conclusions.

**Escalation:**
If pushback is unreasonable, escalate to audit sponsor with documented attempts and impact.`,
    category: 'interview',
    cloudProvider: 'All',
    tags: ['scope', 'pushback', 'negotiation']
  },
  {
    id: 'interview-reporting',
    question: 'How to present findings to different audiences?',
    answer: `**Executive Summary (C-Level):**
- Business risk focus, not technical details
- Financial impact if quantifiable
- Comparison to industry/peers
- 1-2 pages maximum
- Clear action items with owners

**Technical Report (IT/Security Teams):**
- Detailed findings with evidence
- Step-by-step remediation
- Affected systems and scope
- Technical severity ratings
- Timeline for remediation

**Compliance Report (Auditors/Regulators):**
- Mapped to framework requirements
- Pass/fail/partial status
- Evidence references
- Gap analysis
- Remediation status

**Presentation Tips:**
1. Lead with most critical findings
2. Provide context for severity
3. Offer realistic remediation timelines
4. Highlight quick wins
5. Be prepared for questions

**Follow-Up:**
- Schedule remediation review
- Provide remediation support
- Track closure of findings`,
    category: 'interview',
    cloudProvider: 'All',
    tags: ['reporting', 'presentation', 'communication']
  }
];

export const faqCategories = [
  { id: 'all', icon: 'HelpCircle' },
  { id: 'common', icon: 'HelpCircle' },
  { id: 'misconfig', icon: 'AlertTriangle' },
  { id: 'quirks', icon: 'Zap' },
  { id: 'interview', icon: 'Users' }
] as const;
