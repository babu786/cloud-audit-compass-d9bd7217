// Centralized content source for audit controls and awareness content
// Update this file to modify audit guidance without code changes

export interface AuditControl {
  id: string;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  cloudProvider: 'AWS' | 'Azure' | 'GCP';
  framework: 'CIS Benchmark' | 'ISO 27001' | 'Internal Baseline';
  category: string;
  whatToCheck: string;
  whyItMatters: string;
  consoleSteps: string[];
  cliCheck?: string;
  expectedConfig: string;
  commonMisconfigs: string[];
  fixHint: string;
}

export interface AwarenessArticle {
  id: string;
  title: string;
  category: 'Weekly Awareness' | 'Misconfigurations' | 'Best Practices' | 'Audit Tips';
  summary: string;
  content: string;
  date: string;
}

export const cloudProviders = [
  { id: 'AWS', name: 'Amazon Web Services', icon: 'Cloud', description: 'AWS cloud infrastructure security controls' },
  { id: 'Azure', name: 'Microsoft Azure', icon: 'Server', description: 'Azure cloud platform security guidance' },
  { id: 'GCP', name: 'Google Cloud Platform', icon: 'Database', description: 'GCP security best practices and controls' },
] as const;

export const frameworks = [
  { id: 'CIS Benchmark', name: 'CIS Benchmark', description: 'Center for Internet Security benchmarks' },
  { id: 'ISO 27001', name: 'ISO 27001 Mapping', description: 'ISO 27001 security standard mapping' },
  { id: 'Internal Baseline', name: 'Internal Baseline', description: 'Organization-specific security baseline' },
] as const;

export const serviceCategories = [
  { id: 'iam', name: 'Identity & Access Management', icon: 'Shield' },
  { id: 'network', name: 'Network Security', icon: 'Network' },
  { id: 'logging', name: 'Logging & Monitoring', icon: 'Activity' },
  { id: 'storage', name: 'Storage Security', icon: 'HardDrive' },
  { id: 'compute', name: 'Compute Security', icon: 'Cpu' },
  { id: 'encryption', name: 'Encryption & Key Management', icon: 'Lock' },
] as const;

export const auditControls: AuditControl[] = [
  {
    id: 'AWS-IAM-001',
    title: 'Ensure MFA is enabled for the root account',
    severity: 'Critical',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that Multi-Factor Authentication (MFA) is enabled for the AWS root account.',
    whyItMatters: 'The root account has unrestricted access to all resources. Compromising the root account without MFA could lead to complete account takeover.',
    consoleSteps: [
      'Sign in to the AWS Management Console as the root user',
      'Navigate to IAM Dashboard',
      'Look for "Security Status" section',
      'Verify "MFA for root account" shows a green checkmark',
    ],
    cliCheck: 'aws iam get-account-summary | grep AccountMFAEnabled',
    expectedConfig: 'AccountMFAEnabled should return 1',
    commonMisconfigs: [
      'MFA not configured at all',
      'Virtual MFA device lost or inaccessible',
      'Hardware MFA token not properly synchronized',
    ],
    fixHint: 'Enable virtual MFA using an authenticator app or hardware MFA device through IAM console security credentials.',
  },
  {
    id: 'AWS-IAM-002',
    title: 'Ensure IAM password policy requires minimum length of 14',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify the IAM password policy enforces a minimum password length of at least 14 characters.',
    whyItMatters: 'Longer passwords exponentially increase the difficulty of brute-force attacks and password guessing attempts.',
    consoleSteps: [
      'Navigate to IAM Console',
      'Select "Account settings" from the left menu',
      'Review the Password policy section',
      'Confirm minimum password length is set to 14 or higher',
    ],
    cliCheck: 'aws iam get-account-password-policy',
    expectedConfig: 'MinimumPasswordLength should be 14 or greater',
    commonMisconfigs: [
      'Default password policy with 8 character minimum',
      'Password policy not configured at all',
    ],
    fixHint: 'Update the password policy via IAM > Account settings > Password policy to set minimum length to 14.',
  },
  {
    id: 'AWS-NET-001',
    title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify no security groups allow unrestricted SSH access from the internet.',
    whyItMatters: 'Unrestricted SSH access exposes instances to brute-force attacks and potential unauthorized access.',
    consoleSteps: [
      'Navigate to EC2 Console > Security Groups',
      'Review each security group\'s inbound rules',
      'Look for rules allowing port 22 from 0.0.0.0/0 or ::/0',
      'Document any violations found',
    ],
    cliCheck: 'aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values="0.0.0.0/0"',
    expectedConfig: 'No security groups should be returned',
    commonMisconfigs: [
      'Default security groups with open SSH',
      'Development security groups left open',
      'Overly permissive bastion host rules',
    ],
    fixHint: 'Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager for instance access.',
  },
  {
    id: 'AWS-LOG-001',
    title: 'Ensure CloudTrail is enabled in all regions',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify CloudTrail is configured to log API activity across all AWS regions.',
    whyItMatters: 'CloudTrail provides audit logs essential for security analysis, compliance, and incident response.',
    consoleSteps: [
      'Navigate to CloudTrail Console',
      'Select "Trails" from the left menu',
      'Verify at least one trail exists with "Multi-region trail" set to Yes',
      'Confirm the trail is logging and not stopped',
    ],
    cliCheck: 'aws cloudtrail describe-trails --query "trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail}"',
    expectedConfig: 'At least one trail with IsMultiRegionTrail: true',
    commonMisconfigs: [
      'CloudTrail only enabled in primary region',
      'Trail logging stopped due to S3 bucket issues',
      'Trail not capturing management events',
    ],
    fixHint: 'Create a multi-region trail or update existing trail to enable multi-region logging.',
  },
  {
    id: 'AWS-STR-001',
    title: 'Ensure S3 bucket access logging is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify server access logging is enabled for all S3 buckets containing sensitive data.',
    whyItMatters: 'Access logs provide detailed records of requests made to S3 buckets for security auditing and forensics.',
    consoleSteps: [
      'Navigate to S3 Console',
      'Select a bucket to review',
      'Go to Properties tab',
      'Check "Server access logging" section',
      'Verify logging is enabled with a target bucket configured',
    ],
    cliCheck: 'aws s3api get-bucket-logging --bucket BUCKET_NAME',
    expectedConfig: 'LoggingEnabled with TargetBucket and TargetPrefix configured',
    commonMisconfigs: [
      'Access logging disabled by default',
      'Logging bucket in different region causing issues',
      'Target prefix not set causing log organization issues',
    ],
    fixHint: 'Enable server access logging in bucket properties and specify a target bucket for log delivery.',
  },
  {
    id: 'AWS-ENC-001',
    title: 'Ensure EBS volumes are encrypted at rest',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify all EBS volumes are encrypted using AWS KMS keys.',
    whyItMatters: 'Encryption at rest protects data from unauthorized access if physical storage media is compromised.',
    consoleSteps: [
      'Navigate to EC2 Console > Volumes',
      'Review the "Encryption" column for each volume',
      'Filter by "Not Encrypted" to find violations',
      'Check EC2 Settings for "Always encrypt new EBS volumes"',
    ],
    cliCheck: 'aws ec2 describe-volumes --query "Volumes[?Encrypted==`false`].VolumeId"',
    expectedConfig: 'Empty array (no unencrypted volumes)',
    commonMisconfigs: [
      'Legacy volumes created before encryption default',
      'Volumes created from unencrypted snapshots',
      'Default encryption not enabled at account level',
    ],
    fixHint: 'Enable default EBS encryption in EC2 Settings and migrate unencrypted volumes by creating encrypted snapshots.',
  },
  {
    id: 'Azure-IAM-001',
    title: 'Ensure MFA is enabled for all privileged users',
    severity: 'Critical',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that Multi-Factor Authentication is enforced for all users with privileged roles.',
    whyItMatters: 'Privileged accounts are high-value targets. MFA significantly reduces the risk of account compromise.',
    consoleSteps: [
      'Navigate to Azure Active Directory',
      'Select "Security" > "MFA"',
      'Review per-user MFA settings',
      'Verify Conditional Access policies enforce MFA for admins',
    ],
    cliCheck: 'az ad user list --query "[?userType==\'Member\'].{UPN:userPrincipalName}"',
    expectedConfig: 'All privileged users should have MFA enforced via Conditional Access',
    commonMisconfigs: [
      'MFA only enabled for Global Admins',
      'Break-glass accounts without MFA policy exclusion documentation',
      'Conditional Access policies not covering all admin roles',
    ],
    fixHint: 'Create Conditional Access policies requiring MFA for all directory roles.',
  },
  {
    id: 'GCP-IAM-001',
    title: 'Ensure corporate login credentials are used',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify all users authenticate using corporate/organizational credentials rather than personal Gmail accounts.',
    whyItMatters: 'Corporate credentials enable centralized identity management, access reviews, and security policy enforcement.',
    consoleSteps: [
      'Navigate to IAM & Admin > IAM',
      'Review member list for any @gmail.com addresses',
      'Check for service accounts with excessive permissions',
      'Verify Organization Policy for domain restriction',
    ],
    cliCheck: 'gcloud projects get-iam-policy PROJECT_ID --format=json | grep -i gmail',
    expectedConfig: 'No personal Gmail accounts in IAM policy',
    commonMisconfigs: [
      'Developer personal accounts used during initial setup',
      'External contractors using personal Gmail',
      'Service accounts shared across teams',
    ],
    fixHint: 'Remove personal accounts and add users via Cloud Identity or Workspace managed domains.',
  },
];

export const awarenessArticles: AwarenessArticle[] = [
  {
    id: 'weekly-001',
    title: 'The Rise of Cloud-Native Ransomware',
    category: 'Weekly Awareness',
    summary: 'Understanding how attackers are adapting ransomware tactics specifically for cloud environments.',
    content: `Cloud-native ransomware represents a significant evolution in cyber threats. Unlike traditional ransomware that encrypts local files, these attacks target cloud storage, databases, and backups directly.

**Key Attack Vectors:**
- Compromised IAM credentials with excessive permissions
- Misconfigured storage buckets with public write access
- Exposed API keys in code repositories
- Insufficient backup isolation

**Protection Strategies:**
1. Implement least privilege access for all identities
2. Enable versioning and MFA delete on storage
3. Maintain air-gapped or immutable backups
4. Use cloud-native threat detection services`,
    date: '2024-01-15',
  },
  {
    id: 'misconfig-001',
    title: 'Top 5 S3 Bucket Misconfigurations',
    category: 'Misconfigurations',
    summary: 'The most common S3 security mistakes and how to identify them during audits.',
    content: `S3 buckets remain one of the most misconfigured cloud resources. Here are the top issues to check:

**1. Public Access Enabled**
- Block Public Access settings disabled
- Bucket policies allowing * principal

**2. Missing Encryption**
- Default encryption not configured
- Objects uploaded without SSE headers

**3. Inadequate Logging**
- Server access logging disabled
- CloudTrail data events not captured

**4. Weak Bucket Policies**
- Overly permissive resource policies
- Missing condition keys for IP/VPC restrictions

**5. Version Control Issues**
- Versioning disabled on critical buckets
- MFA Delete not enabled`,
    date: '2024-01-10',
  },
  {
    id: 'bestpractice-001',
    title: 'Zero Trust Architecture in Cloud Environments',
    category: 'Best Practices',
    summary: 'Implementing zero trust principles across AWS, Azure, and GCP workloads.',
    content: `Zero Trust is not a product but an architecture approach. In cloud environments, this means:

**Identity-Centric Security**
- Verify every access request regardless of source
- Use short-lived credentials and just-in-time access
- Implement continuous authentication

**Micro-Segmentation**
- Isolate workloads with VPCs and security groups
- Use private endpoints for service communication
- Implement service mesh for workload identity

**Continuous Monitoring**
- Enable all available logging
- Implement real-time threat detection
- Automate response to security events`,
    date: '2024-01-08',
  },
  {
    id: 'tips-001',
    title: 'Audit Efficiency: CLI Commands Every Auditor Should Know',
    category: 'Audit Tips',
    summary: 'Essential command-line techniques to speed up your cloud security assessments.',
    content: `Master these CLI patterns to accelerate your audits:

**AWS Quick Checks:**
\`\`\`bash
# Find all public S3 buckets
aws s3api list-buckets --query "Buckets[].Name" | xargs -I {} aws s3api get-public-access-block --bucket {}

# List unencrypted EBS volumes
aws ec2 describe-volumes --query "Volumes[?!Encrypted].VolumeId"

# Find security groups with 0.0.0.0/0
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values='0.0.0.0/0'
\`\`\`

**Pro Tips:**
- Use --output table for readable results
- Pipe to jq for complex filtering
- Create aliases for frequently used commands
- Document your findings with timestamps`,
    date: '2024-01-05',
  },
];
