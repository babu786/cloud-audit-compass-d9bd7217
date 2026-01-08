// Centralized content source for audit controls and awareness content
// Based on official CIS Benchmarks:
// - CIS Amazon Web Services Foundations Benchmark v6.0.0
// - CIS Microsoft Azure Compute Services Benchmark v2.0.0
// - CIS Google Cloud Platform Foundation Benchmark v4.0.0

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
  imageUrl?: string;
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
  // ============================================
  // AWS CONTROLS - CIS AWS Foundations v6.0.0
  // ============================================
  
  // IAM Controls
  {
    id: 'CIS-AWS-2.1',
    title: 'Maintain current contact details',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Ensure contact email and telephone details for AWS accounts are current and map to more than one individual in your organization.',
    whyItMatters: 'If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic.',
    consoleSteps: [
      'Sign in to the AWS Management Console',
      'Open the Billing and Cost Management console',
      'On the navigation bar, choose your account name, then Account',
      'Review and verify the current contact details under Contact Information',
    ],
    cliCheck: 'aws account get-contact-information',
    expectedConfig: 'Contact information should point to shared aliases or group contacts, not individual emails',
    commonMisconfigs: [
      'Contact details reference a single individual',
      'Email addresses point to personal accounts rather than group aliases',
      'Phone numbers are for individuals who may be unavailable',
    ],
    fixHint: 'Update contact details to use group email aliases and PABX hunt groups instead of individual contacts.',
  },
  {
    id: 'CIS-AWS-2.2',
    title: 'Ensure security contact information is registered',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that security-specific contact information is registered for the AWS account.',
    whyItMatters: 'Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them.',
    consoleSteps: [
      'Click on your account name at the top right corner of the console',
      'From the drop-down menu, click My Account',
      'Scroll down to the Alternate Contacts section',
      'Ensure contact information is specified in the Security section',
    ],
    cliCheck: 'aws account get-alternate-contact --alternate-contact-type SECURITY',
    expectedConfig: 'Security contact should be configured with valid email and phone',
    commonMisconfigs: [
      'No alternate security contact configured',
      'Security contact uses personal email instead of distribution list',
      'Contact information is outdated',
    ],
    fixHint: 'Add security contact via Account Settings > Alternate Contacts. Use an internal email distribution list to ensure emails are monitored by more than one individual.',
  },
  {
    id: 'CIS-AWS-2.3',
    title: 'Ensure no root user account access key exists',
    severity: 'Critical',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that all access keys associated with the root user account have been deleted.',
    whyItMatters: 'The root user account is the most privileged user in an AWS account. Deleting access keys associated with the root user limits vectors by which the account can be compromised and encourages the creation and use of role-based accounts that are least privileged.',
    consoleSteps: [
      'Login to the AWS Management Console',
      'Click Services, then IAM',
      'Click on Credential Report and download it',
      'For the <root_account> user, ensure access_key_1_active and access_key_2_active are set to FALSE',
    ],
    cliCheck: 'aws iam get-account-summary | grep "AccountAccessKeysPresent"',
    expectedConfig: '"AccountAccessKeysPresent": 0',
    commonMisconfigs: [
      'Root access keys created during initial account setup',
      'Legacy access keys not properly decommissioned',
      'Access keys created for automation that should use IAM roles instead',
    ],
    fixHint: 'Sign in as root, navigate to My Security Credentials, and delete any active access keys. Use IAM users or roles for programmatic access instead.',
  },
  {
    id: 'CIS-AWS-2.4',
    title: 'Ensure MFA is enabled for the root user account',
    severity: 'Critical',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that Multi-Factor Authentication (MFA) is enabled for the AWS root account.',
    whyItMatters: 'The root user account has unrestricted access to all resources. MFA adds an extra layer of protection requiring the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential.',
    consoleSteps: [
      'Login to the AWS Management Console',
      'Click Services, then IAM',
      'Click on Credential Report and download it',
      'For the <root_account> user, ensure the mfa_active field is set to TRUE',
    ],
    cliCheck: 'aws iam get-account-summary | grep "AccountMFAEnabled"',
    expectedConfig: '"AccountMFAEnabled": 1',
    commonMisconfigs: [
      'MFA not configured at all',
      'Virtual MFA device on personal device that could be lost',
      'MFA device not properly synchronized',
    ],
    fixHint: 'Enable virtual MFA using an authenticator app or hardware MFA device. Use a dedicated device (not personal) kept charged and secured.',
  },
  {
    id: 'CIS-AWS-2.5',
    title: 'Ensure hardware MFA is enabled for the root user account',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that a hardware MFA device is enabled for the root user account (Level 2).',
    whyItMatters: 'A hardware MFA has a smaller attack surface than a virtual MFA. It does not suffer the attack surface introduced by the mobile smartphone on which a virtual MFA resides.',
    consoleSteps: [
      'Run: aws iam get-account-summary | grep "AccountMFAEnabled"',
      'Verify AccountMFAEnabled is set to 1',
      'Run: aws iam list-virtual-mfa-devices',
      'Ensure no virtual MFA with SerialNumber containing "root-account-mfa-device" exists',
    ],
    cliCheck: 'aws iam list-virtual-mfa-devices',
    expectedConfig: 'No virtual MFA device for root account (hardware MFA should be used instead)',
    commonMisconfigs: [
      'Using virtual MFA instead of hardware MFA',
      'Hardware MFA token not properly synchronized',
      'No backup security keys configured',
    ],
    fixHint: 'Purchase a FIDO security key or hardware TOTP token. Configure via Security Credentials > Assign MFA device. Keep backup keys secured.',
  },
  {
    id: 'CIS-AWS-2.6',
    title: 'Eliminate use of the root user for administrative and daily tasks',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that the root user account is not used for everyday administrative tasks.',
    whyItMatters: 'The root user has unrestricted access to and control over all resources in the AWS account. Use of it is inconsistent with the principles of least privilege and separation of duties, and can lead to unnecessary harm due to error or compromised credentials.',
    consoleSteps: [
      'Login to the AWS Management Console',
      'Click Services, then IAM',
      'Click on Credential Report and download it',
      'For the <root_account> user, check password_last_used and access_key_1_last_used_date',
      'Ensure root usage is minimal and only for root-specific tasks',
    ],
    cliCheck: 'aws iam generate-credential-report && aws iam get-credential-report --query "Content" --output text | base64 -d | grep "<root_account>"',
    expectedConfig: 'Root account should have minimal or no recent usage; password_last_used should be old or N/A',
    commonMisconfigs: [
      'Root account used for daily administrative tasks',
      'Root credentials shared among team members',
      'Root account used for programmatic access',
    ],
    fixHint: 'Create IAM users with appropriate permissions for daily tasks. Reserve root only for tasks that specifically require root privileges (like changing account settings).',
  },
  {
    id: 'CIS-AWS-2.7',
    title: 'Ensure IAM password policy requires minimum length of 14 or greater',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify the IAM password policy enforces a minimum password length of at least 14 characters.',
    whyItMatters: 'Setting a password complexity policy increases account resiliency against brute force login attempts. Longer passwords exponentially increase the difficulty of brute-force attacks.',
    consoleSteps: [
      'Navigate to IAM Console',
      'Select "Account settings" from the left menu',
      'Review the Password policy section',
      'Confirm minimum password length is set to 14 or higher',
    ],
    cliCheck: 'aws iam get-account-password-policy',
    expectedConfig: '"MinimumPasswordLength": 14 or greater',
    commonMisconfigs: [
      'Default password policy with 8 character minimum',
      'Password policy not configured at all',
      'Minimum length set below 14 characters',
    ],
    fixHint: 'Update the password policy via IAM > Account settings > Password policy to set minimum length to 14.',
  },
  {
    id: 'CIS-AWS-2.8',
    title: 'Ensure IAM password policy prevents password reuse',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify the IAM password policy prevents the reuse of passwords by remembering the last 24 passwords.',
    whyItMatters: 'Preventing password reuse increases account resiliency against brute force login attempts. If an old password is compromised, it cannot be reused to gain access.',
    consoleSteps: [
      'Login to AWS Console',
      'Go to IAM Service',
      'Select Account Settings on the Left Pane',
      'Check "Prevent password reuse" is enabled',
      'Verify "Number of passwords to remember" is set to 24',
    ],
    cliCheck: 'aws iam get-account-password-policy',
    expectedConfig: '"PasswordReusePrevention": 24',
    commonMisconfigs: [
      'Password reuse prevention not configured',
      'Number of remembered passwords set too low',
      'Policy configured but not enforced',
    ],
    fixHint: 'Run: aws iam update-account-password-policy --password-reuse-prevention 24',
  },
  {
    id: 'CIS-AWS-2.9',
    title: 'Ensure MFA is enabled for all IAM users with console password',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that Multi-Factor Authentication is enabled for all IAM users that have a console password.',
    whyItMatters: 'Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that displays a time-sensitive key and have knowledge of a credential.',
    consoleSteps: [
      'Open the IAM console',
      'In the left pane, select Users',
      'Ensure MFA and Password age columns are visible',
      'For each user with a password age, verify MFA shows Virtual, U2F Security Key, or Hardware',
    ],
    cliCheck: 'aws iam generate-credential-report && aws iam get-credential-report --query "Content" --output text | base64 -d | cut -d, -f1,4,8',
    expectedConfig: 'For all users with password_enabled=true, mfa_active should also be true',
    commonMisconfigs: [
      'MFA not enabled for console users',
      'MFA only required for some users, not all',
      'SMS MFA used instead of app-based or hardware MFA',
    ],
    fixHint: 'Navigate to IAM > Users > Security Credentials > Manage MFA Device. Enable virtual or hardware MFA for each user with console access.',
  },
  {
    id: 'CIS-AWS-2.11',
    title: 'Ensure credentials unused for 45 days or more are disabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that IAM credentials (passwords and access keys) unused for 45 days or more are disabled.',
    whyItMatters: 'Unused credentials pose a security risk as they may belong to former employees or for deprecated use cases, and if compromised, provide unauthorized access.',
    consoleSteps: [
      'Open the IAM console',
      'Generate and download the Credential Report',
      'Review password_last_used and access_key_last_used_date columns',
      'Identify any credentials not used in 45+ days',
    ],
    cliCheck: 'aws iam generate-credential-report && aws iam get-credential-report --query "Content" --output text | base64 -d',
    expectedConfig: 'No credentials with last_used date older than 45 days should be active',
    commonMisconfigs: [
      'Credentials for former employees still active',
      'Service account credentials never rotated or reviewed',
      'Test accounts left active after project completion',
    ],
    fixHint: 'Disable or delete unused credentials. For users: deactivate access keys or delete passwords. Implement regular credential reviews.',
  },
  {
    id: 'CIS-AWS-2.13',
    title: 'Ensure access keys are rotated every 90 days or less',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that access keys are rotated within 90 days.',
    whyItMatters: 'Rotating access keys reduces the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Access keys should be rotated to ensure that data cannot be accessed with an old key.',
    consoleSteps: [
      'Open the IAM console',
      'Click on Users in the left pane',
      'For each user, check the Access key age column',
      'Ensure no active keys are older than 90 days',
    ],
    cliCheck: 'aws iam list-access-keys --user-name <username>',
    expectedConfig: 'All access keys should have CreateDate within the last 90 days',
    commonMisconfigs: [
      'Access keys never rotated since creation',
      'No automated rotation process in place',
      'Old keys not deactivated after rotation',
    ],
    fixHint: 'Create new access keys, update applications to use new keys, then deactivate and delete old keys. Implement automated rotation.',
  },
  {
    id: 'CIS-AWS-2.15',
    title: 'Ensure IAM policies with full administrative privileges are not attached',
    severity: 'Critical',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that no IAM policies allow full "*:*" administrative privileges.',
    whyItMatters: 'Providing full administrative privileges instead of least privilege increases the risk of over-permissioned access and potential for misuse or compromise.',
    consoleSteps: [
      'Navigate to IAM Console',
      'Select Policies from the left menu',
      'Search for policies with Effect: Allow and Action: * and Resource: *',
      'Verify no custom policies grant full admin access',
    ],
    cliCheck: 'aws iam list-policies --only-attached --query "Policies[*].Arn" --output text | xargs -I {} aws iam get-policy-version --policy-arn {} --version-id v1',
    expectedConfig: 'No policies should have Effect: Allow with Action: * and Resource: *',
    commonMisconfigs: [
      'Custom policies created with full admin access',
      'AdministratorAccess attached to too many users/roles',
      'Policies with * actions on * resources',
    ],
    fixHint: 'Remove full administrative policies and replace with least-privilege policies that only grant necessary permissions.',
  },

  // Network Security Controls
  {
    id: 'CIS-AWS-6.2',
    title: 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to admin ports',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (22, 3389).',
    whyItMatters: 'Allowing unrestricted ingress access to administrative ports exposes servers to brute-force attacks, vulnerability exploitation, and unauthorized access from any internet source.',
    consoleSteps: [
      'Navigate to VPC Console > Network ACLs',
      'Review inbound rules for each NACL',
      'Look for rules allowing ports 22 or 3389 from 0.0.0.0/0 or ::/0',
      'Document any violations found',
    ],
    cliCheck: 'aws ec2 describe-network-acls --query "NetworkAcls[*].Entries[?CidrBlock==\'0.0.0.0/0\' && RuleAction==\'allow\']"',
    expectedConfig: 'No NACL rules should allow 0.0.0.0/0 to ports 22 or 3389',
    commonMisconfigs: [
      'Default NACLs with open rules',
      'NACL rules too permissive for development',
      'Rules added for troubleshooting not removed',
    ],
    fixHint: 'Modify NACL rules to restrict SSH/RDP access to specific IP ranges. Use AWS Systems Manager Session Manager as an alternative.',
  },
  {
    id: 'CIS-AWS-6.3',
    title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify no security groups allow unrestricted SSH (port 22) or RDP (port 3389) access from the internet.',
    whyItMatters: 'Unrestricted inbound access to administrative ports exposes instances to brute-force attacks and potential unauthorized access from anywhere on the internet.',
    consoleSteps: [
      'Navigate to EC2 Console > Security Groups',
      'Review each security group\'s inbound rules',
      'Look for rules allowing port 22 or 3389 from 0.0.0.0/0 or ::/0',
      'Document any violations found',
    ],
    cliCheck: 'aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values="0.0.0.0/0"',
    expectedConfig: 'No security groups should be returned',
    commonMisconfigs: [
      'Default security groups with open SSH',
      'Development security groups left open',
      'Overly permissive bastion host rules',
    ],
    fixHint: 'Restrict SSH/RDP access to specific IP ranges or use AWS Systems Manager Session Manager for instance access.',
  },
  {
    id: 'CIS-AWS-6.5',
    title: 'Ensure the default security group restricts all traffic',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that the default security group of every VPC restricts all inbound and outbound traffic.',
    whyItMatters: 'The default security group is often overlooked during security hardening. Resources accidentally assigned to it may inherit overly permissive rules.',
    consoleSteps: [
      'Navigate to VPC Console > Security Groups',
      'Filter for security groups named "default"',
      'For each default security group, verify no inbound or outbound rules exist',
    ],
    cliCheck: 'aws ec2 describe-security-groups --filters Name=group-name,Values="default" --query "SecurityGroups[*].{GroupId:GroupId, IpPermissions:IpPermissions, IpPermissionsEgress:IpPermissionsEgress}"',
    expectedConfig: 'Default security groups should have no inbound or outbound rules',
    commonMisconfigs: [
      'Default SG still has default allow-all-egress rule',
      'Inbound rules added to default SG for convenience',
      'Resources using default SG instead of purpose-built SGs',
    ],
    fixHint: 'Remove all inbound and outbound rules from default security groups. Create purpose-specific security groups for resources.',
  },
  {
    id: 'CIS-AWS-6.7',
    title: 'Ensure EC2 Metadata Service only allows IMDSv2',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify that EC2 instances are configured to require IMDSv2 (Instance Metadata Service Version 2).',
    whyItMatters: 'IMDSv1 is vulnerable to SSRF attacks that can be used to steal instance credentials. IMDSv2 requires session tokens and provides better protection against these attacks.',
    consoleSteps: [
      'Navigate to EC2 Console > Instances',
      'Select an instance and view Details',
      'Check "IMDSv2" setting under Instance metadata options',
      'Verify it shows "Required" not "Optional"',
    ],
    cliCheck: 'aws ec2 describe-instances --query "Reservations[*].Instances[*].{InstanceId:InstanceId,MetadataOptions:MetadataOptions}"',
    expectedConfig: 'HttpTokens should be "required" for all instances',
    commonMisconfigs: [
      'IMDSv2 not enforced (HttpTokens: optional)',
      'Legacy instances not updated to require IMDSv2',
      'Launch templates using IMDSv1',
    ],
    fixHint: 'Modify instance metadata options to require IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required',
  },

  // Logging & Monitoring Controls
  {
    id: 'CIS-AWS-4.1',
    title: 'Ensure CloudTrail is enabled in all regions',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify CloudTrail is configured to log API activity across all AWS regions.',
    whyItMatters: 'CloudTrail provides audit logs essential for security analysis, compliance, and incident response. Multi-region trails ensure visibility across all regions where resources might be created.',
    consoleSteps: [
      'Navigate to CloudTrail Console',
      'Select "Trails" from the left menu',
      'Verify at least one trail exists with "Multi-region trail" set to Yes',
      'Confirm the trail is logging and not stopped',
    ],
    cliCheck: 'aws cloudtrail describe-trails --query "trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail}"',
    expectedConfig: 'At least one trail with IsMultiRegionTrail: true and IsLogging: true',
    commonMisconfigs: [
      'CloudTrail only enabled in primary region',
      'Trail logging stopped due to S3 bucket issues',
      'Trail not capturing management events',
    ],
    fixHint: 'Create a multi-region trail or update existing trail: aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail',
  },
  {
    id: 'CIS-AWS-4.3',
    title: 'Ensure CloudTrail log file integrity validation is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify that CloudTrail log file validation is enabled for all trails.',
    whyItMatters: 'Log file validation creates a digitally signed digest file that can be used to determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it.',
    consoleSteps: [
      'Navigate to CloudTrail Console',
      'Select "Trails" and click on each trail',
      'Under "General details", verify "Log file validation" is Enabled',
    ],
    cliCheck: 'aws cloudtrail describe-trails --query "trailList[*].{Name:Name,LogFileValidationEnabled:LogFileValidationEnabled}"',
    expectedConfig: 'LogFileValidationEnabled: true for all trails',
    commonMisconfigs: [
      'Log file validation disabled by default',
      'Validation not enabled on legacy trails',
      'Digest files not being stored properly',
    ],
    fixHint: 'Enable log file validation: aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation',
  },
  {
    id: 'CIS-AWS-5.16',
    title: 'Ensure AWS Security Hub is enabled',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify that AWS Security Hub is enabled and configured in all regions.',
    whyItMatters: 'Security Hub provides a comprehensive view of security alerts and security posture across AWS accounts. It aggregates, organizes, and prioritizes security findings from multiple AWS services.',
    consoleSteps: [
      'Navigate to Security Hub Console',
      'Verify Security Hub is enabled',
      'Check that relevant security standards are enabled (CIS AWS Foundations)',
      'Review integrations with other AWS services',
    ],
    cliCheck: 'aws securityhub describe-hub',
    expectedConfig: 'Security Hub should be enabled with CIS AWS Foundations Benchmark standard active',
    commonMisconfigs: [
      'Security Hub not enabled',
      'Security standards not enabled',
      'Findings not being reviewed or actioned',
    ],
    fixHint: 'Enable Security Hub via console or CLI: aws securityhub enable-security-hub --enable-default-standards',
  },

  // Storage Security Controls
  {
    id: 'CIS-AWS-3.1.1',
    title: 'Ensure S3 Bucket Policy is set to deny HTTP requests',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify that S3 bucket policies deny non-HTTPS requests.',
    whyItMatters: 'Without HTTPS enforcement, data transmitted to/from S3 buckets can be intercepted. Bucket policies should explicitly deny requests that are not made over TLS.',
    consoleSteps: [
      'Navigate to S3 Console',
      'Select a bucket and go to Permissions tab',
      'Review Bucket Policy',
      'Verify a policy exists with Condition: aws:SecureTransport = false and Effect: Deny',
    ],
    cliCheck: 'aws s3api get-bucket-policy --bucket <bucket-name>',
    expectedConfig: 'Policy should include: {"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}',
    commonMisconfigs: [
      'No bucket policy requiring HTTPS',
      'Policy exists but condition is incorrect',
      'Policy not applied to all relevant buckets',
    ],
    fixHint: 'Add a bucket policy statement denying requests where aws:SecureTransport is false.',
  },
  {
    id: 'CIS-AWS-3.3',
    title: 'Ensure S3 bucket access logging is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify server access logging is enabled for all S3 buckets containing sensitive data.',
    whyItMatters: 'Access logs provide detailed records of requests made to S3 buckets for security auditing, forensics, and compliance.',
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

  // Encryption Controls
  {
    id: 'CIS-AWS-6.1.1',
    title: 'Ensure EBS volume encryption is enabled in all regions',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify that EBS encryption by default is enabled in all regions.',
    whyItMatters: 'Enabling encryption at rest for EBS volumes protects data from unauthorized access if physical storage media is compromised or volumes are incorrectly configured.',
    consoleSteps: [
      'Navigate to EC2 Console',
      'Go to EC2 Dashboard > Account Attributes > EBS Encryption',
      'Verify "Always encrypt new EBS volumes" is enabled',
      'Repeat for all regions in use',
    ],
    cliCheck: 'aws ec2 get-ebs-encryption-by-default --region <region>',
    expectedConfig: 'EbsEncryptionByDefault: true in all regions',
    commonMisconfigs: [
      'EBS encryption not enabled by default',
      'Only enabled in primary region',
      'Using default AWS managed key instead of CMK',
    ],
    fixHint: 'Enable EBS encryption by default: aws ec2 enable-ebs-encryption-by-default --region <region>',
  },

  // ============================================
  // AZURE CONTROLS - CIS Azure Compute v2.0.0
  // ============================================
  
  {
    id: 'CIS-Azure-2.1.1',
    title: 'Ensure Java version is currently supported (App Service)',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify that App Service apps using Java are running a currently supported version.',
    whyItMatters: 'Deprecated and unsupported versions of programming languages can present vulnerabilities which may not be addressed or may not be addressable.',
    consoleSteps: [
      'Go to App Services',
      'Click the name of an app',
      'Under Settings, click Configuration',
      'In General settings, verify Java Major and Minor Version are supported',
      'Check java.oracle.com for current supported versions',
    ],
    cliCheck: 'az webapp config show --resource-group <rg> --name <app> --query "{LinuxFxVersion:linuxFxVersion,JavaVersion:javaVersion}"',
    expectedConfig: 'Java version should be a currently supported release per Oracle support roadmap',
    commonMisconfigs: [
      'Running end-of-life Java versions',
      'Not using auto-update for Java web server',
      'Version not updated after initial deployment',
    ],
    fixHint: 'Update Java version via Portal > App Service > Configuration > General settings, or use: az webapp config set --java-version',
  },
  {
    id: 'CIS-Azure-2.1.4',
    title: 'Ensure Basic Authentication Publishing Credentials are Disabled',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that basic authentication publishing credentials are disabled for App Services.',
    whyItMatters: 'Basic authentication uses username and password which can be guessed or leaked. Disabling it forces the use of more secure authentication methods.',
    consoleSteps: [
      'Go to App Services',
      'Click the name of an app',
      'Under Settings, click Configuration',
      'Go to General settings',
      'Ensure "Basic Auth Publishing Credentials" is set to Off',
    ],
    cliCheck: 'az webapp deployment list-publishing-credentials --resource-group <rg> --name <app>',
    expectedConfig: 'Basic authentication should be disabled; use Azure AD or managed identity instead',
    commonMisconfigs: [
      'Basic auth enabled for legacy deployment pipelines',
      'Publishing credentials shared among team members',
      'FTP deployment using basic auth',
    ],
    fixHint: 'Disable basic auth via Portal or use: az resource update --set properties.basicPublishingCredentialsPolicies.scm.allow=false',
  },
  {
    id: 'CIS-Azure-2.1.7',
    title: 'Ensure HTTPS Only is set to On (App Service)',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that App Service apps are configured to only allow HTTPS connections.',
    whyItMatters: 'HTTPS ensures data in transit is encrypted. Without HTTPS-only mode, users can access the app over unencrypted HTTP, exposing sensitive data.',
    consoleSteps: [
      'Go to App Services',
      'Click the name of an app',
      'Under Settings, click Configuration',
      'In General settings, verify HTTPS Only is set to On',
    ],
    cliCheck: 'az webapp show --resource-group <rg> --name <app> --query httpsOnly',
    expectedConfig: 'httpsOnly: true',
    commonMisconfigs: [
      'HTTPS Only not enabled',
      'HTTP allowed for legacy integrations',
      'Mixed content issues after enabling HTTPS',
    ],
    fixHint: 'Enable HTTPS Only via Portal or: az webapp update --resource-group <rg> --name <app> --set httpsOnly=true',
  },
  {
    id: 'CIS-Azure-2.1.8',
    title: 'Ensure Minimum TLS Version is set to 1.2 or higher',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify that the minimum inbound TLS version for App Services is set to 1.2 or higher.',
    whyItMatters: 'TLS 1.0 and 1.1 have known vulnerabilities. Using TLS 1.2+ ensures encrypted connections use secure cryptographic protocols.',
    consoleSteps: [
      'Go to App Services',
      'Click the name of an app',
      'Under Settings, click TLS/SSL settings',
      'Verify Minimum TLS Version is set to 1.2 or higher',
    ],
    cliCheck: 'az webapp config show --resource-group <rg> --name <app> --query minTlsVersion',
    expectedConfig: 'minTlsVersion: 1.2 or higher',
    commonMisconfigs: [
      'TLS 1.0 or 1.1 still allowed',
      'Default TLS settings not reviewed',
      'Legacy clients requiring older TLS versions',
    ],
    fixHint: 'Set minimum TLS version via Portal or: az webapp config set --min-tls-version 1.2',
  },
  {
    id: 'CIS-Azure-2.1.10',
    title: 'Ensure Remote debugging is set to Off',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify that remote debugging is disabled for App Services.',
    whyItMatters: 'Remote debugging opens additional ports and can expose sensitive information. It should only be enabled temporarily for troubleshooting and disabled in production.',
    consoleSteps: [
      'Go to App Services',
      'Click the name of an app',
      'Under Settings, click Configuration',
      'In General settings, verify Remote debugging is Off',
    ],
    cliCheck: 'az webapp config show --resource-group <rg> --name <app> --query remoteDebuggingEnabled',
    expectedConfig: 'remoteDebuggingEnabled: false',
    commonMisconfigs: [
      'Remote debugging left enabled after troubleshooting',
      'Enabled in production environments',
      'Debug ports exposed to the internet',
    ],
    fixHint: 'Disable remote debugging via Portal or: az webapp config set --remote-debugging-enabled false',
  },
  {
    id: 'CIS-Azure-2.1.14',
    title: 'Ensure public network access is disabled (App Service)',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that public network access is disabled for App Services, using private endpoints instead.',
    whyItMatters: 'Disabling public access reduces the attack surface by ensuring the app is only accessible via private networks or approved private endpoints.',
    consoleSteps: [
      'Go to App Services',
      'Click the name of an app',
      'Under Settings, click Networking',
      'Verify Public network access is set to Disabled',
      'Confirm private endpoints are configured',
    ],
    cliCheck: 'az webapp config access-restriction show --resource-group <rg> --name <app>',
    expectedConfig: 'Public network access should be disabled with private endpoints configured',
    commonMisconfigs: [
      'Public access enabled for convenience',
      'No private endpoints configured',
      'Access restrictions not properly configured',
    ],
    fixHint: 'Disable public access and configure private endpoints via Portal or Azure CLI.',
  },
  {
    id: 'CIS-Azure-20.2',
    title: 'Ensure OS and Data disks are encrypted with CMK',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify that OS and Data disks are encrypted with Customer Managed Keys (CMK).',
    whyItMatters: 'Using customer-managed keys for disk encryption provides more control over the encryption keys and enables additional security requirements like key rotation policies.',
    consoleSteps: [
      'Go to Virtual Machines',
      'Select a VM and click on Disks',
      'For each disk, verify Encryption type shows "Encryption at-rest with a customer-managed key"',
    ],
    cliCheck: 'az disk show --resource-group <rg> --name <disk> --query encryption',
    expectedConfig: 'Encryption type should be EncryptionAtRestWithCustomerKey',
    commonMisconfigs: [
      'Using platform-managed keys instead of CMK',
      'Encryption not enabled on all disks',
      'Key vault not properly configured',
    ],
    fixHint: 'Create a disk encryption set with CMK and apply to VM disks during creation or via disk update.',
  },
  {
    id: 'CIS-Azure-20.10',
    title: 'Ensure Trusted Launch is enabled on Virtual Machines',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify that Trusted Launch is enabled on Virtual Machines for enhanced security.',
    whyItMatters: 'Trusted Launch protects against advanced persistent threats by enabling Secure Boot and vTPM, protecting against bootkits, rootkits, and boot-time attacks.',
    consoleSteps: [
      'Go to Virtual Machines',
      'Select a VM',
      'Under Settings, go to Configuration',
      'Verify Security type shows "Trusted launch"',
      'Confirm Secure Boot and vTPM are enabled',
    ],
    cliCheck: 'az vm show --resource-group <rg> --name <vm> --query securityProfile',
    expectedConfig: 'securityType: TrustedLaunch with secureBootEnabled and vTpmEnabled set to true',
    commonMisconfigs: [
      'VMs created without Trusted Launch',
      'Legacy VMs not supporting Trusted Launch',
      'Secure Boot disabled for compatibility',
    ],
    fixHint: 'Create new VMs with Trusted Launch enabled. Existing VMs may need to be recreated to enable this feature.',
  },

  // ============================================
  // GCP CONTROLS - CIS GCP Foundation v4.0.0
  // ============================================
  
  {
    id: 'CIS-GCP-1.1',
    title: 'Ensure that Corporate Login Credentials are Used',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify all users authenticate using corporate/organizational credentials rather than personal Gmail accounts.',
    whyItMatters: 'Corporate credentials enable centralized identity management, access reviews, and security policy enforcement. Personal accounts bypass organizational security controls.',
    consoleSteps: [
      'Navigate to IAM & Admin > IAM',
      'Review member list for any @gmail.com addresses',
      'Check for external users with personal email accounts',
      'Verify Organization Policy for domain restriction is enabled',
    ],
    cliCheck: 'gcloud projects get-iam-policy PROJECT_ID --format=json | grep -i gmail',
    expectedConfig: 'No personal Gmail accounts in IAM policy (excluding service accounts)',
    commonMisconfigs: [
      'Developer personal accounts used during initial setup',
      'External contractors using personal Gmail',
      'Test users with personal accounts',
    ],
    fixHint: 'Remove personal accounts and add users via Cloud Identity or Workspace managed domains. Enable Domain Restricted Sharing organization policy.',
  },
  {
    id: 'CIS-GCP-1.2',
    title: 'Ensure Multi-Factor Authentication is Enabled for All Non-Service Accounts',
    severity: 'Critical',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that MFA is enabled for all non-service accounts accessing GCP.',
    whyItMatters: 'Multi-factor authentication requires more than one mechanism to authenticate a user, securing logins from attackers exploiting stolen or weak credentials.',
    consoleSteps: [
      'For each GCP project, folder, or organization, identify non-service accounts',
      'Navigate to admin.google.com (Cloud Identity/Workspace)',
      'Verify 2-Step Verification is enforced for all users',
      'Check Security > 2-Step Verification settings',
    ],
    cliCheck: 'Manual verification required in Google Admin Console',
    expectedConfig: 'All non-service accounts should have MFA enabled and enforced',
    commonMisconfigs: [
      'MFA not enforced at organization level',
      'Users allowed to skip MFA enrollment',
      'Break-glass accounts without MFA documentation',
    ],
    fixHint: 'Enforce MFA via Google Admin Console > Security > 2-Step Verification > Enforcement.',
  },
  {
    id: 'CIS-GCP-1.3',
    title: 'Ensure Security Key Enforcement is Enabled for All Admin Accounts',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that Security Key Enforcement is enabled for all Organization Administrator accounts.',
    whyItMatters: 'Organization Administrators have the highest level of privilege. Security Keys provide the strongest form of MFA, sending encrypted signatures that cannot be phished.',
    consoleSteps: [
      'Identify users with Organization Administrator role',
      'Run: gcloud organizations get-iam-policy ORGANIZATION_ID',
      'Look for roles/resourcemanager.organizationAdmin',
      'Verify Security Key Enforcement is enabled for these users in Admin Console',
    ],
    cliCheck: 'gcloud organizations get-iam-policy ORGANIZATION_ID',
    expectedConfig: 'All organization administrators should have security key enforcement enabled',
    commonMisconfigs: [
      'Security keys not required for admins',
      'No backup security keys configured',
      'Using weaker MFA methods for admin accounts',
    ],
    fixHint: 'Setup Security Key Enforcement for each admin account. Configure backup security keys.',
  },
  {
    id: 'CIS-GCP-1.4',
    title: 'Ensure Only GCP-Managed Service Account Keys Are Used',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that user-managed service accounts do not have user-managed keys.',
    whyItMatters: 'User-managed keys require manual key management (storage, distribution, rotation, revocation). Keys can be leaked through code repositories or other channels.',
    consoleSteps: [
      'Navigate to IAM & Admin > Service accounts',
      'For each service account, click to view details',
      'Check the Keys tab',
      'Ensure no user-managed keys exist',
    ],
    cliCheck: 'gcloud iam service-accounts keys list --iam-account=<service-account> --managed-by=user',
    expectedConfig: 'No user-managed keys should be listed for any service account',
    commonMisconfigs: [
      'Service account keys created for local development',
      'Keys embedded in application code',
      'Keys not rotated regularly',
    ],
    fixHint: 'Delete user-managed keys. Use Workload Identity for GKE, or default service account credentials for GCE. Enable organization policy to disable key creation.',
  },
  {
    id: 'CIS-GCP-1.5',
    title: 'Ensure Service Account Has No Admin Privileges',
    severity: 'Critical',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that no service accounts have admin, Editor, or Owner roles assigned.',
    whyItMatters: 'Service accounts represent service-level security. Granting admin rights gives full access to applications or VMs, allowing critical actions without user intervention.',
    consoleSteps: [
      'Navigate to IAM & Admin > IAM',
      'View by Principals and filter by "Service account"',
      'Look for service accounts with nomenclature: NAME@PROJECT_ID.iam.gserviceaccount.com',
      'Ensure no service accounts have *Admin, Editor, or Owner roles',
    ],
    cliCheck: 'gcloud projects get-iam-policy PROJECT_ID --format json',
    expectedConfig: 'No service accounts should have roles containing *Admin or matching Editor/Owner',
    commonMisconfigs: [
      'Default compute service account with Editor role',
      'Service accounts granted Owner for convenience',
      'Overly permissive roles for CI/CD pipelines',
    ],
    fixHint: 'Remove admin/editor/owner roles from service accounts. Assign minimum required permissions using predefined or custom roles.',
  },
  {
    id: 'CIS-GCP-1.6',
    title: 'Ensure IAM Users Are Not Assigned Service Account User Role at Project Level',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that Service Account User and Token Creator roles are assigned per service account, not at project level.',
    whyItMatters: 'Granting these roles at project level gives access to ALL service accounts in the project, including future ones. This can result in privilege escalation.',
    consoleSteps: [
      'Navigate to IAM & Admin > IAM',
      'Filter by Role: Service Account User',
      'Ensure no users are listed at project level',
      'Repeat for Role: Service Account Token Creator',
    ],
    cliCheck: 'gcloud projects get-iam-policy PROJECT_ID --format json | jq \'.bindings[].role\' | grep "roles/iam.serviceAccountUser"',
    expectedConfig: 'No output should be returned (no project-level assignments)',
    commonMisconfigs: [
      'Service Account User role granted at project level',
      'Token Creator role broadly assigned',
      'Roles granted for convenience rather than necessity',
    ],
    fixHint: 'Remove project-level role assignments and assign Service Account User/Token Creator roles on specific service accounts only.',
  },
  {
    id: 'CIS-GCP-1.7',
    title: 'Ensure Service Account Keys Are Rotated Every 90 Days',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that user-managed service account keys are rotated within 90 days.',
    whyItMatters: 'Regular key rotation limits the window of exposure if a key is compromised. Keys older than 90 days increase the risk of unauthorized access.',
    consoleSteps: [
      'Navigate to APIs & Services > Credentials',
      'Review Service account keys section',
      'Check creation date for each key',
      'Ensure no keys are older than 90 days',
    ],
    cliCheck: 'gcloud iam service-accounts keys list --iam-account=<service-account> --format="table(name,validAfterTime)"',
    expectedConfig: 'All keys should have validAfterTime within the last 90 days',
    commonMisconfigs: [
      'Keys never rotated after initial creation',
      'No automated rotation process',
      'Old keys not deleted after rotation',
    ],
    fixHint: 'Create new keys, update applications, then delete old keys. Consider using short-lived credentials instead.',
  },
  {
    id: 'CIS-GCP-1.9',
    title: 'Ensure Cloud KMS Cryptokeys Are Not Publicly Accessible',
    severity: 'Critical',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify that Cloud KMS cryptokeys do not allow access to allUsers or allAuthenticatedUsers.',
    whyItMatters: 'Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access cryptographic keys, potentially compromising encrypted data.',
    consoleSteps: [
      'Navigate to Security > Key Management',
      'For each keyring and key, review IAM permissions',
      'Ensure no bindings include allUsers or allAuthenticatedUsers',
    ],
    cliCheck: 'gcloud kms keys get-iam-policy <key_name> --keyring=<keyring> --location=<location> --format=json | jq \'.bindings[].members[]\'',
    expectedConfig: 'No allUsers or allAuthenticatedUsers in any key IAM policy',
    commonMisconfigs: [
      'Public access granted for testing',
      'allAuthenticatedUsers used instead of specific principals',
      'Inherited permissions from keyring level',
    ],
    fixHint: 'Remove public bindings: gcloud kms keys remove-iam-policy-binding <key> --member="allUsers" --role="<role>"',
  },
  {
    id: 'CIS-GCP-1.10',
    title: 'Ensure KMS Encryption Keys Are Rotated Within 90 Days',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify that Cloud KMS keys have automatic rotation configured with a period of 90 days or less.',
    whyItMatters: 'Regular key rotation limits the amount of data encrypted with a single key version. If a key is compromised, only data encrypted with that version is at risk.',
    consoleSteps: [
      'Navigate to Security > Key Management',
      'Click on each key ring, then each key',
      'Verify "Next Rotation" is set for less than 90 days from current date',
      'Confirm rotation period is configured',
    ],
    cliCheck: 'gcloud kms keys describe <key> --keyring=<keyring> --location=<location> --format="value(rotationPeriod,nextRotationTime)"',
    expectedConfig: 'rotationPeriod should be 7776000s (90 days) or less with nextRotationTime within 90 days',
    commonMisconfigs: [
      'No rotation period configured',
      'Rotation period too long (>90 days)',
      'Automatic rotation disabled',
    ],
    fixHint: 'Configure key rotation: gcloud kms keys update <key> --keyring=<keyring> --location=<location> --rotation-period=7776000s --next-rotation-time=<time>',
  },
  {
    id: 'CIS-GCP-2.1',
    title: 'Ensure Cloud Audit Logging is Configured Properly',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify that Cloud Audit Logging is enabled for all services and log types.',
    whyItMatters: 'Cloud Audit Logs maintain a trail of actions taken by users, operators, and automated processes. This is critical for security analysis and compliance.',
    consoleSteps: [
      'Navigate to IAM & Admin > Audit Logs',
      'Review the audit log configuration for each service',
      'Ensure Admin Read, Data Read, and Data Write are enabled for critical services',
    ],
    cliCheck: 'gcloud projects get-iam-policy PROJECT_ID --format=json | jq \'.auditConfigs\'',
    expectedConfig: 'auditConfigs should be present for critical services with all log types enabled',
    commonMisconfigs: [
      'Audit logging not enabled for all services',
      'Data access logging disabled',
      'Exempted users reducing visibility',
    ],
    fixHint: 'Configure audit logs via IAM & Admin > Audit Logs or using gcloud/terraform with proper auditConfigs.',
  },
  {
    id: 'CIS-GCP-3.1',
    title: 'Ensure Default Network Does Not Exist',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that the default network has been deleted from all projects.',
    whyItMatters: 'The default network has preconfigured firewall rules that are overly permissive. Deleting it ensures all network configurations are intentionally designed.',
    consoleSteps: [
      'Navigate to VPC Network > VPC networks',
      'Look for a network named "default"',
      'If it exists, delete it (ensure no resources depend on it first)',
    ],
    cliCheck: 'gcloud compute networks list --filter="name=default"',
    expectedConfig: 'No networks named "default" should exist',
    commonMisconfigs: [
      'Default network left in place for convenience',
      'Resources deployed to default network',
      'Default firewall rules not reviewed',
    ],
    fixHint: 'Delete the default network: gcloud compute networks delete default. Create custom VPC networks with proper firewall rules.',
  },
  {
    id: 'CIS-GCP-3.6',
    title: 'Ensure SSH Access Is Restricted From the Internet',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that firewall rules do not allow SSH (port 22) access from 0.0.0.0/0.',
    whyItMatters: 'Unrestricted SSH access exposes instances to brute-force attacks and potential unauthorized access from anywhere on the internet.',
    consoleSteps: [
      'Navigate to VPC Network > Firewall',
      'Review each firewall rule',
      'Look for rules allowing port 22 from 0.0.0.0/0',
      'Verify no such rules exist',
    ],
    cliCheck: 'gcloud compute firewall-rules list --format=json | jq \'.[] | select(.allowed[].ports[]? == "22" and .sourceRanges[]? == "0.0.0.0/0")\'',
    expectedConfig: 'No firewall rules should allow 0.0.0.0/0 to port 22',
    commonMisconfigs: [
      'Default allow-ssh rule from default network',
      'Development rules left in production',
      'Overly permissive source ranges',
    ],
    fixHint: 'Delete or modify rules to restrict SSH to specific IP ranges. Use Identity-Aware Proxy (IAP) for SSH access instead.',
  },
  {
    id: 'CIS-GCP-3.7',
    title: 'Ensure RDP Access Is Restricted From the Internet',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that firewall rules do not allow RDP (port 3389) access from 0.0.0.0/0.',
    whyItMatters: 'Unrestricted RDP access exposes Windows instances to brute-force attacks and exploitation of RDP vulnerabilities.',
    consoleSteps: [
      'Navigate to VPC Network > Firewall',
      'Review each firewall rule',
      'Look for rules allowing port 3389 from 0.0.0.0/0',
      'Verify no such rules exist',
    ],
    cliCheck: 'gcloud compute firewall-rules list --format=json | jq \'.[] | select(.allowed[].ports[]? == "3389" and .sourceRanges[]? == "0.0.0.0/0")\'',
    expectedConfig: 'No firewall rules should allow 0.0.0.0/0 to port 3389',
    commonMisconfigs: [
      'Default allow-rdp rule from default network',
      'Rules added for troubleshooting not removed',
      'Overly permissive source ranges',
    ],
    fixHint: 'Delete or modify rules to restrict RDP to specific IP ranges. Use Identity-Aware Proxy (IAP) for RDP access instead.',
  },
  {
    id: 'CIS-GCP-4.1',
    title: 'Ensure Instances Are Not Configured To Use Default Service Account',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify that compute instances do not use the default compute service account.',
    whyItMatters: 'The default service account has the Editor role, providing broad access. Instances should use custom service accounts with minimal required permissions.',
    consoleSteps: [
      'Navigate to Compute Engine > VM instances',
      'Click on each instance',
      'Under "API and identity management", check the service account',
      'Ensure it is not the default compute service account (PROJECT_NUMBER-compute@developer.gserviceaccount.com)',
    ],
    cliCheck: 'gcloud compute instances describe <instance> --zone=<zone> --format="value(serviceAccounts.email)"',
    expectedConfig: 'Service account should not end with -compute@developer.gserviceaccount.com',
    commonMisconfigs: [
      'Using default service account for all instances',
      'Custom service account not created',
      'Default used for quick deployments',
    ],
    fixHint: 'Create custom service accounts with minimal permissions. Assign them to instances during creation or via instance settings.',
  },
  {
    id: 'CIS-GCP-4.5',
    title: 'Ensure Enable Connecting to Serial Ports Is Not Enabled',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify that serial port access is disabled on VM instances.',
    whyItMatters: 'Serial port access provides an additional attack vector. If enabled, anyone with the right credentials could access the instance through the serial console.',
    consoleSteps: [
      'Navigate to Compute Engine > VM instances',
      'Click on each instance',
      'Under "Remote access", verify "Enable connecting to serial ports" is not checked',
    ],
    cliCheck: 'gcloud compute instances describe <instance> --zone=<zone> --format="value(metadata.items[serial-port-enable])"',
    expectedConfig: 'serial-port-enable should be false or not set',
    commonMisconfigs: [
      'Serial port enabled for debugging',
      'Enabled by default in some templates',
      'Left enabled after troubleshooting',
    ],
    fixHint: 'Disable serial port: gcloud compute instances add-metadata <instance> --metadata=serial-port-enable=FALSE',
  },
  {
    id: 'CIS-GCP-5.1',
    title: 'Ensure Cloud Storage Bucket Is Not Publicly Accessible',
    severity: 'Critical',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify that Cloud Storage buckets do not allow access to allUsers or allAuthenticatedUsers.',
    whyItMatters: 'Publicly accessible storage buckets can lead to data breaches. Sensitive data may be exposed to anyone on the internet.',
    consoleSteps: [
      'Navigate to Cloud Storage > Buckets',
      'For each bucket, click to view details',
      'Go to Permissions tab',
      'Ensure no principals include allUsers or allAuthenticatedUsers',
    ],
    cliCheck: 'gsutil iam get gs://<bucket_name>',
    expectedConfig: 'No bindings should include allUsers or allAuthenticatedUsers',
    commonMisconfigs: [
      'Public access granted for static website hosting',
      'allAuthenticatedUsers used instead of specific accounts',
      'Permissions set at object level allowing public access',
    ],
    fixHint: 'Remove public access: gsutil iam ch -d allUsers gs://<bucket>. Enable uniform bucket-level access and configure Organization Policy to prevent public access.',
  },
  {
    id: 'CIS-GCP-5.2',
    title: 'Ensure Uniform Bucket-Level Access is Enabled',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify that uniform bucket-level access is enabled for all Cloud Storage buckets.',
    whyItMatters: 'Uniform bucket-level access ensures consistent permissions across all objects in a bucket, preventing complex and error-prone ACL configurations.',
    consoleSteps: [
      'Navigate to Cloud Storage > Buckets',
      'For each bucket, click to view details',
      'Under Configuration, check Access control',
      'Verify it shows "Uniform" not "Fine-grained"',
    ],
    cliCheck: 'gsutil uniformbucketlevelaccess get gs://<bucket_name>',
    expectedConfig: 'Uniform bucket-level access: Enabled',
    commonMisconfigs: [
      'Using fine-grained access control',
      'Legacy buckets with mixed ACLs',
      'Object-level permissions inconsistent with bucket policy',
    ],
    fixHint: 'Enable uniform access: gsutil uniformbucketlevelaccess set on gs://<bucket>. Note: This cannot be reversed after 90 days.',
  },
  {
    id: 'CIS-GCP-6.4',
    title: 'Ensure Cloud SQL Database Instance Requires SSL',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify that all Cloud SQL database instances require SSL for incoming connections.',
    whyItMatters: 'Without SSL, database connections transmit data in cleartext, exposing sensitive information to potential eavesdropping.',
    consoleSteps: [
      'Navigate to SQL > Instances',
      'Click on each instance',
      'Go to Connections tab',
      'Under SSL, verify "Require SSL certificates" is enabled',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="value(settings.ipConfiguration.requireSsl)"',
    expectedConfig: 'requireSsl: true',
    commonMisconfigs: [
      'SSL not required for internal connections',
      'SSL disabled for legacy application compatibility',
      'Client certificates not properly configured',
    ],
    fixHint: 'Enable SSL requirement: gcloud sql instances patch <instance> --require-ssl',
  },
  {
    id: 'CIS-GCP-6.6',
    title: 'Ensure Cloud SQL Database Instances Do Not Have Public IPs',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify that Cloud SQL instances do not have public IP addresses assigned.',
    whyItMatters: 'Public IP addresses on database instances expose them directly to the internet, increasing the attack surface and risk of unauthorized access.',
    consoleSteps: [
      'Navigate to SQL > Instances',
      'For each instance, check IP addresses column',
      'Verify only private IP addresses are listed',
      'Confirm "Public IP" is not enabled',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="value(ipAddresses.type)"',
    expectedConfig: 'Only PRIVATE type should be listed, no PRIMARY (public) IP',
    commonMisconfigs: [
      'Public IP enabled for remote administration',
      'Private networking not configured',
      'Cloud SQL Auth proxy not used',
    ],
    fixHint: 'Remove public IP and configure private IP with VPC peering. Use Cloud SQL Auth proxy for secure connections.',
  },

  // ============================================
  // INTERNAL BASELINE CONTROLS - AWS
  // ============================================
  
  {
    id: 'INT-AWS-001',
    title: 'Enable AWS Security Hub with Baseline Score',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify AWS Security Hub is enabled and security score is maintained above enterprise baseline.',
    whyItMatters: 'Security Hub provides centralized visibility into security findings and compliance status. Low scores indicate unaddressed vulnerabilities.',
    consoleSteps: [
      'Navigate to AWS Security Hub console',
      'Check overall security score on dashboard',
      'Review findings by severity (Critical, High, Medium)',
      'Verify all High/Critical findings are addressed or have documented exceptions',
    ],
    expectedConfig: 'Security Hub enabled with score above 75%. All Critical/High findings addressed or documented.',
    commonMisconfigs: [
      'Security Hub not enabled',
      'Standards not enabled (CIS, AWS Foundational)',
      'Critical findings left unaddressed',
      'No regular review process',
    ],
    fixHint: 'Enable Security Hub and enable relevant security standards. Address Critical and High findings first. Document exceptions for findings that cannot be remediated.',
  },
  {
    id: 'INT-AWS-002',
    title: 'Separate Production and Non-Production Accounts',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify separate AWS accounts are used for production and non-production environments.',
    whyItMatters: 'Account separation provides strong blast radius containment and simplifies access control and billing.',
    consoleSteps: [
      'Review AWS Organizations structure',
      'Verify production workloads are in dedicated accounts',
      'Check that dev/test resources are in separate accounts',
      'Confirm SCPs enforce appropriate guardrails',
    ],
    expectedConfig: 'Separate accounts for prod and non-prod. AWS Organizations with SCPs for governance.',
    commonMisconfigs: [
      'All resources in single account',
      'No Organizations structure',
      'Missing SCPs for guardrails',
      'VPC peering between prod and non-prod without controls',
    ],
    fixHint: 'Implement AWS Organizations with separate accounts per environment. Use SCPs to enforce security policies across accounts.',
  },
  {
    id: 'INT-AWS-003',
    title: 'Implement Least Privilege IAM with MFA',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Ensure all IAM users and roles follow least privilege with MFA required for console access.',
    whyItMatters: 'Excessive permissions increase blast radius. Missing MFA makes credential theft more impactful.',
    consoleSteps: [
      'Navigate to IAM > Users and review permissions',
      'Check MFA is enabled for all console users',
      'Review IAM policies for overly permissive access (*:*)',
      'Verify no dormant accounts exist',
      'Check for privileged access approval documentation',
    ],
    expectedConfig: 'All users with minimum required permissions. MFA enabled for all console users. Quarterly access reviews documented.',
    commonMisconfigs: [
      'Users with AdministratorAccess when not needed',
      'Console users without MFA',
      'Former employees still have access',
      'No periodic access review process',
    ],
    fixHint: 'Implement least privilege policies. Enforce MFA via IAM policies. Conduct quarterly access reviews and maintain approval documentation.',
  },
  {
    id: 'INT-AWS-004',
    title: 'Verify Endpoint Protection on EC2 Instances',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'compute',
    whatToCheck: 'Check if Microsoft Defender ATP or equivalent endpoint protection is installed on all EC2 instances.',
    whyItMatters: 'Instances without endpoint protection are vulnerable to malware, ransomware, and other threats.',
    consoleSteps: [
      'Check EC2 instance tags for endpoint protection status',
      'Verify instances have cg_MDATP=onboarded tag or equivalent',
      'Check SSM inventory for installed security agents',
      'Review Defender for Cloud (if connected) for coverage',
    ],
    expectedConfig: 'All EC2 instances with endpoint protection installed and reporting. Tagged appropriately for tracking.',
    commonMisconfigs: [
      'Instances deployed without endpoint agents',
      'Agents installed but not reporting',
      'Missing or incorrect tags',
      'AMIs without pre-installed protection',
    ],
    fixHint: 'Deploy endpoint protection via SSM or user data. Tag instances with protection status. Include agents in golden AMIs.',
  },
  {
    id: 'INT-AWS-005',
    title: 'Enable Encryption for Data at Rest and Transit',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'encryption',
    whatToCheck: 'Verify all production resources encrypt data at rest and enforce TLS for data in transit.',
    whyItMatters: 'Unencrypted data is vulnerable if storage is compromised or network traffic is intercepted.',
    consoleSteps: [
      'Check EBS volumes for encryption (default encryption enabled)',
      'Verify S3 buckets have default encryption',
      'Check RDS instances for encryption at rest',
      'Verify HTTPS/TLS enforcement on load balancers and APIs',
    ],
    expectedConfig: 'All storage encrypted with KMS keys. TLS 1.2+ enforced for all data in transit.',
    commonMisconfigs: [
      'EBS volumes without encryption',
      'S3 buckets without default encryption',
      'RDS instances unencrypted',
      'HTTP endpoints without TLS enforcement',
    ],
    fixHint: 'Enable default EBS encryption in account settings. Configure S3 bucket policies to require encryption. Enable encryption for RDS instances.',
  },
  {
    id: 'INT-AWS-006',
    title: 'Secure Secrets Management with Rotation',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'encryption',
    whatToCheck: 'Verify secrets are stored in Secrets Manager or Parameter Store with rotation policies.',
    whyItMatters: 'Hardcoded secrets and unrotated credentials increase risk of compromise and unauthorized access.',
    consoleSteps: [
      'Verify no hardcoded secrets in code, environment variables, or scripts',
      'Check Secrets Manager for secret rotation configuration',
      'Review Parameter Store SecureString usage',
      'Verify KMS key policies for secrets encryption',
    ],
    expectedConfig: 'All secrets in Secrets Manager with automatic rotation. No hardcoded credentials.',
    commonMisconfigs: [
      'Secrets hardcoded in application code or Lambda env vars',
      'No rotation configured for database credentials',
      'Secrets Manager not used',
      'Overly permissive secret access policies',
    ],
    fixHint: 'Move all secrets to Secrets Manager. Enable automatic rotation for supported secrets. Use IAM policies to restrict secret access.',
  },
  {
    id: 'INT-AWS-007',
    title: 'Configure Backups for Critical Resources',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'storage',
    whatToCheck: 'Verify AWS Backup is configured for all critical resources with appropriate retention.',
    whyItMatters: 'Without proper backups, data loss from ransomware, deletion, or failures cannot be recovered.',
    consoleSteps: [
      'Navigate to AWS Backup console',
      'Verify backup plans exist for critical resources',
      'Check backup vault retention policies',
      'Confirm backup completion reports are reviewed',
      'Verify cross-region backup for disaster recovery',
    ],
    expectedConfig: 'All critical resources in backup plans. Appropriate retention. Regular restore testing documented.',
    commonMisconfigs: [
      'Critical resources without backup plans',
      'Backup retention too short',
      'No restore testing performed',
      'Backup failure notifications not configured',
    ],
    fixHint: 'Create AWS Backup plans for all critical resources. Configure SNS notifications for failures. Perform periodic restore tests.',
  },
  {
    id: 'INT-AWS-008',
    title: 'Security Groups - No Open Source IPs',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify security groups do not allow 0.0.0.0/0 for sensitive ports.',
    whyItMatters: 'Open security groups expose resources to the entire internet, enabling automated attacks.',
    consoleSteps: [
      'Navigate to VPC > Security Groups',
      'Review inbound rules for each security group',
      'Check for 0.0.0.0/0 on ports 22, 3389, 3306, 5432, etc.',
      'Verify source restrictions for management ports',
    ],
    expectedConfig: 'All security groups have specific source IPs/ranges. No 0.0.0.0/0 on sensitive ports.',
    commonMisconfigs: [
      'SSH/RDP open to 0.0.0.0/0',
      'Database ports accessible from internet',
      'Default security groups with permissive rules',
      'All traffic allowed between security groups',
    ],
    fixHint: 'Replace 0.0.0.0/0 with specific IP ranges or security groups. Use AWS Systems Manager Session Manager for secure access instead of direct SSH/RDP.',
  },
  {
    id: 'INT-AWS-009',
    title: 'Enable CloudTrail and Centralized Logging',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify CloudTrail is enabled with logs centralized and monitored.',
    whyItMatters: 'Without logging, security incidents cannot be detected, investigated, or used for compliance evidence.',
    consoleSteps: [
      'Navigate to CloudTrail console',
      'Verify organization trail or account trails exist',
      'Check log file validation is enabled',
      'Confirm logs are sent to centralized S3 bucket and/or CloudWatch',
      'Verify log retention meets compliance requirements',
    ],
    expectedConfig: 'CloudTrail enabled for all regions. Log validation enabled. Centralized logging with appropriate retention.',
    commonMisconfigs: [
      'CloudTrail not enabled',
      'Single-region trails missing activity',
      'Log file validation disabled',
      'No centralized log aggregation',
    ],
    fixHint: 'Create organization trail or multi-region trail. Enable log file validation. Send logs to centralized S3 bucket with lifecycle policies.',
  },
  {
    id: 'INT-AWS-010',
    title: 'VPC Flow Logs Enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify VPC Flow Logs are enabled for network traffic visibility.',
    whyItMatters: 'Flow logs provide visibility into network traffic patterns and are essential for security investigation.',
    consoleSteps: [
      'Navigate to VPC console',
      'Select each VPC and check Flow Logs tab',
      'Verify flow logs are configured for all VPCs',
      'Check logs are sent to CloudWatch or S3',
    ],
    expectedConfig: 'VPC Flow Logs enabled on all VPCs. Logs retained for investigation purposes.',
    commonMisconfigs: [
      'Flow logs not enabled',
      'Only REJECT traffic logged (missing ACCEPT)',
      'Retention too short for investigation',
      'No log analysis or alerting',
    ],
    fixHint: 'Enable VPC Flow Logs for all VPCs. Configure to log ALL traffic. Send to CloudWatch Logs or S3 for retention.',
  },
  {
    id: 'INT-AWS-011',
    title: 'Access Offboarding Process',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify access revocation process when team members leave or change roles.',
    whyItMatters: 'Orphaned access for former employees creates security risks and compliance violations.',
    consoleSteps: [
      'Request user access review documentation',
      'Verify offboarding checklist includes AWS access revocation',
      'Check IAM for any accounts of departed team members',
      'Confirm quarterly access reviews are performed and documented',
    ],
    expectedConfig: 'Documented offboarding process. Immediate access revocation. Quarterly access reviews with evidence.',
    commonMisconfigs: [
      'No offboarding checklist for AWS access',
      'Former employees retain IAM access',
      'Access keys not rotated when owners change',
      'No regular access reviews',
    ],
    fixHint: 'Implement formal offboarding checklist. Immediately disable or delete IAM users on departure. Rotate shared credentials. Document all reviews.',
  },

  // ============================================
  // INTERNAL BASELINE CONTROLS - Azure
  // ============================================
  
  {
    id: 'INT-AZ-001',
    title: 'Maintain Security Score Above Baseline',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify that the subscription security score is maintained above the enterprise baseline score of 75%.',
    whyItMatters: 'A low security score indicates unaddressed security recommendations that expose the environment to potential threats. Maintaining baseline scores ensures consistent security posture.',
    consoleSteps: [
      'Navigate to https://portal.azure.com/#view/Microsoft_Azure_Security/SecureScoreDashboard',
      'Check security score for your subscriptions',
      'Verify score is above 75% baseline',
      'Review any high/medium recommendations not addressed',
    ],
    expectedConfig: 'Security score should be 75% or higher for production subscriptions',
    commonMisconfigs: [
      'Security recommendations ignored or deferred without exception approval',
      'Score degradation not monitored over time',
      'High/medium recommendations left unaddressed',
    ],
    fixHint: 'Navigate to Defender for Cloud > Recommendations > Secure Score Recommendations. Address all High and Medium risk recommendations or request formal exceptions.',
  },
  {
    id: 'INT-AZ-002',
    title: 'Enable Defender for Cloud Paid Plans for Production',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify that all production resources have Microsoft Defender for Cloud paid plans enabled.',
    whyItMatters: 'Paid Defender plans provide advanced threat protection, vulnerability assessments, and workload protection capabilities essential for production environments.',
    consoleSteps: [
      'Navigate to Microsoft Defender for Cloud',
      'Go to Environment Settings',
      'Select your subscription',
      'Click on Defender Plans',
      'Verify paid plans are enabled for all production resources',
    ],
    expectedConfig: 'Foundational CSPM must be enabled. Cloud Workload Protection (CWP) should be enabled except for AI Services, Servers, and APIs.',
    commonMisconfigs: [
      'Using only free tier for production resources',
      'CWP not enabled for workloads',
      'CSPM not configured',
    ],
    fixHint: 'Enable Defender paid plans via Environment Settings > Defender Plans. Enable CSPM and CWP for comprehensive protection.',
  },
  {
    id: 'INT-AZ-003',
    title: 'Separate Production and Non-Production Subscriptions',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify that separate subscriptions are maintained for production and non-production environments with proper network segregation.',
    whyItMatters: 'Mixing production and non-production resources increases risk of accidental changes, data exposure, and makes access control more complex.',
    consoleSteps: [
      'Review subscription structure in Azure Portal',
      'Verify production resources are in dedicated subscriptions',
      'Confirm network segregation between prod and non-prod',
      'Check that VNets are properly isolated',
    ],
    expectedConfig: 'Production and non-production resources should not co-exist in the same subscription. Networks should be segregated.',
    commonMisconfigs: [
      'Dev/test and production in same subscription',
      'VNet peering between prod and non-prod without proper controls',
      'Shared resources across environments',
    ],
    fixHint: 'Create separate subscriptions for production workloads. Implement network segregation using separate VNets with controlled peering.',
  },
  {
    id: 'INT-AZ-004',
    title: 'Implement Least Privilege IAM with Periodic Reviews',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Ensure all IAM accounts follow the principle of least privilege and are periodically reviewed.',
    whyItMatters: 'Excessive permissions increase the blast radius of compromised accounts. Dormant accounts with access pose security risks.',
    consoleSteps: [
      'Navigate to Resource > Identity and Access Management',
      'Check Role Assignments for each resource',
      'Verify user permissions are correctly configured',
      'Identify and remove dormant accounts',
      'Verify privileged access approvals are documented',
    ],
    expectedConfig: 'All users should have minimum required permissions. Access reviews performed quarterly with documented evidence.',
    commonMisconfigs: [
      'Users with Owner/Contributor roles when Reader would suffice',
      'Former team members still have access',
      'No periodic access review process',
      'Privileged access granted without approval documentation',
    ],
    fixHint: 'Implement Azure AD Privileged Identity Management (PIM) for just-in-time access. Conduct quarterly access reviews and maintain approval documentation.',
  },
  {
    id: 'INT-AZ-005',
    title: 'Verify Antimalware Solution Installation',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'compute',
    whatToCheck: 'Check if Microsoft Defender ATP is installed and onboarded on all VMs.',
    whyItMatters: 'VMs without endpoint protection are vulnerable to malware, ransomware, and other threats that could spread across the environment.',
    consoleSteps: [
      'Check if resource tag "cg_MDATP" with value "onboarded" exists for VMs',
      'Verify VMs are tagged with cg_mdatpstatus:onboarded',
      'Check for cg_mdatpky:<KeyValue> tags confirming agent activation',
      'Contact cloudops@nagarro.com if antimalware is not installed',
    ],
    expectedConfig: 'All VMs should have cg_MDATP=onboarded tag and Microsoft Defender ATP active',
    commonMisconfigs: [
      'VMs deployed without endpoint protection',
      'Defender agent installed but not onboarded',
      'Missing or incorrect tags',
    ],
    fixHint: 'Install Microsoft Defender for Endpoint on all VMs. Ensure proper tagging with cg_MDATP=onboarded for tracking.',
  },
  {
    id: 'INT-AZ-006',
    title: 'Enable Encryption for Data at Rest and in Transit',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'encryption',
    whatToCheck: 'Check if all production databases and resources encrypt data at rest and in transit.',
    whyItMatters: 'Unencrypted data is vulnerable to exposure if storage is compromised or network traffic is intercepted.',
    consoleSteps: [
      'Check Defender for Cloud for encryption-related recommendations',
      'Verify TDE is enabled for databases',
      'Confirm HTTPS/TLS is enforced for data in transit',
      'Review Key Vault configuration for key management',
    ],
    expectedConfig: 'All production resources should have encryption enabled. TLS 1.2+ for transit, Azure-managed or customer-managed keys for rest.',
    commonMisconfigs: [
      'Storage accounts without encryption enforcement',
      'Databases without Transparent Data Encryption',
      'HTTP endpoints without TLS enforcement',
    ],
    fixHint: 'Enable encryption at rest for all storage and databases. Enforce HTTPS-only access and TLS 1.2 minimum.',
  },
  {
    id: 'INT-AZ-007',
    title: 'Secure Key Vault Access and Key Rotation',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'encryption',
    whatToCheck: 'Verify secrets and keys are stored in Key Vault with proper access controls and rotation policies.',
    whyItMatters: 'Hardcoded secrets and unrotated keys increase risk of credential compromise and unauthorized access.',
    consoleSteps: [
      'Verify no hardcoded secrets in code, environment variables, or DevOps scripts',
      'Check Key Vault secrets have expiry dates set',
      'Verify keys are rotated every 6 months (default frequency)',
      'Confirm Key Vault access is restricted to approved VPNs only',
    ],
    expectedConfig: 'All secrets in Key Vault with expiry. Keys rotated every 6 months. Access only via approved VPNs (shin-vpn, weeu-vpn, scanner-vnet).',
    commonMisconfigs: [
      'Secrets hardcoded in application code',
      'No expiry dates on Key Vault secrets',
      'Keys never rotated',
      'Key Vault accessible from public internet',
    ],
    fixHint: 'Move all secrets to Key Vault. Set expiry dates and implement rotation policies. Configure IP whitelisting for approved VPN ranges.',
  },
  {
    id: 'INT-AZ-008',
    title: 'Configure Backups for Critical Resources',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'storage',
    whatToCheck: 'Verify backups are configured and encrypted for all critical resources with proper retention.',
    whyItMatters: 'Without proper backups, data loss from ransomware, accidental deletion, or system failures cannot be recovered.',
    consoleSteps: [
      'Verify critical resources are backed up via Azure Backup',
      'Check backup frequency matches business requirements',
      'Verify resources are tagged with backup class (A-E)',
      'Confirm restoration drills are performed periodically',
      'Check backup failure notification alerts are enabled',
    ],
    expectedConfig: 'All critical resources tagged with backup class. Regular backup tests performed. Failure notifications configured.',
    commonMisconfigs: [
      'Critical resources without backup policies',
      'Backup retention too short',
      'No restoration testing',
      'Backup failure alerts not configured',
    ],
    fixHint: 'Configure Azure Backup for all critical resources. Tag resources with appropriate backup class (A-E). Enable failure notifications.',
  },
  {
    id: 'INT-AZ-009',
    title: 'Restrict NSG Rules - No Any Source',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify NSG rules do not allow "Any" as source IP and common ports are restricted.',
    whyItMatters: 'Allowing any source IP creates major security risks by exposing resources to the entire internet.',
    consoleSteps: [
      'Navigate to Network Security Groups',
      'Review inbound rules for each NSG',
      'Verify source is never set to "Any", "*", or 0.0.0.0/0',
      'Check that common ports (22, 3389, 3306, etc.) are restricted to specific IPs',
    ],
    expectedConfig: 'All NSG rules should have specific source IPs/ranges. No rules with "Any" source. Multiple IPs allowed but must be explicitly defined.',
    commonMisconfigs: [
      'Source set to "Any" or "*"',
      'Common management ports open to internet',
      'Default allow rules not removed',
      'High risk when port, source, AND protocol are all "Any"',
    ],
    fixHint: 'Replace "Any" source with specific IP ranges or service tags. Use Azure Bastion for secure remote access instead of public RDP/SSH.',
  },
  {
    id: 'INT-AZ-010',
    title: 'Configure Logging and Monitoring',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify logging is enabled for all resources with Azure Monitor Agent installed.',
    whyItMatters: 'Without logging, security incidents cannot be detected, investigated, or used for compliance evidence.',
    consoleSteps: [
      'Verify Azure Monitor Agent is installed on all VMs',
      'Check diagnostic settings are enabled for all supported resources',
      'Confirm logs are sent to Log Analytics workspace',
      'Verify retention policies meet compliance requirements',
    ],
    expectedConfig: 'Azure Monitor Agent on all VMs. Diagnostic settings enabled. Logs centralized in Log Analytics.',
    commonMisconfigs: [
      'VMs without monitoring agent',
      'Diagnostic settings not configured',
      'Logs not retained long enough',
      'No centralized log collection',
    ],
    fixHint: 'Deploy Azure Monitor Agent via Azure Policy. Enable diagnostic settings on all resources. Configure Log Analytics workspace.',
  },
  {
    id: 'INT-AZ-011',
    title: 'Kubernetes API Security',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'compute',
    whatToCheck: 'Verify Kubernetes API security with authorized IP ranges enabled.',
    whyItMatters: 'Misconfigured Kubernetes APIs can expose clusters to unauthorized access and attacks.',
    consoleSteps: [
      'Check Defender for Cloud for Kubernetes API security alerts',
      'Navigate to AKS cluster > Networking',
      'Verify "Authorized IP ranges" is enabled',
      'Confirm only trusted IP ranges are whitelisted',
    ],
    expectedConfig: 'Authorized IP ranges enabled. Only corporate/VPN IPs whitelisted for API access.',
    commonMisconfigs: [
      'API server exposed to internet',
      'Authorized IP ranges not configured',
      'Too many IP ranges whitelisted',
    ],
    fixHint: 'Enable authorized IP ranges on AKS clusters. Restrict to corporate VPN and management IPs only.',
  },
  {
    id: 'INT-AZ-012',
    title: 'Access Offboarding Process',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify access revocation process when team members leave or change roles.',
    whyItMatters: 'Orphaned access for former employees creates security risks and compliance violations.',
    consoleSteps: [
      'Request user access review documentation',
      'Verify offboarding process includes cloud access revocation',
      'Check that access transfers to PCEO/CCS when resource owners change',
      'Confirm quarterly access reviews are performed and documented',
    ],
    expectedConfig: 'Documented offboarding process. Access changes communicated to Cloud Ops. Quarterly access reviews with evidence.',
    commonMisconfigs: [
      'No offboarding checklist for cloud access',
      'Former employees retain access',
      'Access not transferred when owners change',
    ],
    fixHint: 'Implement formal offboarding checklist including cloud access. Notify cloudops@nagarro.com for access changes. Document all reviews.',
  },

  // ============================================
  // INTERNAL BASELINE CONTROLS - GCP
  // ============================================
  
  {
    id: 'INT-GCP-001',
    title: 'Enable Defender for Cloud Visibility for GCP',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify all GCP detections, risks, and recommendations are visible in Microsoft Defender for Cloud.',
    whyItMatters: 'Centralized visibility into potential threats and compliance gaps is essential for consistent security monitoring across multi-cloud environments.',
    consoleSteps: [
      'Navigate to Microsoft Defender for Cloud in Azure Portal',
      'Verify GCP projects are connected',
      'Check that project-specific risks and recommendations appear',
      'Confirm high-risk alerts trigger email notifications',
    ],
    expectedConfig: 'All GCP projects onboarded to Defender for Cloud. Teams have project-specific visibility. High-risk alerts configured for notifications.',
    commonMisconfigs: [
      'GCP projects not connected to Defender',
      'Alert notifications not configured',
      'Teams unable to see project-specific data',
    ],
    fixHint: 'Connect GCP projects to Defender for Cloud. Configure alert notifications for security teams. Ensure proper RBAC for project visibility.',
  },
  {
    id: 'INT-GCP-002',
    title: 'Enforce Role-Based Access with MFA',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify IAM access is role-based, duration-based, limited to necessary permissions, and MFA is required.',
    whyItMatters: 'Overly permissive access without MFA significantly increases risk of unauthorized access and credential compromise.',
    consoleSteps: [
      'Navigate to IAM & Admin > IAM',
      'Review role assignments for least privilege',
      'Verify no personal Gmail accounts in IAM',
      'Check Cloud Identity for MFA enforcement',
      'Verify password policy is implemented',
    ],
    expectedConfig: 'Role-based access with minimum permissions. MFA required for all users. Password policy enforced via Cloud Identity.',
    commonMisconfigs: [
      'Personal Gmail accounts with project access',
      'Editor/Owner roles assigned broadly',
      'MFA not enforced',
      'No password policy',
    ],
    fixHint: 'Use Cloud Identity or Workspace for user management. Enforce MFA via security settings. Assign predefined roles instead of primitive roles.',
  },
  {
    id: 'INT-GCP-003',
    title: 'Revoke Access on Offboarding',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify project owners revoke access when team members offboard.',
    whyItMatters: 'Orphaned accounts with active access create security vulnerabilities and potential for unauthorized data access.',
    consoleSteps: [
      'Review IAM & Admin for current members',
      'Cross-reference with current team roster',
      'Check for any accounts of departed team members',
      'Verify offboarding checklist includes GCP access revocation',
    ],
    expectedConfig: 'Offboarding process includes immediate access revocation. Quarterly access reviews performed.',
    commonMisconfigs: [
      'No formal offboarding process',
      'Departed members retain access for weeks/months',
      'No regular access reviews',
    ],
    fixHint: 'Implement offboarding checklist with Cloud Ops notification. Conduct quarterly access reviews. Document all access changes.',
  },
  {
    id: 'INT-GCP-004',
    title: 'VPC Firewall - No Open Source IPs',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify VPC firewall rules do not allow source 0.0.0.0/0, "Any", or wildcard for common ports.',
    whyItMatters: 'Open firewall rules expose resources to the entire internet, making them targets for automated attacks.',
    consoleSteps: [
      'Navigate to VPC Network > Firewall',
      'Review each firewall rule',
      'Check that source is not 0.0.0.0/0, "Any", or *',
      'Verify common ports (22, 3389, 3306, etc.) are restricted',
      'Check if default VPC rules are still in use',
    ],
    expectedConfig: 'All firewall rules have specific source IP ranges. No rules allowing 0.0.0.0/0 for sensitive ports.',
    commonMisconfigs: [
      'Default VPC with permissive rules',
      'SSH allowed from ANY IP (GCP default behavior)',
      'Firewall source set to 0.0.0.0/0',
      'Common ports open to internet',
    ],
    fixHint: 'Delete or modify default VPC rules. Create specific rules with trusted IP ranges. Use IAP for secure SSH/RDP access.',
  },
  {
    id: 'INT-GCP-005',
    title: 'Configure Authorized IP Ranges for Public Access',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify Networking public access has "Authorized IP ranges" enabled.',
    whyItMatters: 'Unrestricted public access exposes management interfaces and APIs to potential attacks from anywhere.',
    consoleSteps: [
      'Navigate to GKE clusters > Networking',
      'Verify "Authorized IP ranges" is enabled',
      'Check Cloud SQL instances for IP whitelisting',
      'Review any resources with public endpoints',
    ],
    expectedConfig: 'All public endpoints restricted to authorized IP ranges. GKE control plane access limited.',
    commonMisconfigs: [
      'GKE API accessible from any IP',
      'Cloud SQL public IP without restrictions',
      'No IP whitelisting on public resources',
    ],
    fixHint: 'Enable authorized networks on GKE clusters. Configure IP whitelisting for Cloud SQL. Use Private Google Access where possible.',
  },
  {
    id: 'INT-GCP-006',
    title: 'Check VPC WAN and LAN Connectivity',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify VPC WAN and LAN connectivity configuration via GCP console.',
    whyItMatters: 'Improper network connectivity configuration can lead to security gaps or unintended exposure.',
    consoleSteps: [
      'Navigate to VPC Network > VPC networks',
      'Review network topology and peering connections',
      'Check Cloud Interconnect and VPN configurations',
      'Verify proper network segmentation',
    ],
    expectedConfig: 'Clear network segmentation. Secure interconnect to on-premises. VPN tunnels properly configured.',
    commonMisconfigs: [
      'Flat network without segmentation',
      'Unsecured interconnect configurations',
      'VPN tunnels with weak encryption',
    ],
    fixHint: 'Implement VPC network segmentation. Use Cloud Interconnect or VPN for secure on-premises connectivity. Review and document network topology.',
  },
  {
    id: 'INT-GCP-007',
    title: 'VM Antimalware Tagging Verification',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'compute',
    whatToCheck: 'Verify VMs are tagged with cg_mdatpstatus:onboarded indicating antivirus and monitoring agents are active.',
    whyItMatters: 'VMs without endpoint protection are vulnerable to malware and cannot be monitored for threats.',
    consoleSteps: [
      'Navigate to Compute Engine > VM instances',
      'Check labels for each VM',
      'Verify cg_mdatpstatus:onboarded label exists',
      'Check for cg_mdatpky:<KeyValue> label',
    ],
    expectedConfig: 'All VMs tagged with cg_mdatpstatus:onboarded and cg_mdatpky:<KeyValue> confirming Defender ATP onboarding.',
    commonMisconfigs: [
      'VMs deployed without required labels',
      'Defender ATP not installed',
      'Labels present but agent not functioning',
    ],
    fixHint: 'Install Microsoft Defender for Endpoint on all VMs. Apply required labels. Verify agent connectivity in Defender portal.',
  },
  {
    id: 'INT-GCP-008',
    title: 'Configure Backup Policies with Tags',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'storage',
    whatToCheck: 'Verify resources are tagged with backup enabled and appropriate backup classes are defined.',
    whyItMatters: 'Without proper backups and retention, data cannot be recovered from ransomware, deletion, or corruption.',
    consoleSteps: [
      'Check resource labels for backup:enabled',
      'Verify backup class assignments (A-E)',
      'Review Cloud Storage versioning configuration',
      'Confirm backup schedules match class requirements',
    ],
    expectedConfig: 'All critical resources tagged with backup class. Versioning enabled on Cloud Storage. Backup schedules documented.',
    commonMisconfigs: [
      'Critical resources without backup labels',
      'No backup class assigned',
      'Versioning disabled on buckets',
      'Backup retention too short',
    ],
    fixHint: 'Tag all resources with appropriate backup class. Enable Object Versioning on Cloud Storage. Configure Cloud Backup services.',
  },

  // ============================================
  // ISO 27001 CONTROLS - AWS
  // ============================================
  
  {
    id: 'ISO-AWS-A9.1',
    title: 'A.9.1 - Access Control Policy Implementation',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify access control policies are established, documented, and reviewed based on business and security requirements.',
    whyItMatters: 'ISO 27001 A.9.1.1 requires documented access control policies. Without them, access decisions are inconsistent and unauditable.',
    consoleSteps: [
      'Review documented IAM policies and their business justification',
      'Check IAM policy versioning and change history',
      'Verify policy review schedule exists (at least annually)',
      'Confirm access control matrix is maintained',
    ],
    expectedConfig: 'Documented access control policies aligned with business requirements. Annual policy reviews documented.',
    commonMisconfigs: [
      'No documented access control policy',
      'Policies not reviewed periodically',
      'No business justification for access levels',
      'Inconsistent policy application',
    ],
    fixHint: 'Document access control policies in company wiki/ISMS. Implement annual review process. Map policies to IAM implementation.',
  },
  {
    id: 'ISO-AWS-A9.2',
    title: 'A.9.2 - User Access Provisioning and Review',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify formal user registration, de-registration, and access review processes are implemented.',
    whyItMatters: 'ISO 27001 A.9.2.1-A.9.2.6 requires formal access management processes to prevent unauthorized access.',
    consoleSteps: [
      'Review user provisioning workflow documentation',
      'Check access request and approval records',
      'Verify quarterly access reviews are performed',
      'Confirm offboarding includes access revocation',
      'Check privileged access management process',
    ],
    expectedConfig: 'Formal provisioning process with approvals. Quarterly access reviews. Immediate revocation on termination.',
    commonMisconfigs: [
      'No formal access request process',
      'Missing approval documentation',
      'Infrequent access reviews',
      'Delayed access revocation',
    ],
    fixHint: 'Implement formal access request workflow. Use AWS SSO with approval workflows. Conduct quarterly access reviews with documented evidence.',
  },
  {
    id: 'ISO-AWS-A9.4',
    title: 'A.9.4 - System and Application Access Control',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify secure log-on procedures, password policies, and privileged utility controls are in place.',
    whyItMatters: 'ISO 27001 A.9.4 requires controls to prevent unauthorized access to systems and applications.',
    consoleSteps: [
      'Check IAM password policy meets complexity requirements',
      'Verify MFA is enforced for all console access',
      'Review privileged access management (break-glass procedures)',
      'Confirm session timeout policies are configured',
    ],
    expectedConfig: 'Strong password policy. MFA required. Privileged access logged and audited.',
    commonMisconfigs: [
      'Weak password policy',
      'MFA not enforced',
      'No privileged access management',
      'Unlimited session duration',
    ],
    fixHint: 'Configure IAM password policy with 14+ char minimum. Enforce MFA via IAM policies. Implement AWS SSO with session controls.',
  },
  {
    id: 'ISO-AWS-A10.1',
    title: 'A.10.1 - Cryptographic Controls',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'encryption',
    whatToCheck: 'Verify cryptographic policy exists and encryption is properly implemented for data protection.',
    whyItMatters: 'ISO 27001 A.10.1 requires documented cryptographic policy and proper key management to protect information.',
    consoleSteps: [
      'Review documented cryptographic policy',
      'Verify KMS keys are used for encryption',
      'Check key rotation is enabled (annual minimum)',
      'Confirm encryption at rest for all storage services',
      'Verify TLS 1.2+ for data in transit',
    ],
    expectedConfig: 'Documented crypto policy. KMS keys with rotation. All data encrypted at rest and in transit.',
    commonMisconfigs: [
      'No documented cryptographic policy',
      'Using default AWS keys instead of CMKs',
      'Key rotation disabled',
      'TLS 1.0/1.1 still allowed',
    ],
    fixHint: 'Document cryptographic policy in ISMS. Use customer-managed KMS keys with rotation. Enforce TLS 1.2 minimum.',
  },
  {
    id: 'ISO-AWS-A12.4',
    title: 'A.12.4 - Logging and Monitoring',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'logging',
    whatToCheck: 'Verify event logging, protection of logs, and monitoring of administrator activities.',
    whyItMatters: 'ISO 27001 A.12.4 requires logging of user activities, exceptions, and security events for investigation.',
    consoleSteps: [
      'Verify CloudTrail is enabled for all regions',
      'Check CloudWatch Logs retention meets requirements',
      'Confirm log integrity validation is enabled',
      'Review alerting for security-relevant events',
      'Verify administrator activity logging',
    ],
    expectedConfig: 'CloudTrail enabled. Log validation enabled. Centralized logging. Security event alerting.',
    commonMisconfigs: [
      'CloudTrail not enabled in all regions',
      'Log validation disabled',
      'Insufficient log retention',
      'No security event alerting',
    ],
    fixHint: 'Enable organization CloudTrail. Configure CloudWatch alarms for security events. Implement SIEM integration.',
  },
  {
    id: 'ISO-AWS-A12.6',
    title: 'A.12.6 - Technical Vulnerability Management',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'compute',
    whatToCheck: 'Verify technical vulnerabilities are identified, evaluated, and remediated in a timely manner.',
    whyItMatters: 'ISO 27001 A.12.6.1 requires a process to identify and address technical vulnerabilities to reduce exploitation risk.',
    consoleSteps: [
      'Check AWS Inspector is enabled for vulnerability scanning',
      'Review Security Hub findings for vulnerabilities',
      'Verify patch management process exists',
      'Confirm vulnerability remediation SLAs are defined',
      'Check ECR image scanning is enabled',
    ],
    expectedConfig: 'Regular vulnerability scanning. Defined remediation SLAs. Documented exception process.',
    commonMisconfigs: [
      'No vulnerability scanning enabled',
      'Findings not reviewed regularly',
      'No remediation SLAs defined',
      'Unpatched systems in production',
    ],
    fixHint: 'Enable AWS Inspector and ECR scanning. Define SLAs (Critical: 24h, High: 7d). Implement patch automation with SSM.',
  },
  {
    id: 'ISO-AWS-A13.1',
    title: 'A.13.1 - Network Security Management',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'network',
    whatToCheck: 'Verify networks are managed and controlled with segregation of services.',
    whyItMatters: 'ISO 27001 A.13.1 requires network controls, segregation, and security of network services.',
    consoleSteps: [
      'Review VPC architecture and segmentation',
      'Verify security groups follow least privilege',
      'Check network ACLs are properly configured',
      'Confirm network monitoring is in place (VPC Flow Logs)',
      'Review network diagram documentation',
    ],
    expectedConfig: 'Documented network architecture. Segmented VPCs. Least privilege security groups. Flow logs enabled.',
    commonMisconfigs: [
      'Flat network without segmentation',
      'Overly permissive security groups',
      'No network monitoring',
      'Undocumented network architecture',
    ],
    fixHint: 'Implement VPC segmentation by tier. Use security groups and NACLs together. Enable VPC Flow Logs. Document architecture.',
  },
  {
    id: 'ISO-AWS-A17.1',
    title: 'A.17.1 - Information Security Continuity',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'ISO 27001',
    category: 'storage',
    whatToCheck: 'Verify information security continuity is embedded in business continuity management.',
    whyItMatters: 'ISO 27001 A.17.1 requires planning for security continuity during adverse situations.',
    consoleSteps: [
      'Review backup policies and retention',
      'Verify cross-region replication for critical data',
      'Check disaster recovery procedures are documented',
      'Confirm DR tests are performed periodically',
      'Review RTO/RPO requirements and implementation',
    ],
    expectedConfig: 'Documented DR plan. Cross-region backups. Regular DR testing. RTO/RPO defined and tested.',
    commonMisconfigs: [
      'No disaster recovery plan',
      'Single-region deployment for critical systems',
      'DR procedures never tested',
      'RTO/RPO not defined',
    ],
    fixHint: 'Document DR plan. Implement cross-region replication. Conduct annual DR tests. Define and validate RTO/RPO.',
  },

  // ============================================
  // ISO 27001 CONTROLS - Azure
  // ============================================
  
  {
    id: 'ISO-AZ-A9.1',
    title: 'A.9.1 - Access Control Policy Implementation',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify access control policies are established, documented, and reviewed based on business and security requirements.',
    whyItMatters: 'ISO 27001 A.9.1.1 requires documented access control policies. Without them, access decisions are inconsistent.',
    consoleSteps: [
      'Review documented Azure RBAC policies and their justification',
      'Check Azure AD role assignments and custom roles',
      'Verify Conditional Access policies are documented',
      'Confirm access control matrix is maintained',
    ],
    expectedConfig: 'Documented access control policies. Conditional Access enabled. Annual policy reviews.',
    commonMisconfigs: [
      'No documented access control policy',
      'Conditional Access not configured',
      'Custom roles without documentation',
      'No periodic policy review',
    ],
    fixHint: 'Document access control policies in ISMS. Implement Conditional Access policies. Review and document all custom roles.',
  },
  {
    id: 'ISO-AZ-A9.2',
    title: 'A.9.2 - User Access Provisioning and Review',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify formal user registration, de-registration, and access review processes using Azure AD.',
    whyItMatters: 'ISO 27001 A.9.2 requires formal access management processes to prevent unauthorized access.',
    consoleSteps: [
      'Review Azure AD access review configurations',
      'Check Privileged Identity Management (PIM) setup',
      'Verify access request workflows in Azure AD',
      'Confirm guest user access reviews are performed',
      'Check offboarding process includes Azure access revocation',
    ],
    expectedConfig: 'Azure AD Access Reviews enabled. PIM for privileged roles. Documented provisioning workflow.',
    commonMisconfigs: [
      'Access Reviews not configured',
      'PIM not used for privileged roles',
      'No formal provisioning process',
      'Guest users not reviewed',
    ],
    fixHint: 'Enable Azure AD Access Reviews. Implement PIM for all privileged roles. Configure entitlement management for access requests.',
  },
  {
    id: 'ISO-AZ-A9.4',
    title: 'A.9.4 - System and Application Access Control',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify secure log-on procedures, MFA, and Conditional Access policies are in place.',
    whyItMatters: 'ISO 27001 A.9.4 requires controls to prevent unauthorized access to systems and applications.',
    consoleSteps: [
      'Check Azure AD Conditional Access policies',
      'Verify MFA is required for all users',
      'Review sign-in risk policies',
      'Confirm session controls are configured',
      'Check legacy authentication is blocked',
    ],
    expectedConfig: 'MFA required. Conditional Access enforced. Legacy auth blocked. Session controls configured.',
    commonMisconfigs: [
      'MFA not enforced for all users',
      'Legacy authentication allowed',
      'No Conditional Access policies',
      'No sign-in risk policies',
    ],
    fixHint: 'Configure Conditional Access to require MFA. Block legacy authentication. Enable Azure AD Identity Protection.',
  },
  {
    id: 'ISO-AZ-A10.1',
    title: 'A.10.1 - Cryptographic Controls',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'encryption',
    whatToCheck: 'Verify cryptographic policy exists and Azure Key Vault is properly used for key management.',
    whyItMatters: 'ISO 27001 A.10.1 requires documented cryptographic policy and proper key management.',
    consoleSteps: [
      'Review documented cryptographic policy',
      'Verify Key Vault is used for secrets and keys',
      'Check key rotation policies are configured',
      'Confirm disk encryption is enabled (Azure Disk Encryption)',
      'Verify TLS 1.2+ enforcement on all services',
    ],
    expectedConfig: 'Documented crypto policy. Key Vault with rotation. All data encrypted. TLS 1.2+ enforced.',
    commonMisconfigs: [
      'No documented cryptographic policy',
      'Secrets stored outside Key Vault',
      'No key rotation',
      'TLS 1.0/1.1 allowed',
    ],
    fixHint: 'Document cryptographic policy. Migrate all secrets to Key Vault. Enable key rotation. Enforce TLS 1.2 minimum.',
  },
  {
    id: 'ISO-AZ-A12.4',
    title: 'A.12.4 - Logging and Monitoring',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'logging',
    whatToCheck: 'Verify Azure Monitor, diagnostic logs, and security event monitoring are configured.',
    whyItMatters: 'ISO 27001 A.12.4 requires logging of user activities, exceptions, and security events.',
    consoleSteps: [
      'Verify Azure Monitor is configured',
      'Check diagnostic settings on all resources',
      'Confirm Log Analytics workspace retention',
      'Review Azure AD sign-in and audit logs',
      'Check Microsoft Sentinel is configured for SIEM',
    ],
    expectedConfig: 'Diagnostic settings enabled. Centralized Log Analytics. Azure AD logs retained. Sentinel for alerting.',
    commonMisconfigs: [
      'Diagnostic settings not configured',
      'Insufficient log retention',
      'Azure AD logs not exported',
      'No security alerting',
    ],
    fixHint: 'Enable diagnostic settings via Azure Policy. Configure Log Analytics retention. Export Azure AD logs. Deploy Sentinel.',
  },
  {
    id: 'ISO-AZ-A12.6',
    title: 'A.12.6 - Technical Vulnerability Management',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'compute',
    whatToCheck: 'Verify Defender for Cloud vulnerability assessments and patch management processes.',
    whyItMatters: 'ISO 27001 A.12.6.1 requires identification and remediation of technical vulnerabilities.',
    consoleSteps: [
      'Check Defender for Cloud vulnerability recommendations',
      'Review Qualys or built-in VA solution findings',
      'Verify Update Management is configured for VMs',
      'Confirm container image scanning is enabled',
      'Check vulnerability remediation SLAs are defined',
    ],
    expectedConfig: 'Vulnerability scanning enabled. Patch management automated. Remediation SLAs documented.',
    commonMisconfigs: [
      'Vulnerability assessment not enabled',
      'No patch management process',
      'Container images not scanned',
      'Findings not remediated timely',
    ],
    fixHint: 'Enable Defender for Cloud VA. Configure Azure Update Management. Define remediation SLAs. Enable container scanning.',
  },
  {
    id: 'ISO-AZ-A13.1',
    title: 'A.13.1 - Network Security Management',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'network',
    whatToCheck: 'Verify VNet architecture, NSGs, and network monitoring are properly configured.',
    whyItMatters: 'ISO 27001 A.13.1 requires network controls, segregation, and security of network services.',
    consoleSteps: [
      'Review VNet architecture and segmentation',
      'Verify NSGs follow least privilege',
      'Check Azure Firewall or NVA configuration',
      'Confirm NSG Flow Logs are enabled',
      'Review network documentation',
    ],
    expectedConfig: 'Documented network architecture. Segmented VNets. NSG Flow Logs enabled. Firewall configured.',
    commonMisconfigs: [
      'Flat network without segmentation',
      'Overly permissive NSG rules',
      'No network monitoring',
      'Undocumented architecture',
    ],
    fixHint: 'Implement VNet segmentation. Configure NSGs with least privilege. Enable NSG Flow Logs. Document architecture.',
  },
  {
    id: 'ISO-AZ-A17.1',
    title: 'A.17.1 - Information Security Continuity',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'ISO 27001',
    category: 'storage',
    whatToCheck: 'Verify Azure Backup, Site Recovery, and disaster recovery planning.',
    whyItMatters: 'ISO 27001 A.17.1 requires planning for security continuity during adverse situations.',
    consoleSteps: [
      'Review Azure Backup policies and vault configuration',
      'Verify Azure Site Recovery is configured for critical workloads',
      'Check disaster recovery procedures are documented',
      'Confirm DR tests are performed periodically',
      'Review RTO/RPO requirements and implementation',
    ],
    expectedConfig: 'Azure Backup configured. Site Recovery for critical VMs. Documented and tested DR plan.',
    commonMisconfigs: [
      'No backup policies',
      'Site Recovery not configured',
      'DR procedures never tested',
      'RTO/RPO not defined',
    ],
    fixHint: 'Configure Azure Backup. Implement Site Recovery for DR. Document and test DR procedures annually.',
  },

  // ============================================
  // ISO 27001 CONTROLS - GCP
  // ============================================
  
  {
    id: 'ISO-GCP-A9.1',
    title: 'A.9.1 - Access Control Policy Implementation',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify IAM policies are documented and reviewed based on business requirements.',
    whyItMatters: 'ISO 27001 A.9.1.1 requires documented access control policies for consistent and auditable access decisions.',
    consoleSteps: [
      'Review documented IAM policies and role assignments',
      'Check for use of predefined vs custom roles',
      'Verify organization policies are configured',
      'Confirm access control matrix is maintained',
    ],
    expectedConfig: 'Documented access policies. Predefined roles preferred. Organization policies enforced.',
    commonMisconfigs: [
      'No documented access control policy',
      'Custom roles without documentation',
      'No organization policy constraints',
      'Policies not reviewed periodically',
    ],
    fixHint: 'Document access control policies. Use predefined roles where possible. Implement organization policy constraints.',
  },
  {
    id: 'ISO-GCP-A9.2',
    title: 'A.9.2 - User Access Provisioning and Review',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify formal access provisioning, review, and revocation processes are implemented.',
    whyItMatters: 'ISO 27001 A.9.2 requires formal access management to prevent unauthorized access.',
    consoleSteps: [
      'Review Cloud Identity user provisioning',
      'Check IAM recommender for unused permissions',
      'Verify access review process documentation',
      'Confirm offboarding includes GCP access revocation',
      'Check for dormant service accounts',
    ],
    expectedConfig: 'Formal provisioning process. Regular access reviews using IAM recommender. Immediate offboarding.',
    commonMisconfigs: [
      'No formal access request process',
      'IAM recommender findings ignored',
      'Infrequent access reviews',
      'Dormant service accounts',
    ],
    fixHint: 'Implement formal access workflows. Review IAM recommender regularly. Remove unused permissions and accounts.',
  },
  {
    id: 'ISO-GCP-A9.4',
    title: 'A.9.4 - System and Application Access Control',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'iam',
    whatToCheck: 'Verify secure authentication with 2-Step Verification and session controls.',
    whyItMatters: 'ISO 27001 A.9.4 requires controls to prevent unauthorized access to systems.',
    consoleSteps: [
      'Verify 2-Step Verification is enforced via Cloud Identity',
      'Check context-aware access policies',
      'Review service account key management',
      'Confirm session duration limits are set',
    ],
    expectedConfig: '2-Step Verification required. Context-aware access enabled. Minimal service account keys.',
    commonMisconfigs: [
      '2-Step Verification not enforced',
      'No context-aware access',
      'Too many service account keys',
      'No session controls',
    ],
    fixHint: 'Enforce 2-Step Verification in Cloud Identity. Implement BeyondCorp Enterprise. Minimize service account key usage.',
  },
  {
    id: 'ISO-GCP-A10.1',
    title: 'A.10.1 - Cryptographic Controls',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'encryption',
    whatToCheck: 'Verify Cloud KMS usage and encryption policies for data protection.',
    whyItMatters: 'ISO 27001 A.10.1 requires documented cryptographic policy and proper key management.',
    consoleSteps: [
      'Review documented cryptographic policy',
      'Verify Cloud KMS is used for CMEK encryption',
      'Check key rotation is enabled',
      'Confirm default encryption for Cloud Storage',
      'Verify SSL/TLS enforcement on all services',
    ],
    expectedConfig: 'Documented crypto policy. CMEK with Cloud KMS. Key rotation enabled. TLS enforced.',
    commonMisconfigs: [
      'No documented cryptographic policy',
      'Using Google-managed keys only',
      'No key rotation',
      'SSL not enforced',
    ],
    fixHint: 'Document cryptographic policy. Implement CMEK with Cloud KMS. Enable automatic key rotation.',
  },
  {
    id: 'ISO-GCP-A12.4',
    title: 'A.12.4 - Logging and Monitoring',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'logging',
    whatToCheck: 'Verify Cloud Logging, audit logs, and security monitoring are properly configured.',
    whyItMatters: 'ISO 27001 A.12.4 requires logging of user activities and security events.',
    consoleSteps: [
      'Verify Cloud Audit Logs are enabled',
      'Check Data Access logging configuration',
      'Confirm log retention meets requirements',
      'Review Cloud Monitoring alerting policies',
      'Check Security Command Center configuration',
    ],
    expectedConfig: 'Audit logs enabled. Data Access logs for sensitive resources. Appropriate retention. SCC enabled.',
    commonMisconfigs: [
      'Data Access logs disabled',
      'Insufficient retention',
      'No alerting configured',
      'SCC not enabled',
    ],
    fixHint: 'Enable Data Access logs for sensitive resources. Configure log retention. Enable Security Command Center Premium.',
  },
  {
    id: 'ISO-GCP-A12.6',
    title: 'A.12.6 - Technical Vulnerability Management',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'compute',
    whatToCheck: 'Verify Security Command Center and vulnerability management processes.',
    whyItMatters: 'ISO 27001 A.12.6.1 requires identification and remediation of technical vulnerabilities.',
    consoleSteps: [
      'Check Security Command Center findings',
      'Review Container Analysis for image vulnerabilities',
      'Verify VM Manager patch compliance',
      'Confirm Web Security Scanner is configured',
      'Check vulnerability remediation SLAs',
    ],
    expectedConfig: 'SCC Premium enabled. Container scanning active. Patch management automated. Remediation SLAs defined.',
    commonMisconfigs: [
      'SCC not enabled or using Standard tier',
      'Container images not scanned',
      'No patch management process',
      'Vulnerabilities not remediated',
    ],
    fixHint: 'Enable SCC Premium. Configure Container Analysis. Use VM Manager for patching. Define and track remediation SLAs.',
  },
  {
    id: 'ISO-GCP-A13.1',
    title: 'A.13.1 - Network Security Management',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'network',
    whatToCheck: 'Verify VPC design, firewall rules, and network monitoring.',
    whyItMatters: 'ISO 27001 A.13.1 requires network controls, segregation, and security of network services.',
    consoleSteps: [
      'Review VPC network architecture',
      'Verify firewall rules follow least privilege',
      'Check VPC Flow Logs are enabled',
      'Confirm Cloud Armor is configured for public endpoints',
      'Review network documentation',
    ],
    expectedConfig: 'Documented network architecture. Segmented VPCs. Flow Logs enabled. Cloud Armor for DDoS.',
    commonMisconfigs: [
      'Default VPC in use',
      'Overly permissive firewall rules',
      'Flow Logs not enabled',
      'No DDoS protection',
    ],
    fixHint: 'Create custom VPCs with proper segmentation. Implement hierarchical firewall policies. Enable VPC Flow Logs.',
  },
  {
    id: 'ISO-GCP-A17.1',
    title: 'A.17.1 - Information Security Continuity',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'ISO 27001',
    category: 'storage',
    whatToCheck: 'Verify backup strategies, multi-region deployment, and disaster recovery planning.',
    whyItMatters: 'ISO 27001 A.17.1 requires planning for security continuity during adverse situations.',
    consoleSteps: [
      'Review Cloud Storage versioning and lifecycle policies',
      'Check Persistent Disk snapshot schedules',
      'Verify multi-region deployment for critical services',
      'Confirm DR procedures are documented',
      'Check DR tests are performed periodically',
    ],
    expectedConfig: 'Versioning enabled. Regular snapshots. Multi-region for critical data. Documented and tested DR.',
    commonMisconfigs: [
      'No versioning on Cloud Storage',
      'No snapshot policies',
      'Single-region deployment',
      'DR never tested',
    ],
    fixHint: 'Enable Object Versioning. Configure snapshot schedules. Deploy critical services multi-region. Test DR annually.',
  },

  // ============================================
  // ADDITIONAL AWS CIS CONTROLS - v6.0.0
  // ============================================

  // IAM Additional Controls
  {
    id: 'CIS-AWS-2.10',
    title: 'Do not create access keys during initial setup for users with console password',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Ensure that access keys are not created at initial user setup for users who require console access.',
    whyItMatters: 'AWS console defaults include access key creation. Requiring unnecessary keys increases risk of key compromise.',
    consoleSteps: [
      'Go to IAM Dashboard',
      'Review users with both console access and access keys',
      'Verify access keys are only created when programmatic access is required',
      'Check user creation workflow does not auto-generate keys',
    ],
    cliCheck: 'aws iam list-users --query "Users[*].UserName" | xargs -I {} aws iam list-access-keys --user-name {}',
    expectedConfig: 'Users with console access should not have access keys unless specifically required for programmatic access.',
    commonMisconfigs: [
      'Access keys created by default during user setup',
      'Users with console access also have unnecessary access keys',
      'Keys created but never rotated or used',
    ],
    fixHint: 'Modify user creation process to not create access keys by default. Remove unused access keys from console users.',
  },
  {
    id: 'CIS-AWS-2.12',
    title: 'Ensure there is only one active access key available for any single IAM user',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify each IAM user has at most one active access key.',
    whyItMatters: 'Multiple active keys expand the attack surface. If one key is compromised, having multiple makes rotation more complex.',
    consoleSteps: [
      'Go to IAM > Users',
      'For each user, click Security credentials tab',
      'Check the Access keys section',
      'Ensure no user has more than one Active access key',
    ],
    cliCheck: 'aws iam list-users --query "Users[*].UserName" --output text | xargs -I {} sh -c \'echo "User: {}"; aws iam list-access-keys --user-name {} --query "AccessKeyMetadata[?Status==`Active`]"\'',
    expectedConfig: 'Each IAM user should have at most one active access key.',
    commonMisconfigs: [
      'Multiple active keys per user',
      'Old keys not deactivated after rotation',
      'Keys created for testing not removed',
    ],
    fixHint: 'Deactivate and delete secondary access keys. Implement key rotation that ensures only one active key at a time.',
  },
  {
    id: 'CIS-AWS-2.14',
    title: 'Ensure IAM users receive permissions only through groups',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that IAM users do not have inline or directly attached policies.',
    whyItMatters: 'Managing permissions through groups simplifies access management and makes auditing easier. Direct user policies are harder to track.',
    consoleSteps: [
      'Go to IAM > Users',
      'For each user, review the Permissions tab',
      'Check that "Attached directly" policies section is empty',
      'Verify no inline policies exist',
    ],
    cliCheck: 'for user in $(aws iam list-users --query "Users[*].UserName" --output text); do echo "User: $user"; aws iam list-attached-user-policies --user-name $user; aws iam list-user-policies --user-name $user; done',
    expectedConfig: 'Users should have no directly attached policies. All permissions should come from group membership.',
    commonMisconfigs: [
      'Policies attached directly to users',
      'Inline policies on individual users',
      'Permissions not managed through groups',
    ],
    fixHint: 'Create appropriate IAM groups with required policies. Add users to groups and remove direct policy attachments.',
  },
  {
    id: 'CIS-AWS-2.16',
    title: 'Ensure a support role has been created to manage incidents with AWS Support',
    severity: 'Low',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify a support role exists with AWSSupportAccess policy.',
    whyItMatters: 'A dedicated support role ensures proper access to AWS Support without granting excessive permissions.',
    consoleSteps: [
      'Go to IAM > Policies',
      'Search for AWSSupportAccess',
      'Click on the policy and review attached entities',
      'Verify at least one role has this policy attached',
    ],
    cliCheck: 'aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess',
    expectedConfig: 'At least one IAM role should have AWSSupportAccess policy attached.',
    commonMisconfigs: [
      'No support role exists',
      'Support access granted through overly permissive roles',
      'Individual users have support access instead of assuming a role',
    ],
    fixHint: 'Create a dedicated IAM role with AWSSupportAccess policy. Configure role assumption for authorized personnel.',
  },
  {
    id: 'CIS-AWS-2.17',
    title: 'Ensure IAM instance roles are used for AWS resource access from instances',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify EC2 instances use IAM roles instead of embedded access keys.',
    whyItMatters: 'Instance roles provide temporary credentials that are automatically rotated. Embedded keys are static and can be compromised.',
    consoleSteps: [
      'Go to EC2 > Instances',
      'Check each instance for IAM role assignment',
      'Verify applications on instances are not using long-term credentials',
      'Review instance metadata service configuration',
    ],
    cliCheck: 'aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn]" --output table',
    expectedConfig: 'All EC2 instances requiring AWS API access should have an IAM instance profile/role attached.',
    commonMisconfigs: [
      'EC2 instances without instance profiles',
      'Access keys stored on instances',
      'Credentials hardcoded in application code',
    ],
    fixHint: 'Create IAM roles with required permissions. Attach roles to EC2 instances. Remove any hardcoded credentials.',
  },
  {
    id: 'CIS-AWS-2.18',
    title: 'Ensure expired SSL/TLS certificates stored in AWS IAM are removed',
    severity: 'Low',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify that expired SSL/TLS certificates are removed from IAM.',
    whyItMatters: 'Expired certificates can cause service disruptions and indicate poor certificate lifecycle management.',
    consoleSteps: [
      'Go to IAM > Server certificates (or use ACM)',
      'Review all certificates listed',
      'Check expiration dates for each certificate',
      'Identify and remove expired certificates',
    ],
    cliCheck: 'aws iam list-server-certificates --query "ServerCertificateMetadataList[?Expiration<`$(date -u +%Y-%m-%dT%H:%M:%SZ)`]"',
    expectedConfig: 'No expired certificates should exist in IAM. Use ACM for automatic renewal where possible.',
    commonMisconfigs: [
      'Expired certificates not removed',
      'Certificates approaching expiration without renewal plan',
      'Using IAM for certificates instead of ACM',
    ],
    fixHint: 'Delete expired certificates. Migrate to ACM for automatic certificate renewal. Set up expiration monitoring.',
  },
  {
    id: 'CIS-AWS-2.19',
    title: 'Ensure IAM Access Analyzer is enabled for all regions',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify IAM Access Analyzer is enabled in all regions to identify resources shared externally.',
    whyItMatters: 'Access Analyzer continuously monitors for resource policies that grant access to external principals.',
    consoleSteps: [
      'Go to IAM > Access Analyzer',
      'Review analyzers in each region',
      'Ensure an analyzer exists for each active region',
      'Review any active findings',
    ],
    cliCheck: 'for region in $(aws ec2 describe-regions --query "Regions[*].RegionName" --output text); do echo "Region: $region"; aws accessanalyzer list-analyzers --region $region --query "analyzers[*].name"; done',
    expectedConfig: 'IAM Access Analyzer should be enabled in all regions with active resources.',
    commonMisconfigs: [
      'Access Analyzer not enabled',
      'Only enabled in some regions',
      'Findings not reviewed or remediated',
    ],
    fixHint: 'Enable Access Analyzer in all regions. Review and remediate findings regularly.',
  },
  {
    id: 'CIS-AWS-2.20',
    title: 'Ensure IAM users are managed centrally via identity federation or AWS Organizations',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify identity management is centralized using SSO, federation, or AWS Organizations.',
    whyItMatters: 'Centralized identity management reduces duplicate accounts, ensures consistent policies, and simplifies access revocation.',
    consoleSteps: [
      'Check if AWS IAM Identity Center (SSO) is configured',
      'Review identity provider federation settings',
      'Verify AWS Organizations is used for multi-account management',
      'Ensure local IAM users are minimized',
    ],
    cliCheck: 'aws organizations describe-organization; aws sso-admin list-instances',
    expectedConfig: 'IAM Identity Center or SAML federation should be the primary identity source. Local IAM users minimized.',
    commonMisconfigs: [
      'No identity federation configured',
      'Many local IAM users across accounts',
      'Inconsistent identity management',
    ],
    fixHint: 'Implement AWS IAM Identity Center for centralized access. Use federation with corporate IdP. Minimize local IAM users.',
  },
  {
    id: 'CIS-AWS-2.21',
    title: 'Ensure AWSCloudShellFullAccess is not directly attached to any IAM principal',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify AWSCloudShellFullAccess policy is not attached to users, groups, or roles.',
    whyItMatters: 'CloudShell provides a persistent environment that can be used to exfiltrate data. Full access should be restricted.',
    consoleSteps: [
      'Go to IAM > Policies',
      'Search for AWSCloudShellFullAccess',
      'Click on the policy and check Attached entities',
      'Ensure no direct attachments exist',
    ],
    cliCheck: 'aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess',
    expectedConfig: 'AWSCloudShellFullAccess should not be directly attached to any IAM entity.',
    commonMisconfigs: [
      'Policy attached to users or roles',
      'CloudShell access not restricted by network',
      'No monitoring of CloudShell usage',
    ],
    fixHint: 'Remove AWSCloudShellFullAccess attachments. Use custom policy with restrictions if CloudShell is required.',
  },

  // Storage Additional Controls
  {
    id: 'CIS-AWS-3.1.2',
    title: 'Ensure MFA Delete is enabled on S3 buckets',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify MFA Delete is enabled on S3 buckets storing sensitive data.',
    whyItMatters: 'MFA Delete adds an additional layer of protection against accidental or malicious deletion of S3 objects.',
    consoleSteps: [
      'Go to S3 > select bucket',
      'Click Properties tab',
      'Check Bucket Versioning section',
      'Verify MFA Delete is enabled (requires root credentials to configure)',
    ],
    cliCheck: 'aws s3api get-bucket-versioning --bucket <bucket-name>',
    expectedConfig: 'MFA Delete should be enabled for buckets containing sensitive or critical data.',
    commonMisconfigs: [
      'MFA Delete not enabled',
      'Versioning enabled without MFA Delete',
      'Root credentials not available to enable',
    ],
    fixHint: 'Enable MFA Delete using root account credentials: aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "arn:aws:iam::<account-id>:mfa/root-account-mfa-device <mfa-code>"',
  },
  {
    id: 'CIS-AWS-3.1.3',
    title: 'Ensure S3 Object Lock is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify S3 Object Lock is configured for buckets requiring immutable storage.',
    whyItMatters: 'Object Lock provides WORM (Write Once Read Many) protection for regulatory compliance and ransomware protection.',
    consoleSteps: [
      'Go to S3 > select bucket',
      'Check if Object Lock was enabled during bucket creation',
      'Review Object Lock configuration in Properties',
      'Verify retention mode and period are appropriate',
    ],
    cliCheck: 'aws s3api get-object-lock-configuration --bucket <bucket-name>',
    expectedConfig: 'Object Lock should be enabled with appropriate retention for compliance-sensitive data.',
    commonMisconfigs: [
      'Object Lock not enabled (can only be set at bucket creation)',
      'Inappropriate retention periods',
      'Governance mode used instead of Compliance when required',
    ],
    fixHint: 'Create new buckets with Object Lock enabled. Migrate data to Object Lock-enabled buckets. Configure appropriate retention.',
  },
  {
    id: 'CIS-AWS-3.1.4',
    title: 'Ensure S3 Block Public Access is enabled at account level',
    severity: 'Critical',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify S3 Block Public Access settings are enabled at the AWS account level.',
    whyItMatters: 'Account-level block public access prevents any bucket in the account from being made public, even by mistake.',
    consoleSteps: [
      'Go to S3 > Block Public Access settings for this account',
      'Verify all four settings are enabled',
      'Check each bucket for individual overrides',
    ],
    cliCheck: 'aws s3control get-public-access-block --account-id <account-id>',
    expectedConfig: 'All four Block Public Access settings should be enabled at the account level.',
    commonMisconfigs: [
      'Block public access not enabled',
      'Some settings disabled for legacy reasons',
      'Bucket-level overrides that allow public access',
    ],
    fixHint: 'Enable all Block Public Access settings at account level. Review and update any bucket-level overrides.',
  },
  {
    id: 'CIS-AWS-3.2.1',
    title: 'Ensure RDS instances have encryption at rest enabled',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify all RDS database instances have storage encryption enabled.',
    whyItMatters: 'Encryption at rest protects data from unauthorized access to the underlying storage.',
    consoleSteps: [
      'Go to RDS > Databases',
      'Select each database instance',
      'Check Configuration tab for Storage encrypted status',
      'Verify KMS key is appropriate',
    ],
    cliCheck: 'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]"',
    expectedConfig: 'All RDS instances should have StorageEncrypted set to true with appropriate KMS keys.',
    commonMisconfigs: [
      'Encryption not enabled during creation',
      'Using default service key instead of CMK',
      'Legacy instances created before encryption requirement',
    ],
    fixHint: 'Create encrypted snapshot, copy with encryption, restore from encrypted copy. Use CMK for production databases.',
  },
  {
    id: 'CIS-AWS-3.2.2',
    title: 'Ensure RDS Auto Minor Version Upgrade is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify RDS instances have automatic minor version upgrades enabled.',
    whyItMatters: 'Minor version upgrades include security patches. Automatic upgrades ensure timely patching.',
    consoleSteps: [
      'Go to RDS > Databases',
      'Select each database instance',
      'Check Configuration tab for Auto minor version upgrade',
    ],
    cliCheck: 'aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,AutoMinorVersionUpgrade]"',
    expectedConfig: 'AutoMinorVersionUpgrade should be true for all RDS instances.',
    commonMisconfigs: [
      'Auto minor version upgrade disabled',
      'Maintenance window not configured',
      'Manual patching not performed regularly',
    ],
    fixHint: 'Enable Auto Minor Version Upgrade: aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately',
  },
  {
    id: 'CIS-AWS-3.2.3',
    title: 'Ensure RDS instances are not publicly accessible',
    severity: 'Critical',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify RDS database instances do not have public accessibility enabled.',
    whyItMatters: 'Publicly accessible databases are exposed to the internet and vulnerable to attacks.',
    consoleSteps: [
      'Go to RDS > Databases',
      'Select each database instance',
      'Check Connectivity & security tab',
      'Verify Publicly accessible is set to No',
    ],
    cliCheck: 'aws rds describe-db-instances --query "DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Endpoint.Address]"',
    expectedConfig: 'PubliclyAccessible should be false for all RDS instances.',
    commonMisconfigs: [
      'Database created with public accessibility',
      'Public access enabled for debugging not reverted',
      'VPC security groups allow 0.0.0.0/0',
    ],
    fixHint: 'Modify RDS instance to disable public access. Use VPN or Direct Connect for remote access. Review security groups.',
  },

  // Logging Additional Controls
  {
    id: 'CIS-AWS-4.4',
    title: 'Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify server access logging is enabled on S3 buckets storing CloudTrail logs.',
    whyItMatters: 'Access logging on CloudTrail buckets provides audit trail of who accessed the audit logs themselves.',
    consoleSteps: [
      'Identify CloudTrail S3 bucket from CloudTrail configuration',
      'Go to S3 > select the CloudTrail bucket',
      'Click Properties tab',
      'Check Server access logging is enabled',
    ],
    cliCheck: 'aws s3api get-bucket-logging --bucket <cloudtrail-bucket-name>',
    expectedConfig: 'Server access logging should be enabled targeting a separate logging bucket.',
    commonMisconfigs: [
      'Server access logging not enabled',
      'Logs sent to same bucket creating recursion',
      'Logging bucket not properly secured',
    ],
    fixHint: 'Enable server access logging on CloudTrail bucket. Use separate bucket for access logs. Secure logging bucket.',
  },
  {
    id: 'CIS-AWS-4.5',
    title: 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify CloudTrail is configured to use KMS Customer Managed Keys for encryption.',
    whyItMatters: 'CMK encryption provides additional protection and allows you to control access to CloudTrail logs through key policies.',
    consoleSteps: [
      'Go to CloudTrail > Trails',
      'Select each trail',
      'Check General details for KMS alias or ARN',
      'Verify a CMK is configured, not default encryption',
    ],
    cliCheck: 'aws cloudtrail describe-trails --query "trailList[*].[Name,KMSKeyId]"',
    expectedConfig: 'All CloudTrail trails should use a customer managed KMS key for encryption.',
    commonMisconfigs: [
      'Using S3 default encryption instead of CMK',
      'KMS key policy too permissive',
      'No CMK configured',
    ],
    fixHint: 'Create KMS CMK for CloudTrail. Update trail to use CMK. Configure key policy for appropriate access.',
  },
  {
    id: 'CIS-AWS-4.6',
    title: 'Ensure rotation for customer-created CMKs is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify automatic key rotation is enabled for all customer-created symmetric KMS keys.',
    whyItMatters: 'Key rotation limits the amount of data encrypted under one key version, reducing impact of key compromise.',
    consoleSteps: [
      'Go to KMS > Customer managed keys',
      'Select each symmetric key',
      'Check Key rotation tab',
      'Verify Automatic key rotation is enabled',
    ],
    cliCheck: 'aws kms list-keys --query "Keys[*].KeyId" --output text | xargs -I {} aws kms get-key-rotation-status --key-id {}',
    expectedConfig: 'All customer-created symmetric CMKs should have automatic rotation enabled.',
    commonMisconfigs: [
      'Key rotation not enabled',
      'Rotation period too long',
      'Asymmetric keys (cannot be auto-rotated) used where symmetric would work',
    ],
    fixHint: 'Enable key rotation: aws kms enable-key-rotation --key-id <key-id>. Note: asymmetric keys require manual rotation.',
  },
  {
    id: 'CIS-AWS-4.7',
    title: 'Ensure VPC flow logging is enabled in all VPCs',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify VPC Flow Logs are enabled for all VPCs.',
    whyItMatters: 'VPC Flow Logs capture network traffic information, essential for security analysis and troubleshooting.',
    consoleSteps: [
      'Go to VPC > Your VPCs',
      'Select each VPC',
      'Check Flow logs tab',
      'Verify at least one flow log is active',
    ],
    cliCheck: 'for vpc in $(aws ec2 describe-vpcs --query "Vpcs[*].VpcId" --output text); do echo "VPC: $vpc"; aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query "FlowLogs[*].[FlowLogId,FlowLogStatus]"; done',
    expectedConfig: 'Each VPC should have at least one active flow log capturing ACCEPT and REJECT traffic.',
    commonMisconfigs: [
      'Flow logs not enabled',
      'Only capturing ACCEPT or REJECT, not both',
      'Logs not retained long enough',
    ],
    fixHint: 'Create VPC Flow Logs for each VPC. Configure to capture all traffic. Send to CloudWatch Logs or S3.',
  },
  {
    id: 'CIS-AWS-4.8',
    title: 'Ensure S3 bucket object-level logging for read events is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify CloudTrail data events are enabled for S3 read operations on sensitive buckets.',
    whyItMatters: 'Object-level logging provides visibility into who accessed specific objects in S3.',
    consoleSteps: [
      'Go to CloudTrail > Trails',
      'Select trail and check Data events',
      'Verify S3 data events include Read events',
      'Check sensitive buckets are included',
    ],
    cliCheck: 'aws cloudtrail get-event-selectors --trail-name <trail-name>',
    expectedConfig: 'Data events should be configured for S3 read operations on buckets containing sensitive data.',
    commonMisconfigs: [
      'No data events configured',
      'Only write events logged',
      'Not all sensitive buckets included',
    ],
    fixHint: 'Configure CloudTrail data events for S3. Include read and write events for sensitive buckets.',
  },
  {
    id: 'CIS-AWS-4.9',
    title: 'Ensure S3 bucket object-level logging for write events is enabled',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify CloudTrail data events are enabled for S3 write operations.',
    whyItMatters: 'Object-level write logging tracks modifications to S3 objects, critical for data integrity monitoring.',
    consoleSteps: [
      'Go to CloudTrail > Trails',
      'Select trail and check Data events',
      'Verify S3 data events include Write events',
      'Check all critical buckets are included',
    ],
    cliCheck: 'aws cloudtrail get-event-selectors --trail-name <trail-name>',
    expectedConfig: 'Data events should be configured for S3 write operations on all critical buckets.',
    commonMisconfigs: [
      'Write events not logged',
      'Only some buckets included',
      'Data events disabled due to cost',
    ],
    fixHint: 'Enable S3 data events for write operations in CloudTrail. Balance cost with security requirements.',
  },

  // Monitoring Controls
  {
    id: 'CIS-AWS-5.1',
    title: 'Ensure log metric filter and alarm exist for unauthorized API calls',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify CloudWatch metric filter and alarm for unauthorized API calls exist.',
    whyItMatters: 'Monitoring unauthorized API calls helps detect potential credential compromise or permission issues.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Select CloudTrail log group',
      'Check Metric filters for unauthorized API pattern',
      'Verify alarm exists for the metric',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for errorCode = *UnauthorizedOperation or AccessDenied* with associated alarm.',
    commonMisconfigs: [
      'No metric filter exists',
      'Filter exists but no alarm',
      'Alarm not triggering notifications',
    ],
    fixHint: 'Create metric filter: { ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }. Create alarm for metric.',
  },
  {
    id: 'CIS-AWS-5.2',
    title: 'Ensure log metric filter and alarm exist for console sign-in without MFA',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for console logins without MFA.',
    whyItMatters: 'Detecting console access without MFA helps identify accounts that bypass security controls.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check metric filters in CloudTrail log group',
      'Look for filter matching ConsoleLogin without MFA',
      'Verify alarm exists',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for console login events where MFA was not used, with associated alarm.',
    commonMisconfigs: [
      'No monitoring for non-MFA logins',
      'Metric filter pattern incorrect',
      'Alarm not configured',
    ],
    fixHint: 'Create metric filter: { ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }. Create alarm.',
  },
  {
    id: 'CIS-AWS-5.3',
    title: 'Ensure log metric filter and alarm exist for root account usage',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for any usage of the root account.',
    whyItMatters: 'Root account usage should be rare. Any activity should be investigated immediately.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check metric filters in CloudTrail log group',
      'Look for filter matching root user activity',
      'Verify alarm exists with high priority notification',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for root account activity with immediate alarm notification.',
    commonMisconfigs: [
      'No root activity monitoring',
      'Filter only catches login, not all activity',
      'Alarm not set to high priority',
    ],
    fixHint: 'Create metric filter: { $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
  },
  {
    id: 'CIS-AWS-5.4',
    title: 'Ensure log metric filter and alarm exist for IAM policy changes',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for changes to IAM policies.',
    whyItMatters: 'IAM policy changes can grant or remove permissions. Unauthorized changes could indicate compromise.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check metric filters for IAM policy events',
      'Verify filter covers create, delete, attach, detach operations',
      'Confirm alarm is configured',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for IAM policy modification events with associated alarm.',
    commonMisconfigs: [
      'No IAM change monitoring',
      'Filter misses some policy change types',
      'Alarm thresholds too high',
    ],
    fixHint: 'Create metric filter for DeleteGroupPolicy, DeleteRolePolicy, DeleteUserPolicy, PutGroupPolicy, PutRolePolicy, PutUserPolicy, etc.',
  },
  {
    id: 'CIS-AWS-5.5',
    title: 'Ensure log metric filter and alarm exist for CloudTrail configuration changes',
    severity: 'High',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for changes to CloudTrail configuration.',
    whyItMatters: 'CloudTrail changes could indicate an attacker trying to cover their tracks.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check for metric filter on CloudTrail API calls',
      'Verify StopLogging, DeleteTrail, UpdateTrail are monitored',
      'Confirm alarm exists',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for CloudTrail configuration changes with high-priority alarm.',
    commonMisconfigs: [
      'No CloudTrail change monitoring',
      'StopLogging not specifically monitored',
      'Alarm not immediate',
    ],
    fixHint: 'Create metric filter: { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }',
  },
  {
    id: 'CIS-AWS-5.10',
    title: 'Ensure log metric filter and alarm exist for security group changes',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for security group modifications.',
    whyItMatters: 'Security group changes affect network access controls and could expose resources to unauthorized access.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check for metric filter on security group events',
      'Verify create, delete, authorize, revoke operations monitored',
      'Confirm alarm exists',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for security group changes with associated alarm.',
    commonMisconfigs: [
      'No security group monitoring',
      'Missing some operation types',
      'Alarm not configured',
    ],
    fixHint: 'Create metric filter for CreateSecurityGroup, DeleteSecurityGroup, AuthorizeSecurityGroupIngress, AuthorizeSecurityGroupEgress, RevokeSecurityGroupIngress, RevokeSecurityGroupEgress.',
  },
  {
    id: 'CIS-AWS-5.11',
    title: 'Ensure log metric filter and alarm exist for NACL changes',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for Network ACL modifications.',
    whyItMatters: 'NACL changes affect subnet-level traffic filtering and could allow unauthorized network access.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check for metric filter on NACL events',
      'Verify create, delete, replace operations monitored',
      'Confirm alarm exists',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for NACL changes with associated alarm.',
    commonMisconfigs: [
      'No NACL monitoring',
      'Filter pattern incomplete',
      'No alarm configured',
    ],
    fixHint: 'Create metric filter for CreateNetworkAcl, CreateNetworkAclEntry, DeleteNetworkAcl, DeleteNetworkAclEntry, ReplaceNetworkAclEntry, ReplaceNetworkAclAssociation.',
  },
  {
    id: 'CIS-AWS-5.14',
    title: 'Ensure log metric filter and alarm exist for VPC changes',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for VPC modifications.',
    whyItMatters: 'VPC changes affect network architecture and could indicate unauthorized infrastructure modifications.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check for metric filter on VPC events',
      'Verify VPC, subnet, route table, gateway operations monitored',
      'Confirm alarm exists',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for VPC changes with associated alarm.',
    commonMisconfigs: [
      'No VPC monitoring',
      'Only some VPC operations covered',
      'Alarm not configured',
    ],
    fixHint: 'Create metric filter for CreateVpc, DeleteVpc, ModifyVpcAttribute, AcceptVpcPeeringConnection, CreateVpcPeeringConnection, DeleteVpcPeeringConnection, RejectVpcPeeringConnection, AttachClassicLinkVpc, DetachClassicLinkVpc, DisableVpcClassicLink, EnableVpcClassicLink.',
  },
  {
    id: 'CIS-AWS-5.15',
    title: 'Ensure log metric filter and alarm exist for AWS Organizations changes',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for AWS Organizations modifications.',
    whyItMatters: 'Organizations changes affect account structure and policies across the entire organization.',
    consoleSteps: [
      'Go to CloudWatch > Log groups',
      'Check for metric filter on Organizations events',
      'Verify account, policy, OU operations monitored',
      'Confirm alarm exists',
    ],
    cliCheck: 'aws logs describe-metric-filters --log-group-name <cloudtrail-log-group>',
    expectedConfig: 'Metric filter for AWS Organizations changes with associated alarm.',
    commonMisconfigs: [
      'No Organizations monitoring',
      'SCP changes not monitored',
      'Account creation not alerted',
    ],
    fixHint: 'Create metric filter for organizations events: AcceptHandshake, AttachPolicy, CreateAccount, CreateOrganization, CreatePolicy, DeclineHandshake, DeleteOrganization, DeletePolicy, DetachPolicy, etc.',
  },

  // ============================================
  // ADDITIONAL AZURE CIS CONTROLS - v2.0.0
  // ============================================

  // App Service Additional Controls
  {
    id: 'CIS-AZ-2.1.5',
    title: 'Ensure Web App is using FTPS only or FTP disabled',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify App Service FTP state is set to FTPS only or Disabled.',
    whyItMatters: 'FTP transmits credentials in clear text. FTPS provides encryption for credential transmission.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Go to Configuration > General settings',
      'Verify FTP state is FTPS Only or Disabled',
    ],
    cliCheck: 'az webapp config show --name <app-name> --resource-group <rg> --query ftpsState',
    expectedConfig: 'FTP state should be "FtpsOnly" or "Disabled".',
    commonMisconfigs: [
      'FTP state set to AllAllowed',
      'Legacy applications requiring FTP',
      'FTP enabled for troubleshooting not reverted',
    ],
    fixHint: 'az webapp config set --name <app-name> --resource-group <rg> --ftps-state FtpsOnly',
  },
  {
    id: 'CIS-AZ-2.1.6',
    title: 'Ensure HTTP Version is latest for Web Apps',
    severity: 'Low',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify App Service is using HTTP/2.',
    whyItMatters: 'HTTP/2 provides performance improvements including multiplexing, header compression, and server push.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Go to Configuration > General settings',
      'Verify HTTP version is set to 2.0',
    ],
    cliCheck: 'az webapp config show --name <app-name> --resource-group <rg> --query http20Enabled',
    expectedConfig: 'HTTP 2.0 should be enabled (http20Enabled: true).',
    commonMisconfigs: [
      'Using HTTP 1.1',
      'Legacy client compatibility concerns',
    ],
    fixHint: 'az webapp config set --name <app-name> --resource-group <rg> --http20-enabled true',
  },
  {
    id: 'CIS-AZ-2.1.9',
    title: 'Ensure Web App has end-to-end TLS encryption enabled',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify traffic between App Service and backends uses TLS.',
    whyItMatters: 'End-to-end encryption ensures traffic is encrypted even within the Azure network.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Review backend configurations',
      'Verify backends are accessed over HTTPS',
    ],
    cliCheck: 'az webapp show --name <app-name> --resource-group <rg>',
    expectedConfig: 'All backend connections should use HTTPS/TLS.',
    commonMisconfigs: [
      'Backend connections over HTTP',
      'Self-signed certificates on backends',
      'Mixed content issues',
    ],
    fixHint: 'Configure all backend endpoints with valid TLS certificates. Update application code to use HTTPS for backend calls.',
  },
  {
    id: 'CIS-AZ-2.1.12',
    title: 'Ensure App Service Authentication is set up for apps in Azure App Service',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify App Service Authentication (EasyAuth) is enabled for web apps.',
    whyItMatters: 'Built-in authentication provides consistent identity validation without modifying application code.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Go to Authentication',
      'Verify authentication provider is configured',
    ],
    cliCheck: 'az webapp auth show --name <app-name> --resource-group <rg>',
    expectedConfig: 'App Service Authentication should be enabled with appropriate identity provider.',
    commonMisconfigs: [
      'No authentication configured',
      'Authentication allows anonymous access',
      'Token store not enabled',
    ],
    fixHint: 'Configure App Service Authentication with Microsoft Entra ID or other identity provider. Set Action to take when request is not authenticated.',
  },
  {
    id: 'CIS-AZ-2.1.13',
    title: 'Ensure Managed Identity is used in Azure App Service',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify web apps use managed identities for Azure resource access.',
    whyItMatters: 'Managed identities eliminate the need for credentials in code, reducing credential exposure risk.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Go to Identity',
      'Verify System assigned or User assigned identity is enabled',
    ],
    cliCheck: 'az webapp identity show --name <app-name> --resource-group <rg>',
    expectedConfig: 'Managed identity should be enabled (system-assigned or user-assigned).',
    commonMisconfigs: [
      'No managed identity configured',
      'Connection strings with credentials instead of managed identity',
      'Service principals used instead of managed identity',
    ],
    fixHint: 'az webapp identity assign --name <app-name> --resource-group <rg>. Update application to use DefaultAzureCredential.',
  },
  {
    id: 'CIS-AZ-2.1.14',
    title: 'Ensure public network access is disabled for App Service',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify public network access is disabled for internal apps.',
    whyItMatters: 'Disabling public access reduces attack surface by limiting access to private networks.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Go to Networking > Access restriction',
      'Verify public access is restricted or use Private Endpoints',
    ],
    cliCheck: 'az webapp config access-restriction show --name <app-name> --resource-group <rg>',
    expectedConfig: 'Public network access disabled or restricted to known IPs. Private Endpoints for internal apps.',
    commonMisconfigs: [
      'Public access enabled for internal apps',
      'No access restrictions configured',
      'Private endpoints not used',
    ],
    fixHint: 'Configure access restrictions or Private Endpoints. Disable public network access for internal-only applications.',
  },
  {
    id: 'CIS-AZ-2.1.21',
    title: 'Ensure CORS does not allow every resource to access Web Apps',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify CORS is not configured to allow all origins (*).',
    whyItMatters: 'Overly permissive CORS allows any website to make requests to your application.',
    consoleSteps: [
      'Go to App Services',
      'Select each web app',
      'Go to API > CORS',
      'Verify * is not in Allowed Origins',
    ],
    cliCheck: 'az webapp cors show --name <app-name> --resource-group <rg>',
    expectedConfig: 'CORS should only allow specific, trusted origins. No wildcard (*).',
    commonMisconfigs: [
      'Wildcard (*) in allowed origins',
      'Too many origins allowed',
      'CORS not restricted during development',
    ],
    fixHint: 'Remove * from allowed origins. Add only specific trusted domains that require cross-origin access.',
  },

  // Function Apps Controls
  {
    id: 'CIS-AZ-2.3.4',
    title: 'Ensure FTP is disabled for Azure Functions',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify Function Apps have FTP disabled.',
    whyItMatters: 'FTP access to function apps is rarely needed and expands the attack surface.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Configuration > General settings',
      'Verify FTP state is Disabled',
    ],
    cliCheck: 'az functionapp config show --name <app-name> --resource-group <rg> --query ftpsState',
    expectedConfig: 'FTP state should be "Disabled" for function apps.',
    commonMisconfigs: [
      'FTP enabled (AllAllowed or FtpsOnly)',
      'FTP used for deployment instead of proper CI/CD',
    ],
    fixHint: 'az functionapp config set --name <app-name> --resource-group <rg> --ftps-state Disabled',
  },
  {
    id: 'CIS-AZ-2.3.6',
    title: 'Ensure Function App is configured to only accept HTTPS traffic',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify Function Apps have HTTPS Only enabled.',
    whyItMatters: 'HTTP traffic is unencrypted and vulnerable to interception.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Configuration > General settings',
      'Verify HTTPS Only is On',
    ],
    cliCheck: 'az functionapp show --name <app-name> --resource-group <rg> --query httpsOnly',
    expectedConfig: 'HTTPS Only should be true.',
    commonMisconfigs: [
      'HTTPS Only disabled',
      'HTTP endpoints still accessible',
    ],
    fixHint: 'az functionapp update --name <app-name> --resource-group <rg> --set httpsOnly=true',
  },
  {
    id: 'CIS-AZ-2.3.7',
    title: 'Ensure Function App is using minimum TLS version 1.2',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify Function Apps use TLS 1.2 as minimum version.',
    whyItMatters: 'Older TLS versions have known vulnerabilities and should be disabled.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Configuration > General settings',
      'Verify Minimum TLS version is 1.2',
    ],
    cliCheck: 'az functionapp config show --name <app-name> --resource-group <rg> --query minTlsVersion',
    expectedConfig: 'Minimum TLS version should be 1.2 or higher.',
    commonMisconfigs: [
      'TLS 1.0 or 1.1 allowed',
      'Legacy client support enabled',
    ],
    fixHint: 'az functionapp config set --name <app-name> --resource-group <rg> --min-tls-version 1.2',
  },
  {
    id: 'CIS-AZ-2.3.9',
    title: 'Ensure Remote Debugging is disabled for Function Apps',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify remote debugging is disabled on Function Apps.',
    whyItMatters: 'Remote debugging opens a port and can be exploited if left enabled.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Configuration > General settings',
      'Verify Remote debugging is Off',
    ],
    cliCheck: 'az functionapp config show --name <app-name> --resource-group <rg> --query remoteDebuggingEnabled',
    expectedConfig: 'Remote debugging should be disabled (false).',
    commonMisconfigs: [
      'Remote debugging left enabled after troubleshooting',
      'Enabled in production environment',
    ],
    fixHint: 'az functionapp config set --name <app-name> --resource-group <rg> --remote-debugging-enabled false',
  },
  {
    id: 'CIS-AZ-2.3.11',
    title: 'Ensure App Service Authentication is configured for Function Apps',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify App Service Authentication is enabled for Function Apps.',
    whyItMatters: 'Built-in authentication secures HTTP-triggered functions without custom code.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Authentication',
      'Verify authentication provider is configured',
    ],
    cliCheck: 'az functionapp auth show --name <app-name> --resource-group <rg>',
    expectedConfig: 'Authentication should be enabled for HTTP-triggered functions.',
    commonMisconfigs: [
      'No authentication configured',
      'Anonymous access allowed',
      'Function-level auth keys used instead of proper identity',
    ],
    fixHint: 'Configure App Service Authentication with Microsoft Entra ID. Set action for unauthenticated requests.',
  },
  {
    id: 'CIS-AZ-2.3.12',
    title: 'Ensure Managed Identity is configured for Function Apps',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify Function Apps use managed identities.',
    whyItMatters: 'Managed identities eliminate credential management for Azure resource access.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Identity',
      'Verify managed identity is enabled',
    ],
    cliCheck: 'az functionapp identity show --name <app-name> --resource-group <rg>',
    expectedConfig: 'System-assigned or user-assigned managed identity should be enabled.',
    commonMisconfigs: [
      'No managed identity',
      'Connection strings with credentials',
      'Environment variables with secrets',
    ],
    fixHint: 'az functionapp identity assign --name <app-name> --resource-group <rg>. Use managed identity bindings.',
  },
  {
    id: 'CIS-AZ-2.3.13',
    title: 'Ensure public network access is disabled for Function Apps',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify public network access is disabled for internal Function Apps.',
    whyItMatters: 'Restricting public access limits exposure to internet-based attacks.',
    consoleSteps: [
      'Go to Function Apps',
      'Select each function app',
      'Go to Networking',
      'Verify access restrictions or Private Endpoints',
    ],
    cliCheck: 'az functionapp config access-restriction show --name <app-name> --resource-group <rg>',
    expectedConfig: 'Public access disabled or restricted. Private Endpoints for internal functions.',
    commonMisconfigs: [
      'Public access enabled',
      'No network restrictions',
      'Internal functions exposed publicly',
    ],
    fixHint: 'Configure access restrictions or Private Endpoints for Function Apps. Disable public access for internal workloads.',
  },

  // Key Vault Control
  {
    id: 'CIS-AZ-2.5.1',
    title: 'Ensure Azure Key Vault is used for storing secrets',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify secrets are stored in Key Vault rather than application settings.',
    whyItMatters: 'Key Vault provides secure secret storage with access policies, audit logging, and rotation capabilities.',
    consoleSteps: [
      'Review App Service and Function App configuration',
      'Check for secrets in Application settings',
      'Verify Key Vault references are used where secrets are needed',
      'Check Key Vault access policies',
    ],
    cliCheck: 'az keyvault list --query "[*].{name:name, location:location}"',
    expectedConfig: 'Secrets should be stored in Key Vault with Key Vault references used in applications.',
    commonMisconfigs: [
      'Secrets in application settings',
      'Hardcoded secrets in code',
      'Key Vault not used',
      'Overly permissive Key Vault access policies',
    ],
    fixHint: 'Migrate secrets to Key Vault. Use Key Vault references: @Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/secret-name/)',
  },

  // ============================================
  // ADDITIONAL GCP CIS CONTROLS - v4.0.0
  // ============================================

  // Logging and Monitoring Controls
  {
    id: 'CIS-GCP-2.2',
    title: 'Ensure log metric filter and alerts exist for project ownership changes',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for project ownership assignment changes.',
    whyItMatters: 'Project ownership changes grant full control over resources and should be closely monitored.',
    consoleSteps: [
      'Go to Logging > Logs Explorer',
      'Check for log-based metrics filtering ownership changes',
      'Go to Monitoring > Alerting',
      'Verify alert policy exists for the metric',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:SetIamPolicy AND protoPayload.serviceData.policyDelta.bindingDeltas.role=roles/owner"',
    expectedConfig: 'Log metric and alert for protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"',
    commonMisconfigs: [
      'No ownership change monitoring',
      'Alert not configured',
      'Notification channel not set up',
    ],
    fixHint: 'Create log-based metric: (protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee). Create alert policy.',
  },
  {
    id: 'CIS-GCP-2.3',
    title: 'Ensure log metric filter and alerts exist for audit configuration changes',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for changes to audit log configuration.',
    whyItMatters: 'Changes to audit configuration could indicate an attacker trying to hide their activities.',
    consoleSteps: [
      'Go to Logging > Logs Explorer',
      'Check for log-based metrics on SetIamPolicy',
      'Verify alert policy exists',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:SetIamPolicy AND protoPayload.methodName:SetIamPolicy"',
    expectedConfig: 'Log metric and alert for audit configuration changes.',
    commonMisconfigs: [
      'No audit change monitoring',
      'Alert thresholds too high',
      'No notification channels',
    ],
    fixHint: 'Create log-based metric: protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*. Create alert.',
  },
  {
    id: 'CIS-GCP-2.4',
    title: 'Ensure log metric filter and alerts exist for custom role changes',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for custom role creation, deletion, or modification.',
    whyItMatters: 'Custom role changes could grant excessive permissions or remove security controls.',
    consoleSteps: [
      'Go to Logging > Log-based Metrics',
      'Check for metric filtering custom role operations',
      'Verify associated alert policy exists',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:iam.roles"',
    expectedConfig: 'Log metric and alert for iam.roles.create, iam.roles.delete, iam.roles.update operations.',
    commonMisconfigs: [
      'No custom role monitoring',
      'Only monitoring creation, not updates',
      'No alerting configured',
    ],
    fixHint: 'Create log-based metric: resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR "DeleteRole" OR "UpdateRole"). Create alert.',
  },
  {
    id: 'CIS-GCP-2.5',
    title: 'Ensure log metric filter and alerts exist for VPC network firewall rule changes',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for VPC firewall rule modifications.',
    whyItMatters: 'Firewall rule changes directly affect network security posture.',
    consoleSteps: [
      'Go to Logging > Log-based Metrics',
      'Check for metric filtering firewall operations',
      'Go to Monitoring > Alerting',
      'Verify alert policy exists',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:compute.firewalls"',
    expectedConfig: 'Log metric and alert for firewall create, delete, patch, insert operations.',
    commonMisconfigs: [
      'No firewall change monitoring',
      'Missing some operation types',
      'No immediate alerting',
    ],
    fixHint: 'Create log-based metric: resource.type="gce_firewall_rule" AND protoPayload.methodName:(insert OR patch OR delete). Create alert policy.',
  },
  {
    id: 'CIS-GCP-2.6',
    title: 'Ensure log metric filter and alerts exist for VPC network route changes',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for VPC route modifications.',
    whyItMatters: 'Route changes can redirect traffic and potentially expose data to unauthorized parties.',
    consoleSteps: [
      'Go to Logging > Log-based Metrics',
      'Check for metric filtering route operations',
      'Verify associated alert policy',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:compute.routes"',
    expectedConfig: 'Log metric and alert for route create, delete operations.',
    commonMisconfigs: [
      'No route change monitoring',
      'Alert not configured',
    ],
    fixHint: 'Create log-based metric: resource.type="gce_route" AND protoPayload.methodName:(insert OR delete). Create alert.',
  },
  {
    id: 'CIS-GCP-2.7',
    title: 'Ensure log metric filter and alerts exist for VPC network changes',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for VPC network creation, deletion, or modification.',
    whyItMatters: 'VPC network changes affect the overall network architecture and security boundaries.',
    consoleSteps: [
      'Go to Logging > Log-based Metrics',
      'Check for metric filtering network operations',
      'Verify alert policy exists',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:compute.networks"',
    expectedConfig: 'Log metric and alert for VPC network modifications.',
    commonMisconfigs: [
      'No VPC network monitoring',
      'Missing peering or subnetwork changes',
    ],
    fixHint: 'Create log-based metric: resource.type="gce_network" AND protoPayload.methodName:(insert OR patch OR delete OR addPeering OR removePeering). Create alert.',
  },
  {
    id: 'CIS-GCP-2.8',
    title: 'Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for Cloud Storage bucket IAM changes.',
    whyItMatters: 'Storage IAM changes could expose sensitive data to unauthorized access.',
    consoleSteps: [
      'Go to Logging > Log-based Metrics',
      'Check for metric filtering storage.setIamPermissions',
      'Verify alert policy exists',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:storage.setIamPermissions"',
    expectedConfig: 'Log metric and alert for Cloud Storage IAM permission changes.',
    commonMisconfigs: [
      'No storage IAM monitoring',
      'Only monitoring bucket-level, not object-level',
    ],
    fixHint: 'Create log-based metric: resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions". Create alert.',
  },
  {
    id: 'CIS-GCP-2.9',
    title: 'Ensure log metric filter and alerts exist for Cloud SQL instance configuration changes',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify monitoring exists for Cloud SQL configuration changes.',
    whyItMatters: 'SQL instance configuration changes can affect security settings and access controls.',
    consoleSteps: [
      'Go to Logging > Log-based Metrics',
      'Check for metric filtering cloudsql.instances operations',
      'Verify alert policy exists',
    ],
    cliCheck: 'gcloud logging metrics list --filter="filter:cloudsql.instances"',
    expectedConfig: 'Log metric and alert for Cloud SQL configuration changes.',
    commonMisconfigs: [
      'No SQL configuration monitoring',
      'Missing database flag changes',
    ],
    fixHint: 'Create log-based metric: protoPayload.methodName:(cloudsql.instances.update OR cloudsql.instances.patch). Create alert.',
  },
  {
    id: 'CIS-GCP-2.12',
    title: 'Ensure Cloud DNS logging is enabled for all VPC networks',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify DNS query logging is enabled for Cloud DNS.',
    whyItMatters: 'DNS logs help detect data exfiltration, malware communication, and suspicious domain queries.',
    consoleSteps: [
      'Go to Network Services > Cloud DNS',
      'Select each DNS policy',
      'Verify logging is enabled',
    ],
    cliCheck: 'gcloud dns policies list --format="table(name,enableLogging)"',
    expectedConfig: 'Cloud DNS logging should be enabled for all VPC networks.',
    commonMisconfigs: [
      'DNS logging not enabled',
      'Logging only on some networks',
      'Logs not retained',
    ],
    fixHint: 'gcloud dns policies create <policy-name> --enable-logging --networks=<network-name>',
  },
  {
    id: 'CIS-GCP-2.13',
    title: 'Ensure Cloud Asset Inventory is enabled',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify Cloud Asset Inventory API is enabled and feeds are configured.',
    whyItMatters: 'Asset Inventory provides visibility into all GCP resources for security and compliance.',
    consoleSteps: [
      'Go to APIs & Services',
      'Verify Cloud Asset API is enabled',
      'Check for asset feeds or exports',
    ],
    cliCheck: 'gcloud services list --filter="name:cloudasset.googleapis.com"',
    expectedConfig: 'Cloud Asset Inventory API enabled with appropriate feeds for security monitoring.',
    commonMisconfigs: [
      'API not enabled',
      'No asset feeds configured',
      'No integration with security tools',
    ],
    fixHint: 'Enable Cloud Asset API: gcloud services enable cloudasset.googleapis.com. Configure asset feeds for Security Command Center.',
  },

  // Networking Additional Controls
  {
    id: 'CIS-GCP-3.2',
    title: 'Ensure legacy networks do not exist',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify no legacy networks exist in the project.',
    whyItMatters: 'Legacy networks do not support modern features like subnets, Private Google Access, or VPC Flow Logs.',
    consoleSteps: [
      'Go to VPC Networks',
      'Check for any networks without subnet mode',
      'Legacy networks will not show subnets',
    ],
    cliCheck: 'gcloud compute networks list --format="table(name,autoCreateSubnetworks,x_gcloud_subnet_mode)"',
    expectedConfig: 'No legacy networks should exist. All networks should be VPC networks.',
    commonMisconfigs: [
      'Legacy network still in use',
      'Migrated project with legacy network',
    ],
    fixHint: 'Migrate workloads to VPC networks. Delete legacy networks after migration.',
  },
  {
    id: 'CIS-GCP-3.3',
    title: 'Ensure DNSSEC is enabled for Cloud DNS',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify DNSSEC is enabled for public DNS zones.',
    whyItMatters: 'DNSSEC prevents DNS spoofing and cache poisoning attacks.',
    consoleSteps: [
      'Go to Network Services > Cloud DNS',
      'Select each managed zone',
      'Check DNSSEC status',
    ],
    cliCheck: 'gcloud dns managed-zones list --format="table(name,dnsName,dnssecConfig.state)"',
    expectedConfig: 'DNSSEC should be enabled (state: ON) for public DNS zones.',
    commonMisconfigs: [
      'DNSSEC not enabled',
      'DS records not registered with registrar',
    ],
    fixHint: 'gcloud dns managed-zones update <zone-name> --dnssec-state on. Register DS records with domain registrar.',
  },
  {
    id: 'CIS-GCP-3.8',
    title: 'Ensure VPC Flow Logs are enabled for every subnet',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify VPC Flow Logs are enabled for all subnets.',
    whyItMatters: 'Flow Logs capture network traffic for security analysis and troubleshooting.',
    consoleSteps: [
      'Go to VPC Networks > VPC networks',
      'Select each network and view subnets',
      'Check Flow Logs status for each subnet',
    ],
    cliCheck: 'gcloud compute networks subnets list --format="table(name,region,logConfig.enable)"',
    expectedConfig: 'VPC Flow Logs should be enabled for all subnets with appropriate aggregation.',
    commonMisconfigs: [
      'Flow logs not enabled',
      'Enabled on some subnets only',
      'Sampling rate too low',
    ],
    fixHint: 'gcloud compute networks subnets update <subnet> --region=<region> --enable-flow-logs --logging-aggregation-interval=INTERVAL_5_SEC',
  },
  {
    id: 'CIS-GCP-3.9',
    title: 'Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify SSL policies do not allow weak cipher suites.',
    whyItMatters: 'Weak ciphers can be exploited to decrypt TLS traffic.',
    consoleSteps: [
      'Go to Network Services > Load balancing',
      'Check SSL policies on HTTPS load balancers',
      'Verify minimum TLS version and cipher suites',
    ],
    cliCheck: 'gcloud compute ssl-policies list --format="table(name,minTlsVersion,profile)"',
    expectedConfig: 'SSL policies should use MODERN or RESTRICTED profile with TLS 1.2 minimum.',
    commonMisconfigs: [
      'Using COMPATIBLE profile',
      'TLS 1.0 or 1.1 allowed',
      'Weak cipher suites enabled',
    ],
    fixHint: 'gcloud compute ssl-policies create <policy> --profile MODERN --min-tls-version 1.2. Attach to load balancers.',
  },

  // VM Additional Controls
  {
    id: 'CIS-GCP-4.2',
    title: 'Ensure instances are not configured to use default service account with full access',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify VMs do not use default service account with cloud-platform scope.',
    whyItMatters: 'Default SA with full access grants excessive permissions to any code on the instance.',
    consoleSteps: [
      'Go to Compute Engine > VM instances',
      'Check each instance API and identity management section',
      'Verify not using default SA with full access',
    ],
    cliCheck: 'gcloud compute instances list --format="table(name,serviceAccounts[].email,serviceAccounts[].scopes)"',
    expectedConfig: 'Custom service accounts with minimal scopes. No default SA with cloud-platform.',
    commonMisconfigs: [
      'Default service account used',
      'cloud-platform scope granted',
      'No scopes restrictions',
    ],
    fixHint: 'Create custom service account with minimal permissions. Update VM to use custom SA with specific scopes.',
  },
  {
    id: 'CIS-GCP-4.3',
    title: 'Ensure Block Project-Wide SSH Keys is enabled for VM instances',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify instances block project-wide SSH keys.',
    whyItMatters: 'Blocking project-wide keys enforces per-instance SSH key management for better access control.',
    consoleSteps: [
      'Go to Compute Engine > VM instances',
      'Check each instance SSH Keys section',
      'Verify "Block project-wide SSH keys" is enabled',
    ],
    cliCheck: 'gcloud compute instances describe <instance> --format="get(metadata.items)"',
    expectedConfig: 'block-project-ssh-keys should be TRUE for sensitive instances.',
    commonMisconfigs: [
      'Project-wide SSH keys allowed',
      'Inconsistent configuration across instances',
    ],
    fixHint: 'gcloud compute instances add-metadata <instance> --metadata block-project-ssh-keys=TRUE',
  },
  {
    id: 'CIS-GCP-4.4',
    title: 'Ensure OS Login is enabled for VM instances',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify OS Login is enabled for SSH access management.',
    whyItMatters: 'OS Login integrates SSH access with IAM, providing centralized access control and audit logging.',
    consoleSteps: [
      'Go to Compute Engine > Metadata',
      'Check for enable-oslogin key',
      'Verify value is TRUE',
    ],
    cliCheck: 'gcloud compute project-info describe --format="get(commonInstanceMetadata.items)"',
    expectedConfig: 'enable-oslogin should be TRUE at project or instance level.',
    commonMisconfigs: [
      'OS Login not enabled',
      'Using SSH keys instead of OS Login',
      'OS Login only on some instances',
    ],
    fixHint: 'gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE',
  },
  {
    id: 'CIS-GCP-4.6',
    title: 'Ensure IP forwarding is not enabled on instances',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify IP forwarding is disabled unless required for NAT or routing.',
    whyItMatters: 'IP forwarding allows instance to route traffic, which can be misused for traffic interception.',
    consoleSteps: [
      'Go to Compute Engine > VM instances',
      'Check each instance for IP Forwarding setting',
      'Verify it is disabled unless required',
    ],
    cliCheck: 'gcloud compute instances list --format="table(name,canIpForward)"',
    expectedConfig: 'canIpForward should be FALSE except for NAT gateways or router instances.',
    commonMisconfigs: [
      'IP forwarding enabled unnecessarily',
      'Enabled for debugging not reverted',
    ],
    fixHint: 'Recreate instance without IP forwarding. Note: This setting cannot be changed on existing instances.',
  },
  {
    id: 'CIS-GCP-4.8',
    title: 'Ensure Shielded VM is enabled for compute instances',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify Shielded VM options are enabled for instances.',
    whyItMatters: 'Shielded VM provides verifiable integrity through secure boot, vTPM, and integrity monitoring.',
    consoleSteps: [
      'Go to Compute Engine > VM instances',
      'Check each instance Shielded VM settings',
      'Verify vTPM, Secure Boot, and Integrity Monitoring',
    ],
    cliCheck: 'gcloud compute instances describe <instance> --format="get(shieldedInstanceConfig)"',
    expectedConfig: 'enableSecureBoot, enableVtpm, enableIntegrityMonitoring should be true.',
    commonMisconfigs: [
      'Shielded VM not enabled',
      'Only some options enabled',
      'Using non-Shielded VM images',
    ],
    fixHint: 'Create instances with Shielded VM options enabled. Use Shielded VM compatible images.',
  },

  // Cloud SQL Additional Controls
  {
    id: 'CIS-GCP-6.1.2',
    title: 'Ensure skip_show_database flag is set to ON for MySQL instances',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify skip_show_database flag is set to ON for Cloud SQL MySQL.',
    whyItMatters: 'This flag prevents users from seeing databases they do not have privileges to access.',
    consoleSteps: [
      'Go to SQL > select MySQL instance',
      'Click Edit',
      'Check Flags section for skip_show_database',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'skip_show_database flag should be set to ON.',
    commonMisconfigs: [
      'Flag not set',
      'Set to OFF',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags skip_show_database=ON',
  },
  {
    id: 'CIS-GCP-6.1.3',
    title: 'Ensure local_infile flag is set to OFF for MySQL instances',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify local_infile flag is set to OFF for Cloud SQL MySQL.',
    whyItMatters: 'local_infile allows loading data from local files, which can be used for data exfiltration or injection.',
    consoleSteps: [
      'Go to SQL > select MySQL instance',
      'Click Edit',
      'Check Flags section for local_infile',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'local_infile flag should be set to OFF.',
    commonMisconfigs: [
      'Flag not set (defaults to ON)',
      'Set to ON for data loading',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags local_infile=OFF',
  },
  {
    id: 'CIS-GCP-6.2.1',
    title: 'Ensure log_error_verbosity flag is set to DEFAULT or stricter for PostgreSQL',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_error_verbosity is configured appropriately for PostgreSQL.',
    whyItMatters: 'Proper error verbosity helps with troubleshooting while avoiding excessive logging.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit',
      'Check Flags section for log_error_verbosity',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_error_verbosity should be DEFAULT or TERSE.',
    commonMisconfigs: [
      'Set to VERBOSE exposing too much info',
      'Not configured at all',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_error_verbosity=DEFAULT',
  },
  {
    id: 'CIS-GCP-6.2.2',
    title: 'Ensure log_connections flag is set to ON for PostgreSQL',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_connections flag is set to ON for PostgreSQL.',
    whyItMatters: 'Logging connections provides audit trail of who connected to the database.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit',
      'Check Flags section for log_connections',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_connections should be set to ON.',
    commonMisconfigs: [
      'Flag not set',
      'Set to OFF',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_connections=ON',
  },
  {
    id: 'CIS-GCP-6.2.3',
    title: 'Ensure log_disconnections flag is set to ON for PostgreSQL',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_disconnections flag is set to ON for PostgreSQL.',
    whyItMatters: 'Logging disconnections with session duration helps identify unusual patterns.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit',
      'Check Flags section for log_disconnections',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_disconnections should be set to ON.',
    commonMisconfigs: [
      'Flag not set',
      'Set to OFF',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_disconnections=ON',
  },
  {
    id: 'CIS-GCP-6.3.1',
    title: 'Ensure external scripts enabled flag is set to OFF for SQL Server',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify external scripts enabled flag is OFF for SQL Server.',
    whyItMatters: 'External scripts can execute arbitrary code outside the database context.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit',
      'Check Flags section for external scripts enabled',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'external scripts enabled should be set to OFF.',
    commonMisconfigs: [
      'Flag enabled for ML workloads',
      'Not configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags "external scripts enabled=OFF"',
  },
  {
    id: 'CIS-GCP-6.3.5',
    title: 'Ensure remote access flag is set to OFF for SQL Server',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify remote access flag is OFF for SQL Server.',
    whyItMatters: 'Remote access allows execution of stored procedures on remote servers, expanding attack surface.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit',
      'Check Flags section for remote access',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'remote access should be set to OFF.',
    commonMisconfigs: [
      'Remote access enabled',
      'Linked servers configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags "remote access=OFF"',
  },

  // BigQuery Controls
  {
    id: 'CIS-GCP-7.1',
    title: 'Ensure BigQuery datasets are not anonymously or publicly accessible',
    severity: 'Critical',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify BigQuery datasets do not have public or allAuthenticatedUsers access.',
    whyItMatters: 'Public BigQuery datasets can expose sensitive data to anyone on the internet.',
    consoleSteps: [
      'Go to BigQuery > select dataset',
      'Click SHARING > Permissions',
      'Check for allUsers or allAuthenticatedUsers',
    ],
    cliCheck: 'bq show --format=prettyjson <project:dataset> | jq ".access"',
    expectedConfig: 'No allUsers or allAuthenticatedUsers in dataset ACL.',
    commonMisconfigs: [
      'allUsers has access',
      'allAuthenticatedUsers has access',
      'IAM policies too permissive',
    ],
    fixHint: 'Remove allUsers and allAuthenticatedUsers from dataset permissions. Use specific principals.',
  },
  {
    id: 'CIS-GCP-7.2',
    title: 'Ensure BigQuery tables are encrypted with Customer-Managed Keys',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify BigQuery tables use CMEK encryption for sensitive data.',
    whyItMatters: 'CMEK provides additional control over encryption keys and access revocation.',
    consoleSteps: [
      'Go to BigQuery > select table',
      'Check Details tab for encryption type',
      'Verify CMEK is configured for sensitive tables',
    ],
    cliCheck: 'bq show --format=prettyjson <project:dataset.table> | jq ".encryptionConfiguration"',
    expectedConfig: 'Sensitive tables should use Customer-Managed Encryption Key.',
    commonMisconfigs: [
      'Using Google-managed encryption only',
      'CMEK not configured',
      'CMEK key not rotated',
    ],
    fixHint: 'Create table with --destination_kms_key or recreate with CMEK. Configure key rotation.',
  },
  {
    id: 'CIS-GCP-7.3',
    title: 'Ensure default Customer-Managed Encryption Key is specified for BigQuery datasets',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify datasets have default CMEK configured.',
    whyItMatters: 'Default CMEK ensures all new tables in the dataset inherit encryption settings.',
    consoleSteps: [
      'Go to BigQuery > select dataset',
      'Check dataset properties for default encryption',
      'Verify CMEK is the default',
    ],
    cliCheck: 'bq show --format=prettyjson <project:dataset> | jq ".defaultEncryptionConfiguration"',
    expectedConfig: 'Dataset should have defaultEncryptionConfiguration with KMS key.',
    commonMisconfigs: [
      'No default CMEK configured',
      'Tables created with Google-managed keys',
    ],
    fixHint: 'bq update --default_kms_key projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key> <project:dataset>',
  },

  // ============================================
  // ADDITIONAL INTERNAL BASELINE CONTROLS
  // ============================================

  // Azure Internal Baseline
  {
    id: 'INT-AZ-013',
    title: 'Ensure Web Application Firewall (WAF) is enabled for public-facing applications',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify WAF is configured and enabled for public web applications.',
    whyItMatters: 'WAF protects web applications from common attacks like SQL injection and XSS.',
    consoleSteps: [
      'Go to Application Gateway or Front Door',
      'Check WAF policy configuration',
      'Verify WAF mode is Prevention or Detection',
      'Review custom rules and managed rule sets',
    ],
    cliCheck: 'az network application-gateway waf-config show --gateway-name <name> --resource-group <rg>',
    expectedConfig: 'WAF enabled in Prevention mode with OWASP rule set. Custom rules for app-specific protection.',
    commonMisconfigs: [
      'WAF not enabled',
      'Detection mode only',
      'Managed rules not updated',
      'Custom rules not configured',
    ],
    fixHint: 'Enable WAF on Application Gateway or Front Door. Use Prevention mode. Configure OWASP 3.2 rule set.',
  },
  {
    id: 'INT-AZ-014',
    title: 'Ensure network segmentation is implemented for production workloads',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify production, development, and staging environments are network-isolated.',
    whyItMatters: 'Network segmentation limits lateral movement and reduces blast radius of security incidents.',
    consoleSteps: [
      'Review VNet architecture',
      'Verify separate VNets or subnets for each environment',
      'Check NSG rules between segments',
      'Verify peering configurations',
    ],
    expectedConfig: 'Separate VNets or subnets per environment. NSG rules restricting cross-environment traffic.',
    commonMisconfigs: [
      'All environments in same VNet',
      'No NSG rules between segments',
      'Overly permissive peering',
      'Flat network architecture',
    ],
    fixHint: 'Implement hub-spoke VNet architecture. Use NSGs for micro-segmentation. Restrict VNet peering.',
  },
  {
    id: 'INT-AZ-015',
    title: 'Ensure Asset Inventory is maintained and reviewed regularly',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify Azure Resource Graph or similar tool maintains complete asset inventory.',
    whyItMatters: 'Complete asset inventory is essential for security monitoring and compliance.',
    consoleSteps: [
      'Go to Azure Resource Graph Explorer',
      'Run inventory queries',
      'Verify all resource types are tracked',
      'Check for orphaned resources',
    ],
    cliCheck: 'az graph query -q "Resources | summarize count() by type"',
    expectedConfig: 'Complete asset inventory with regular review. Orphaned resources identified and remediated.',
    commonMisconfigs: [
      'No inventory process',
      'Incomplete resource tracking',
      'Orphaned resources not cleaned',
      'No regular review',
    ],
    fixHint: 'Use Azure Resource Graph for inventory. Configure Azure Policy for resource tagging. Schedule regular reviews.',
  },

  // GCP Internal Baseline
  {
    id: 'INT-GCP-009',
    title: 'Ensure default VPC network is not used for production workloads',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'network',
    whatToCheck: 'Verify production workloads are not deployed in default VPC network.',
    whyItMatters: 'Default VPC has overly permissive firewall rules and lacks proper network segmentation.',
    consoleSteps: [
      'Go to VPC Networks',
      'Check if default network exists',
      'Verify no production resources use default network',
    ],
    cliCheck: 'gcloud compute networks list --filter="name=default"',
    expectedConfig: 'Default network deleted or unused. Production workloads in custom VPC networks.',
    commonMisconfigs: [
      'Production resources in default network',
      'Default network not deleted',
      'Default firewall rules active',
    ],
    fixHint: 'Create custom VPC networks. Migrate workloads. Delete default network: gcloud compute networks delete default',
  },
  {
    id: 'INT-GCP-010',
    title: 'Ensure privileged access is documented and reviewed',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify privileged roles (Owner, Editor) are documented with business justification.',
    whyItMatters: 'Privileged access requires oversight to prevent unauthorized actions and ensure accountability.',
    consoleSteps: [
      'Go to IAM & Admin > IAM',
      'Filter by Owner and Editor roles',
      'Verify each assignment has documented justification',
      'Check for service account privileged access',
    ],
    cliCheck: 'gcloud projects get-iam-policy <project> --flatten="bindings[].members" --filter="bindings.role:(roles/owner OR roles/editor)" --format="table(bindings.role,bindings.members)"',
    expectedConfig: 'All privileged access documented. Regular access reviews performed. Justification on file.',
    commonMisconfigs: [
      'Undocumented Owner/Editor access',
      'No access review process',
      'Excessive privileged accounts',
    ],
    fixHint: 'Document all privileged access with justification. Implement quarterly access reviews. Use least privilege.',
  },
  {
    id: 'INT-GCP-011',
    title: 'Ensure security audit process is documented and executed',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify security audit process exists with regular execution evidence.',
    whyItMatters: 'Regular security audits identify misconfigurations and compliance gaps before they become incidents.',
    consoleSteps: [
      'Review Security Command Center findings',
      'Check audit documentation and schedules',
      'Verify remediation tracking process',
      'Confirm audit completion records',
    ],
    expectedConfig: 'Documented audit process. Regular execution (quarterly minimum). Remediation tracking in place.',
    commonMisconfigs: [
      'No audit process documented',
      'Audits not performed regularly',
      'Findings not remediated',
      'No executive reporting',
    ],
    fixHint: 'Document security audit process. Schedule quarterly audits. Track remediation in ticketing system. Report to leadership.',
  },

  // ============================================
  // ADDITIONAL MISSING CONTROLS FROM CHECKLIST/NOTES
  // ============================================

  // Azure Budget and Alert Controls
  {
    id: 'INT-AZ-016',
    title: 'Ensure Budget Rules are configured for all subscriptions',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify budget alerts are configured for cost management.',
    whyItMatters: 'Budget alerts prevent unexpected costs and can indicate security incidents like cryptomining.',
    consoleSteps: [
      'Go to Cost Management + Billing',
      'Select subscription',
      'Check Budgets section',
      'Verify alert thresholds are configured',
    ],
    cliCheck: 'az consumption budget list --subscription <subscription-id>',
    expectedConfig: 'Budget configured with 80%, 100%, 120% alert thresholds. Email notifications enabled.',
    commonMisconfigs: [
      'No budget configured',
      'No alert notifications',
      'Thresholds too high',
      'Wrong recipients',
    ],
    fixHint: 'Create budget with az consumption budget create. Configure email alerts at 80%, 100%, 120%.',
  },
  {
    id: 'INT-AZ-017',
    title: 'Ensure High-Risk Alert Email Notifications are configured in Defender',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify email notifications are enabled for high-severity Defender alerts.',
    whyItMatters: 'Timely notification of high-risk alerts enables rapid incident response.',
    consoleSteps: [
      'Go to Microsoft Defender for Cloud',
      'Select Environment Settings',
      'Check Email Notifications',
      'Verify high-severity alerts trigger emails',
    ],
    cliCheck: 'az security contact list',
    expectedConfig: 'Email notifications enabled. Security team email configured. High severity alerts trigger immediate notification.',
    commonMisconfigs: [
      'No email notifications configured',
      'Wrong email addresses',
      'Only low-severity alerts enabled',
      'Notifications delayed',
    ],
    fixHint: 'Configure security contacts in Defender for Cloud. Enable email for high-severity alerts.',
  },
  {
    id: 'INT-AZ-018',
    title: 'Ensure Security Onboarding Mail was received and verified',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify security onboarding process was completed for new subscriptions/projects.',
    whyItMatters: 'Security onboarding ensures baseline controls are applied from day one.',
    consoleSteps: [
      'Check email records for security onboarding mail',
      'Verify onboarding checklist was completed',
      'Confirm security baseline was applied',
    ],
    expectedConfig: 'Security onboarding mail received. Onboarding checklist completed. Evidence retained.',
    commonMisconfigs: [
      'No onboarding process followed',
      'Onboarding incomplete',
      'No evidence of security review',
    ],
    fixHint: 'Follow organization security onboarding process. Complete checklist and retain evidence.',
  },
  {
    id: 'INT-AZ-019',
    title: 'Ensure Container/VM tagging includes security metadata',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'compute',
    whatToCheck: 'Verify VMs and containers have required security tags (cg_mdatpstatus, cg_mdatpky).',
    whyItMatters: 'Security tags enable tracking of Defender agent status and key compliance.',
    consoleSteps: [
      'Go to Virtual Machines',
      'Check Tags on each VM',
      'Verify cg_mdatpstatus and cg_mdatpky tags exist',
      'Check tag values are current',
    ],
    cliCheck: 'az vm list --query "[].{Name:name, Tags:tags}" -o table',
    expectedConfig: 'All VMs have cg_mdatpstatus=enabled and cg_mdatpky tags. Tags reflect current status.',
    commonMisconfigs: [
      'Missing security tags',
      'Outdated tag values',
      'Tags not enforced via policy',
    ],
    fixHint: 'Apply Azure Policy to enforce security tags. Update existing VMs with required tags.',
  },

  // GCP Additional Controls from Notes
  {
    id: 'INT-GCP-012',
    title: 'Ensure High-Risk Alert Notifications are configured in Security Command Center',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'logging',
    whatToCheck: 'Verify email notifications are enabled for high-severity SCC findings.',
    whyItMatters: 'Timely notification of high-risk findings enables rapid incident response.',
    consoleSteps: [
      'Go to Security Command Center',
      'Select Settings',
      'Check Notifications configuration',
      'Verify Pub/Sub or email notifications for critical findings',
    ],
    cliCheck: 'gcloud scc notifications list --organization=<org-id>',
    expectedConfig: 'Notification channels configured. High/Critical findings trigger immediate alerts.',
    commonMisconfigs: [
      'No notifications configured',
      'Only low-severity alerts enabled',
      'Wrong notification targets',
    ],
    fixHint: 'Create notification config: gcloud scc notifications create <name> --organization=<org> --pubsub-topic=<topic> --filter="severity=HIGH OR severity=CRITICAL"',
  },
  {
    id: 'INT-GCP-013',
    title: 'Ensure Access Documentation is maintained and reviewed',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'iam',
    whatToCheck: 'Verify IAM permissions are documented with business justification.',
    whyItMatters: 'Access documentation supports audit requirements and enables access reviews.',
    consoleSteps: [
      'Review IAM documentation repository',
      'Check for access request tickets',
      'Verify access justifications are recorded',
      'Confirm regular review process exists',
    ],
    expectedConfig: 'All IAM grants have documented justification. Access requests tracked in ticketing system.',
    commonMisconfigs: [
      'No access documentation',
      'Undocumented IAM changes',
      'No request/approval workflow',
    ],
    fixHint: 'Implement access request workflow. Document all IAM grants with justification. Regular reviews.',
  },

  // Common Controls
  {
    id: 'INT-COMMON-001',
    title: 'Ensure Data Retention and Purge Process is documented',
    severity: 'Medium',
    cloudProvider: 'AWS',
    framework: 'Internal Baseline',
    category: 'storage',
    whatToCheck: 'Verify data retention policies are defined and purge processes are executed.',
    whyItMatters: 'Data retention compliance requires defined policies and evidence of periodic purging.',
    consoleSteps: [
      'Review data retention policy documentation',
      'Check S3 lifecycle policies',
      'Verify purge process execution records',
      'Confirm retention periods match policy',
    ],
    cliCheck: 'aws s3api get-bucket-lifecycle-configuration --bucket <bucket-name>',
    expectedConfig: 'Data retention policy documented. S3 lifecycle rules configured. Purge evidence retained.',
    commonMisconfigs: [
      'No retention policy',
      'Lifecycle rules not configured',
      'No purge evidence',
      'Retention periods not enforced',
    ],
    fixHint: 'Document data retention policy. Configure S3 lifecycle rules. Schedule and log purge activities.',
  },
  {
    id: 'INT-COMMON-002',
    title: 'Ensure Data Retention and Purge Process is documented',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'Internal Baseline',
    category: 'storage',
    whatToCheck: 'Verify data retention policies are defined and purge processes are executed.',
    whyItMatters: 'Data retention compliance requires defined policies and evidence of periodic purging.',
    consoleSteps: [
      'Review data retention policy documentation',
      'Check Storage lifecycle management policies',
      'Verify purge process execution records',
      'Confirm retention periods match policy',
    ],
    cliCheck: 'az storage account management-policy show --account-name <storage-account> --resource-group <rg>',
    expectedConfig: 'Data retention policy documented. Lifecycle management configured. Purge evidence retained.',
    commonMisconfigs: [
      'No retention policy',
      'Lifecycle rules not configured',
      'No purge evidence',
      'Retention periods not enforced',
    ],
    fixHint: 'Document data retention policy. Configure lifecycle management. Schedule and log purge activities.',
  },
  {
    id: 'INT-COMMON-003',
    title: 'Ensure Data Retention and Purge Process is documented',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'Internal Baseline',
    category: 'storage',
    whatToCheck: 'Verify data retention policies are defined and purge processes are executed.',
    whyItMatters: 'Data retention compliance requires defined policies and evidence of periodic purging.',
    consoleSteps: [
      'Review data retention policy documentation',
      'Check GCS lifecycle rules',
      'Verify purge process execution records',
      'Confirm retention periods match policy',
    ],
    cliCheck: 'gcloud storage buckets describe gs://<bucket-name> --format="json(lifecycle)"',
    expectedConfig: 'Data retention policy documented. GCS lifecycle rules configured. Purge evidence retained.',
    commonMisconfigs: [
      'No retention policy',
      'Lifecycle rules not configured',
      'No purge evidence',
      'Retention periods not enforced',
    ],
    fixHint: 'Document data retention policy. Configure GCS lifecycle rules. Schedule and log purge activities.',
  },

  // ============================================
  // ADDITIONAL AZURE CIS CONTROLS
  // ============================================

  // App Service Additional Controls
  {
    id: 'CIS-AZ-2.1.11',
    title: 'Ensure incoming client certificates are enabled and required',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify client certificate mode is set to Required for mutual TLS.',
    whyItMatters: 'Client certificates provide strong authentication for service-to-service communication.',
    consoleSteps: [
      'Go to App Service',
      'Select Settings > Configuration',
      'Check Incoming client certificates setting',
      'Verify it is set to Required or Optional',
    ],
    cliCheck: 'az webapp show --name <app-name> --resource-group <rg> --query "clientCertEnabled"',
    expectedConfig: 'clientCertEnabled: true. clientCertMode: Required for sensitive applications.',
    commonMisconfigs: [
      'Client certs disabled',
      'Mode set to Optional when Required needed',
      'No certificate validation',
    ],
    fixHint: 'az webapp update --name <app-name> --resource-group <rg> --set clientCertEnabled=true clientCertMode=Required',
  },
  {
    id: 'CIS-AZ-2.1.15',
    title: 'Ensure App Service Plan SKU supports Private Endpoints',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify App Service Plan uses a SKU that supports private endpoints (Premium or higher).',
    whyItMatters: 'Private endpoints enable secure access without public internet exposure.',
    consoleSteps: [
      'Go to App Service Plan',
      'Check SKU/Pricing tier',
      'Verify Premium V2, Premium V3, or Isolated tier',
    ],
    cliCheck: 'az appservice plan show --name <plan-name> --resource-group <rg> --query "sku"',
    expectedConfig: 'SKU tier is PremiumV2, PremiumV3, or Isolated. Private endpoint capability available.',
    commonMisconfigs: [
      'Basic or Standard tier used',
      'Free tier used for production',
      'Private endpoints not utilized',
    ],
    fixHint: 'Upgrade to Premium V2+ tier to enable private endpoints. Configure private endpoints for secure access.',
  },
  {
    id: 'CIS-AZ-2.1.16',
    title: 'Ensure Private Endpoints are used to access App Service',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify private endpoints are configured for App Service access.',
    whyItMatters: 'Private endpoints eliminate public internet exposure for sensitive applications.',
    consoleSteps: [
      'Go to App Service > Networking',
      'Check Private Endpoints section',
      'Verify private endpoint is configured',
      'Check DNS resolution for private endpoint',
    ],
    cliCheck: 'az network private-endpoint list --query "[?privateLinkServiceConnections[?groupIds[?contains(@, \'sites\')]]]"',
    expectedConfig: 'Private endpoint configured. Public network access disabled. Private DNS zone configured.',
    commonMisconfigs: [
      'No private endpoint configured',
      'Public access still enabled',
      'DNS not configured for private endpoint',
    ],
    fixHint: 'Create private endpoint for App Service. Configure private DNS zone. Disable public network access.',
  },
  {
    id: 'CIS-AZ-2.1.18',
    title: 'Ensure App Service is integrated with Virtual Network',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify App Service has VNet integration configured.',
    whyItMatters: 'VNet integration enables secure access to backend resources without public exposure.',
    consoleSteps: [
      'Go to App Service > Networking',
      'Check VNet Integration section',
      'Verify integration is configured',
      'Check subnet assignment',
    ],
    cliCheck: 'az webapp vnet-integration list --name <app-name> --resource-group <rg>',
    expectedConfig: 'VNet integration configured. Dedicated subnet assigned. Route all traffic through VNet.',
    commonMisconfigs: [
      'No VNet integration',
      'Shared subnet with other resources',
      'Not all traffic routed through VNet',
    ],
    fixHint: 'az webapp vnet-integration add --name <app-name> --resource-group <rg> --vnet <vnet-name> --subnet <subnet-name>',
  },
  {
    id: 'CIS-AZ-2.1.19',
    title: 'Ensure App Configuration access is routed through VNet',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify application configuration access routes through VNet integration.',
    whyItMatters: 'Routing config access through VNet prevents exposure of sensitive settings.',
    consoleSteps: [
      'Go to App Service > Networking',
      'Check VNet Integration > Route All',
      'Verify configuration connections use private endpoints',
    ],
    cliCheck: 'az webapp show --name <app-name> --resource-group <rg> --query "vnetRouteAllEnabled"',
    expectedConfig: 'vnetRouteAllEnabled: true. Configuration resources accessed via private endpoints.',
    commonMisconfigs: [
      'Route all not enabled',
      'Config resources accessed publicly',
      'Split tunneling issues',
    ],
    fixHint: 'Enable Route All in VNet integration. Configure private endpoints for Key Vault and App Configuration.',
  },
  {
    id: 'CIS-AZ-2.1.20',
    title: 'Ensure all traffic is routed through Virtual Network',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify WEBSITE_VNET_ROUTE_ALL is enabled for complete traffic routing.',
    whyItMatters: 'Routing all traffic through VNet enables network security controls and monitoring.',
    consoleSteps: [
      'Go to App Service > Configuration',
      'Check Application Settings',
      'Look for WEBSITE_VNET_ROUTE_ALL setting',
      'Verify value is 1',
    ],
    cliCheck: 'az webapp config appsettings list --name <app-name> --resource-group <rg> --query "[?name==\'WEBSITE_VNET_ROUTE_ALL\']"',
    expectedConfig: 'WEBSITE_VNET_ROUTE_ALL = 1. All outbound traffic routes through VNet integration.',
    commonMisconfigs: [
      'Setting not configured',
      'Value set to 0',
      'Some traffic bypasses VNet',
    ],
    fixHint: 'az webapp config appsettings set --name <app-name> --resource-group <rg> --settings WEBSITE_VNET_ROUTE_ALL=1',
  },

  // App Service Environment Controls
  {
    id: 'CIS-AZ-2.6',
    title: 'Ensure App Service Environment uses Internal Load Balancer',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify ASE is configured with Internal Load Balancer (ILB ASE).',
    whyItMatters: 'ILB ASE keeps applications private within the VNet without public internet exposure.',
    consoleSteps: [
      'Go to App Service Environments',
      'Check Virtual IP Type',
      'Verify Internal is selected',
      'Check VNet configuration',
    ],
    cliCheck: 'az appservice ase show --name <ase-name> --query "internalLoadBalancingMode"',
    expectedConfig: 'internalLoadBalancingMode: Web, Publishing (or 3). No external VIP.',
    commonMisconfigs: [
      'External VIP configured',
      'Both internal and external enabled',
      'DNS not configured for internal access',
    ],
    fixHint: 'Deploy new ASE with ILB mode. Configure private DNS for internal resolution.',
  },
  {
    id: 'CIS-AZ-2.7',
    title: 'Ensure App Service Environment is version 3 or higher',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify ASE is running version 3 (ASEv3) for security improvements.',
    whyItMatters: 'ASEv3 provides enhanced security features, zone redundancy, and better isolation.',
    consoleSteps: [
      'Go to App Service Environments',
      'Check the ASE version/kind',
      'Verify ASEv3 is deployed',
    ],
    cliCheck: 'az appservice ase list --query "[].{Name:name, Kind:kind}"',
    expectedConfig: 'ASE kind should be ASEV3. Legacy ASEv1/v2 should be migrated.',
    commonMisconfigs: [
      'Running ASEv1 or ASEv2',
      'Migration not planned',
      'Missing v3 security features',
    ],
    fixHint: 'Plan migration to ASEv3. New deployments should use ASEv3 only. ASEv1/v2 retirement planned.',
  },
  {
    id: 'CIS-AZ-2.8',
    title: 'Ensure App Service Environment has internal encryption enabled',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify internal encryption is enabled for ASE.',
    whyItMatters: 'Internal encryption protects data in transit within the ASE infrastructure.',
    consoleSteps: [
      'Go to App Service Environment',
      'Check Configuration settings',
      'Verify internal encryption is enabled',
    ],
    cliCheck: 'az appservice ase show --name <ase-name> --query "clusterSettings"',
    expectedConfig: 'InternalEncryption setting should be true in cluster settings.',
    commonMisconfigs: [
      'Internal encryption disabled',
      'Setting not configured',
    ],
    fixHint: 'Enable internal encryption in ASE cluster settings. May require ASE restart.',
  },
  {
    id: 'CIS-AZ-2.9',
    title: 'Ensure App Service Environment has TLS 1.0 and 1.1 disabled',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify TLS 1.0 and 1.1 are disabled in ASE settings.',
    whyItMatters: 'TLS 1.0 and 1.1 have known vulnerabilities and should not be used.',
    consoleSteps: [
      'Go to App Service Environment',
      'Check TLS/SSL settings',
      'Verify minimum TLS version is 1.2',
    ],
    cliCheck: 'az appservice ase show --name <ase-name> --query "clusterSettings"',
    expectedConfig: 'DisableTls1.0 and DisableTls1.1 should be true. Minimum TLS 1.2.',
    commonMisconfigs: [
      'TLS 1.0 still enabled',
      'TLS 1.1 still enabled',
      'Legacy client compatibility override',
    ],
    fixHint: 'Configure ASE to disable TLS 1.0/1.1. Test client compatibility before deployment.',
  },
  {
    id: 'CIS-AZ-2.10',
    title: 'Ensure App Service Environment cipher suite order is configured',
    severity: 'Medium',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify cipher suite ordering prioritizes strong ciphers.',
    whyItMatters: 'Proper cipher ordering ensures the strongest available encryption is used.',
    consoleSteps: [
      'Go to App Service Environment',
      'Check TLS/SSL cipher configuration',
      'Verify strong ciphers are prioritized',
    ],
    cliCheck: 'az appservice ase show --name <ase-name> --query "clusterSettings"',
    expectedConfig: 'FrontEndSSLCipherSuiteOrder configured with strong ciphers first (AES-GCM preferred).',
    commonMisconfigs: [
      'Default cipher order used',
      'Weak ciphers prioritized',
      'No cipher suite customization',
    ],
    fixHint: 'Configure FrontEndSSLCipherSuiteOrder with strong ciphers. Prioritize AES-256-GCM suites.',
  },

  // Container Instances Controls
  {
    id: 'CIS-AZ-3.1',
    title: 'Ensure Container Instances use Private Virtual Networks',
    severity: 'High',
    cloudProvider: 'Azure',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify Container Instances are deployed in private VNets.',
    whyItMatters: 'VNet deployment prevents public exposure of container workloads.',
    consoleSteps: [
      'Go to Container Instances',
      'Check Networking configuration',
      'Verify VNet/Subnet is configured',
      'Check for public IP assignment',
    ],
    cliCheck: 'az container show --name <container-name> --resource-group <rg> --query "ipAddress"',
    expectedConfig: 'Container deployed in VNet subnet. No public IP assigned. type: Private.',
    commonMisconfigs: [
      'Public IP assigned',
      'Not deployed in VNet',
      'Exposed on public network',
    ],
    fixHint: 'Deploy container with --vnet and --subnet parameters. Avoid public IP assignment for internal workloads.',
  },

  // ============================================
  // ADDITIONAL GCP CIS CONTROLS
  // ============================================

  // Logging/Monitoring Additional
  {
    id: 'CIS-GCP-2.14',
    title: 'Ensure Access Transparency is enabled',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify Access Transparency logs are enabled to track Google admin access.',
    whyItMatters: 'Access Transparency logs when Google personnel access your data for support.',
    consoleSteps: [
      'Go to IAM & Admin > Access Transparency',
      'Check if Access Transparency is enabled',
      'Verify logs are being collected',
    ],
    cliCheck: 'gcloud access-transparency get-policy --organization=<org-id>',
    expectedConfig: 'Access Transparency enabled at organization level. Logs reviewed regularly.',
    commonMisconfigs: [
      'Not enabled',
      'Not available on current plan',
      'Logs not reviewed',
    ],
    fixHint: 'Enable Access Transparency (requires Premium or Enterprise support). Review logs in Cloud Logging.',
  },
  {
    id: 'CIS-GCP-2.15',
    title: 'Ensure Access Approval is enabled',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify Access Approval is enabled for admin access requests.',
    whyItMatters: 'Access Approval requires explicit approval before Google can access customer data.',
    consoleSteps: [
      'Go to Security > Access Approval',
      'Check if Access Approval is enabled',
      'Verify approvers are configured',
    ],
    cliCheck: 'gcloud access-approval settings get --organization=<org-id>',
    expectedConfig: 'Access Approval enabled. Approvers configured. Notification emails set.',
    commonMisconfigs: [
      'Not enabled',
      'No approvers configured',
      'Notifications not set up',
    ],
    fixHint: 'Enable Access Approval. Configure approvers and notification channels.',
  },
  {
    id: 'CIS-GCP-2.16',
    title: 'Ensure HTTP(S) Load Balancer logging is enabled',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify logging is enabled for HTTP(S) Load Balancers.',
    whyItMatters: 'Load balancer logs provide visibility into traffic patterns and potential attacks.',
    consoleSteps: [
      'Go to Load Balancing',
      'Select load balancer',
      'Check backend service logging settings',
      'Verify sample rate is appropriate',
    ],
    cliCheck: 'gcloud compute backend-services describe <service-name> --global --format="json(logConfig)"',
    expectedConfig: 'logConfig.enable: true. Sample rate 1.0 for security-sensitive applications.',
    commonMisconfigs: [
      'Logging disabled',
      'Sample rate too low',
      'Logs not exported to SIEM',
    ],
    fixHint: 'gcloud compute backend-services update <service> --global --enable-logging --logging-sample-rate=1.0',
  },

  // Networking Additional
  {
    id: 'CIS-GCP-3.4',
    title: 'Ensure RSASHA1 is not used for Key-Signing Key in Cloud DNS DNSSEC',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify DNSSEC key-signing key does not use weak RSASHA1 algorithm.',
    whyItMatters: 'RSASHA1 is cryptographically weak and may be vulnerable to attacks.',
    consoleSteps: [
      'Go to Cloud DNS',
      'Select managed zone',
      'Check DNSSEC settings',
      'Verify KSK algorithm is not RSASHA1',
    ],
    cliCheck: 'gcloud dns managed-zones describe <zone-name> --format="json(dnssecConfig)"',
    expectedConfig: 'Key-signing key should use RSASHA256 or stronger algorithm.',
    commonMisconfigs: [
      'Using RSASHA1 algorithm',
      'Legacy configuration not updated',
    ],
    fixHint: 'Recreate DNSSEC configuration with RSASHA256 or ECDSAP256SHA256 algorithm.',
  },
  {
    id: 'CIS-GCP-3.5',
    title: 'Ensure RSASHA1 is not used for Zone-Signing Key in Cloud DNS DNSSEC',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'network',
    whatToCheck: 'Verify DNSSEC zone-signing key does not use weak RSASHA1 algorithm.',
    whyItMatters: 'RSASHA1 is cryptographically weak and should be replaced with stronger algorithms.',
    consoleSteps: [
      'Go to Cloud DNS',
      'Select managed zone',
      'Check DNSSEC settings',
      'Verify ZSK algorithm is not RSASHA1',
    ],
    cliCheck: 'gcloud dns managed-zones describe <zone-name> --format="json(dnssecConfig)"',
    expectedConfig: 'Zone-signing key should use RSASHA256 or stronger algorithm.',
    commonMisconfigs: [
      'Using RSASHA1 algorithm',
      'Legacy configuration not updated',
    ],
    fixHint: 'Recreate DNSSEC configuration with RSASHA256 or ECDSAP256SHA256 algorithm.',
  },
  {
    id: 'CIS-GCP-3.10',
    title: 'Ensure Identity Aware Proxy (IAP) is used for context-aware access',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'iam',
    whatToCheck: 'Verify IAP is enabled for web applications requiring authenticated access.',
    whyItMatters: 'IAP provides context-aware access control without VPN for web applications.',
    consoleSteps: [
      'Go to Security > Identity-Aware Proxy',
      'Check IAP status for web resources',
      'Verify access policies are configured',
    ],
    cliCheck: 'gcloud iap web get-iam-policy --resource-type=backend-services --service=<service-name>',
    expectedConfig: 'IAP enabled for internal applications. Access policies based on identity and context.',
    commonMisconfigs: [
      'IAP not enabled',
      'Overly permissive access policies',
      'No context-aware conditions',
    ],
    fixHint: 'Enable IAP for backend services. Configure access policies with context-aware conditions.',
  },

  // VMs Additional
  {
    id: 'CIS-GCP-4.9',
    title: 'Ensure Compute instances do not have public IP addresses',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify Compute instances do not have external IP addresses assigned.',
    whyItMatters: 'Public IPs expose instances directly to the internet, increasing attack surface.',
    consoleSteps: [
      'Go to Compute Engine > VM instances',
      'Check External IP column',
      'Verify production instances have no external IP',
    ],
    cliCheck: 'gcloud compute instances list --format="table(name,networkInterfaces[].accessConfigs[].natIP)"',
    expectedConfig: 'No external IP for production instances. Use Cloud NAT for outbound access.',
    commonMisconfigs: [
      'External IP assigned',
      'Ephemeral external IP enabled',
      'No Cloud NAT configured',
    ],
    fixHint: 'Remove external IP. Configure Cloud NAT for outbound access. Use IAP for SSH/RDP.',
  },
  {
    id: 'CIS-GCP-4.10',
    title: 'Ensure App Engine applications enforce HTTPS connections',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify App Engine is configured to require HTTPS for all connections.',
    whyItMatters: 'HTTPS ensures data in transit is encrypted and prevents man-in-the-middle attacks.',
    consoleSteps: [
      'Review app.yaml configuration',
      'Check handlers section for secure: always',
      'Verify HTTP redirects to HTTPS',
    ],
    cliCheck: 'gcloud app describe --format="json"',
    expectedConfig: 'All handlers configured with secure: always. HTTP redirected to HTTPS.',
    commonMisconfigs: [
      'secure: optional or never',
      'HTTP allowed without redirect',
      'Mixed content issues',
    ],
    fixHint: 'Set secure: always in app.yaml handlers. Configure redirect_http_response_code: 301.',
  },
  {
    id: 'CIS-GCP-4.11',
    title: 'Ensure Confidential Computing is enabled for sensitive workloads',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify Confidential VMs are used for processing sensitive data.',
    whyItMatters: 'Confidential Computing encrypts data in use, protecting from privileged access attacks.',
    consoleSteps: [
      'Go to Compute Engine > VM instances',
      'Check instance details for Confidential VM',
      'Verify applicable workloads use Confidential VMs',
    ],
    cliCheck: 'gcloud compute instances describe <instance> --format="json(confidentialInstanceConfig)"',
    expectedConfig: 'Confidential VM enabled for sensitive workloads. enableConfidentialCompute: true.',
    commonMisconfigs: [
      'Not using Confidential VMs for sensitive data',
      'Machine type not compatible',
    ],
    fixHint: 'Create new instance with --confidential-compute flag. Use N2D machine types.',
  },
  {
    id: 'CIS-GCP-4.12',
    title: 'Ensure VM instances have latest OS updates installed',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'compute',
    whatToCheck: 'Verify OS Patch Management is configured and patches are current.',
    whyItMatters: 'Unpatched systems are vulnerable to known exploits and security issues.',
    consoleSteps: [
      'Go to Compute Engine > OS patch management',
      'Check patch deployment status',
      'Verify patch compliance percentage',
    ],
    cliCheck: 'gcloud compute os-config patch-jobs list',
    expectedConfig: 'Patch management enabled. Regular patch schedules configured. High compliance rate.',
    commonMisconfigs: [
      'No patch management configured',
      'Stale patch deployments',
      'Low compliance rates',
    ],
    fixHint: 'Enable OS Config agent. Configure patch policies. Schedule regular maintenance windows.',
  },

  // Cloud SQL PostgreSQL Additional
  {
    id: 'CIS-GCP-6.2.4',
    title: 'Ensure log_statement flag is set appropriately for PostgreSQL',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_statement is configured to log appropriate SQL statements.',
    whyItMatters: 'Statement logging provides audit trail for database operations and security analysis.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit > Flags',
      'Check log_statement setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_statement set to ddl or all based on security requirements.',
    commonMisconfigs: [
      'Set to none',
      'Not configured',
      'Too verbose causing performance issues',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_statement=ddl',
  },
  {
    id: 'CIS-GCP-6.2.5',
    title: 'Ensure log_min_messages flag is set to WARNING or stricter for PostgreSQL',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_min_messages is configured to capture important messages.',
    whyItMatters: 'Proper message logging helps identify issues and security events.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit > Flags',
      'Check log_min_messages setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_min_messages set to WARNING or stricter (ERROR, LOG).',
    commonMisconfigs: [
      'Set to DEBUG levels',
      'Not configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_min_messages=WARNING',
  },
  {
    id: 'CIS-GCP-6.2.6',
    title: 'Ensure log_min_error_statement flag is set to ERROR or stricter for PostgreSQL',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_min_error_statement captures error-causing statements.',
    whyItMatters: 'Logging error statements helps troubleshoot and identify potential SQL injection attempts.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit > Flags',
      'Check log_min_error_statement setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_min_error_statement set to ERROR or FATAL.',
    commonMisconfigs: [
      'Set to PANIC only',
      'Not configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_min_error_statement=ERROR',
  },
  {
    id: 'CIS-GCP-6.2.7',
    title: 'Ensure log_min_duration_statement flag is set to -1 (disabled) for PostgreSQL',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify log_min_duration_statement is disabled to prevent sensitive data logging.',
    whyItMatters: 'Duration logging may expose sensitive data in SQL statements in logs.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit > Flags',
      'Check log_min_duration_statement setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'log_min_duration_statement set to -1 (disabled) to prevent sensitive data exposure.',
    commonMisconfigs: [
      'Enabled with low threshold',
      'Logging sensitive SQL statements',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags log_min_duration_statement=-1',
  },
  {
    id: 'CIS-GCP-6.2.8',
    title: 'Ensure cloudsql.enable_pgaudit flag is set to ON for PostgreSQL',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'logging',
    whatToCheck: 'Verify pgAudit extension is enabled for detailed audit logging.',
    whyItMatters: 'pgAudit provides detailed session and object audit logging for compliance.',
    consoleSteps: [
      'Go to SQL > select PostgreSQL instance',
      'Click Edit > Flags',
      'Check cloudsql.enable_pgaudit setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'cloudsql.enable_pgaudit set to ON. pgaudit.log configured appropriately.',
    commonMisconfigs: [
      'pgAudit not enabled',
      'Audit log classes not configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags cloudsql.enable_pgaudit=ON,pgaudit.log=all',
  },

  // Cloud SQL SQL Server Additional
  {
    id: 'CIS-GCP-6.3.2',
    title: 'Ensure cross db ownership chaining flag is OFF for SQL Server',
    severity: 'High',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify cross db ownership chaining is disabled for SQL Server.',
    whyItMatters: 'Cross-database ownership chaining can allow unintended access across databases.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit > Flags',
      'Check cross db ownership chaining setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'cross db ownership chaining set to OFF.',
    commonMisconfigs: [
      'Setting enabled',
      'Not explicitly configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags "cross db ownership chaining=OFF"',
  },
  {
    id: 'CIS-GCP-6.3.3',
    title: 'Ensure user connections flag is set to a non-limiting value for SQL Server',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify user connections is set to 0 (unlimited) or appropriate limit.',
    whyItMatters: 'Proper connection limits prevent denial of service while allowing legitimate access.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit > Flags',
      'Check user connections setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'user connections set to 0 or appropriate limit based on workload.',
    commonMisconfigs: [
      'Too restrictive limit',
      'Not configured',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags "user connections=0"',
  },
  {
    id: 'CIS-GCP-6.3.4',
    title: 'Ensure user options flag is not configured for SQL Server',
    severity: 'Low',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify user options flag is not set to prevent changing default query behavior.',
    whyItMatters: 'User options can override important query processing settings unexpectedly.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit > Flags',
      'Verify user options is not configured',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'user options flag should not be present in database flags.',
    commonMisconfigs: [
      'user options configured',
      'Unexpected query behavior changes',
    ],
    fixHint: 'Remove user options flag if configured. Use default query processing behavior.',
  },
  {
    id: 'CIS-GCP-6.3.6',
    title: 'Ensure 3625 trace flag is set to ON for SQL Server',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify trace flag 3625 is enabled to limit error information disclosure.',
    whyItMatters: 'Trace flag 3625 masks system error details that could aid attackers.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit > Flags',
      'Check 3625 (trace flag) setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: '3625 (trace flag) set to ON.',
    commonMisconfigs: [
      'Trace flag not enabled',
      'Detailed errors exposed',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags "3625 (trace flag)=ON"',
  },
  {
    id: 'CIS-GCP-6.3.7',
    title: 'Ensure contained database authentication flag is OFF for SQL Server',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify contained database authentication is disabled.',
    whyItMatters: 'Contained database authentication can bypass instance-level security controls.',
    consoleSteps: [
      'Go to SQL > select SQL Server instance',
      'Click Edit > Flags',
      'Check contained database authentication setting',
    ],
    cliCheck: 'gcloud sql instances describe <instance> --format="get(settings.databaseFlags)"',
    expectedConfig: 'contained database authentication set to OFF.',
    commonMisconfigs: [
      'Setting enabled',
      'Contained databases in use',
    ],
    fixHint: 'gcloud sql instances patch <instance> --database-flags "contained database authentication=OFF"',
  },

  // BigQuery Additional
  {
    id: 'CIS-GCP-7.4',
    title: 'Ensure BigQuery data is classified and labeled appropriately',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'storage',
    whatToCheck: 'Verify BigQuery datasets and tables have data classification labels.',
    whyItMatters: 'Data classification enables appropriate access controls and compliance requirements.',
    consoleSteps: [
      'Go to BigQuery',
      'Check dataset and table labels',
      'Verify classification labels are applied',
      'Check DLP scan results for sensitive data',
    ],
    cliCheck: 'bq show --format=prettyjson <project:dataset> | jq ".labels"',
    expectedConfig: 'Datasets labeled with data classification. DLP scans for sensitive data discovery.',
    commonMisconfigs: [
      'No classification labels',
      'Inconsistent labeling',
      'No DLP scanning configured',
    ],
    fixHint: 'Apply classification labels to datasets. Configure DLP to scan for sensitive data.',
  },

  // Dataproc
  {
    id: 'CIS-GCP-8.1',
    title: 'Ensure Dataproc cluster is encrypted with Customer-Managed Keys',
    severity: 'Medium',
    cloudProvider: 'GCP',
    framework: 'CIS Benchmark',
    category: 'encryption',
    whatToCheck: 'Verify Dataproc clusters use CMEK for encryption.',
    whyItMatters: 'CMEK provides additional control over encryption keys for sensitive data processing.',
    consoleSteps: [
      'Go to Dataproc > Clusters',
      'Select cluster',
      'Check encryption configuration',
      'Verify CMEK is configured',
    ],
    cliCheck: 'gcloud dataproc clusters describe <cluster-name> --region=<region> --format="json(config.encryptionConfig)"',
    expectedConfig: 'gcePdKmsKeyName configured with Cloud KMS key for disk encryption.',
    commonMisconfigs: [
      'Using Google-managed encryption',
      'CMEK not configured',
      'Key not in same region',
    ],
    fixHint: 'Create cluster with --gce-pd-kms-key flag. Configure KMS key with appropriate permissions.',
  },
];

export const awarenessArticles: AwarenessArticle[] = [
  {
    id: 'weekly-001',
    title: 'The Rise of Cloud-Native Ransomware',
    category: 'Weekly Awareness',
    summary: 'Understanding how attackers are adapting ransomware tactics specifically for cloud environments.',
    imageUrl: '/src/assets/awareness/ransomware-cloud.jpg',
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
    imageUrl: '/src/assets/awareness/s3-misconfig.jpg',
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
    imageUrl: '/src/assets/awareness/zero-trust.jpg',
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
    imageUrl: '/src/assets/awareness/cli-audit.jpg',
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
  {
    id: 'weekly-002',
    title: 'Understanding CIS Benchmark Levels',
    category: 'Weekly Awareness',
    summary: 'A guide to Level 1 and Level 2 CIS Benchmark profiles and when to apply each.',
    imageUrl: '/src/assets/awareness/cis-benchmark.jpg',
    content: `CIS Benchmarks define two profile levels that help organizations prioritize security controls:

**Level 1 Profile:**
- Practical and prudent security recommendations
- Designed for most organizations
- Minimal impact on system functionality
- Focus on fundamental security hardening

**Level 2 Profile:**
- Extends Level 1 recommendations
- For environments where security is paramount
- May impact usability or performance
- Often requires additional resources or licensing

**When to Use Each:**
- Start with Level 1 for baseline security
- Apply Level 2 for high-security environments
- Document exceptions with business justification
- Review profile applicability annually`,
    date: '2024-01-20',
  },
  {
    id: 'misconfig-002',
    title: 'Identity Misconfigurations Across Cloud Providers',
    category: 'Misconfigurations',
    summary: 'Common IAM mistakes found in AWS, Azure, and GCP environments.',
    imageUrl: '/src/assets/awareness/iam-misconfig.jpg',
    content: `Identity and Access Management is consistently the most misconfigured area across all cloud providers:

**AWS Common Issues:**
- Root account access keys still active
- MFA not enabled for console users
- Overly permissive IAM policies with *:*
- Unused credentials not disabled

**Azure Common Issues:**
- Guest users with excessive permissions
- Service principals with Owner role
- No Conditional Access policies
- Legacy authentication protocols enabled

**GCP Common Issues:**
- Personal Gmail accounts in IAM
- Service accounts with Editor/Owner roles
- User-managed service account keys
- Default service accounts used by instances

**Universal Fixes:**
1. Implement least privilege everywhere
2. Enable MFA for all human users
3. Regular access reviews
4. Automate credential rotation`,
    date: '2024-01-18',
  },
  {
    id: 'weekly-003',
    title: 'ISO 27001:2022 Cloud Security Updates',
    category: 'Weekly Awareness',
    summary: 'Key changes in ISO 27001:2022 that impact cloud security audits.',
    imageUrl: '/src/assets/awareness/iso-27001.jpg',
    content: `ISO 27001:2022 introduces significant updates relevant to cloud security:

**New Controls Added:**
- A.5.23: Information security for cloud services
- A.5.30: ICT readiness for business continuity
- A.8.11: Data masking
- A.8.12: Data leakage prevention
- A.8.16: Monitoring activities
- A.8.23: Web filtering

**Cloud-Specific Implications:**
- Explicit requirement for cloud security policies
- Enhanced focus on supply chain security
- Stronger emphasis on threat intelligence
- New requirements for secure development

**Audit Considerations:**
1. Review cloud service agreements for security clauses
2. Verify shared responsibility model is documented
3. Check data residency and sovereignty requirements
4. Assess cloud provider security certifications`,
    date: '2024-02-01',
  },
  {
    id: 'bestpractice-002',
    title: 'Microsoft Defender for Cloud Best Practices',
    category: 'Best Practices',
    summary: 'Maximizing security visibility across Azure, AWS, and GCP with Defender for Cloud.',
    imageUrl: '/src/assets/awareness/defender-cloud.jpg',
    content: `Microsoft Defender for Cloud provides unified security management across multi-cloud environments:

**Essential Configuration:**
- Enable Foundational CSPM (free tier minimum)
- Activate Cloud Workload Protection for production
- Connect all cloud accounts (Azure, AWS, GCP)
- Configure email notifications for high-risk alerts

**Security Score Management:**
- Target 75% or higher baseline score
- Address Critical/High recommendations first
- Document exceptions with business justification
- Review score trends weekly

**Multi-Cloud Visibility:**
- AWS: Connect via CloudFormation stack
- GCP: Connect via service account
- Unified view of recommendations across clouds
- Consistent severity ratings

**Alert Response:**
- Configure alert suppression rules carefully
- Integrate with SIEM (Microsoft Sentinel)
- Establish response SLAs by severity
- Document remediation actions`,
    date: '2024-02-05',
  },
  {
    id: 'tips-002',
    title: 'Access Review Checklist for Cloud Auditors',
    category: 'Audit Tips',
    summary: 'Step-by-step guide for conducting effective IAM access reviews.',
    imageUrl: '/src/assets/awareness/access-review.jpg',
    content: `Conducting thorough access reviews is critical for compliance and security:

**Pre-Review Preparation:**
1. Obtain current team roster from HR
2. Request previous access review documentation
3. Export IAM user/role lists from all cloud accounts
4. Identify privileged accounts and service accounts

**Review Checklist:**
- [ ] Compare IAM users against current employee list
- [ ] Verify MFA is enabled for all console users
- [ ] Check for dormant accounts (45+ days inactive)
- [ ] Review privileged access justifications
- [ ] Validate service account necessity
- [ ] Check access key age and rotation

**Evidence Collection:**
- Screenshot of IAM user list with MFA status
- Credential report exports
- Privileged access approval emails
- Previous review documentation
- Remediation ticket references

**Common Findings:**
- Former employees with active access
- Excessive privileged account usage
- Missing MFA on admin accounts
- Undocumented service accounts`,
    date: '2024-02-10',
  },
  {
    id: 'misconfig-003',
    title: 'Network Security Group Pitfalls',
    category: 'Misconfigurations',
    summary: 'Critical NSG and security group misconfigurations that expose cloud resources.',
    imageUrl: '/src/assets/awareness/nsg-security.jpg',
    content: `Network security groups are a primary defense layer but are frequently misconfigured:

**Critical Misconfigurations:**

**1. Open to World (0.0.0.0/0)**
- SSH (22), RDP (3389) exposed
- Database ports (3306, 5432, 1433) public
- Any port with "Any" source

**2. Overly Permissive Rules**
- Source: Any, Destination: Any, Port: Any
- "Allow all" rules for troubleshooting left in place
- Default VPC/NSG rules not reviewed

**3. Missing Egress Controls**
- No restrictions on outbound traffic
- Data exfiltration paths open
- C2 communication possible

**Azure-Specific Issues:**
- NSG not associated with subnet or NIC
- Application Security Groups not used
- Azure Firewall bypassed

**AWS-Specific Issues:**
- Default security groups modified
- Self-referencing rules misconfigured
- Security groups not tied to specific functions

**GCP-Specific Issues:**
- Default network firewall rules active
- Priority ordering errors
- Target tags not properly applied`,
    date: '2024-02-15',
  },
  {
    id: 'weekly-004',
    title: 'Key Vault and Secrets Management Essentials',
    category: 'Weekly Awareness',
    summary: 'Best practices for managing secrets across AWS, Azure, and GCP.',
    imageUrl: '/src/assets/awareness/secrets-mgmt.jpg',
    content: `Proper secrets management is fundamental to cloud security:

**Never Store Secrets In:**
- Application source code
- Environment variables (visible in console)
- Configuration files in repositories
- CI/CD pipeline definitions
- Container images

**Use Native Secret Stores:**
- AWS: Secrets Manager, Parameter Store (SecureString)
- Azure: Key Vault
- GCP: Secret Manager

**Key Rotation Best Practices:**
- Database credentials: 90 days maximum
- API keys: 90 days or on-demand
- Encryption keys: Annual rotation minimum
- SSH keys: Annual rotation with audit

**Access Control:**
- Restrict secret access to specific services/roles
- Use VPN/private endpoint access only
- Enable audit logging for all secret access
- Implement break-glass procedures

**Monitoring:**
- Alert on unauthorized access attempts
- Track secret version changes
- Monitor for secrets in logs
- Scan code repositories for exposed secrets`,
    date: '2024-02-20',
  },
  {
    id: 'bestpractice-003',
    title: 'Backup and Disaster Recovery in Cloud',
    category: 'Best Practices',
    summary: 'Essential backup strategies and DR planning for cloud environments.',
    imageUrl: '/src/assets/awareness/backup-dr.jpg',
    content: `Robust backup and DR is crucial for business continuity:

**Backup Classification (Example Classes):**
- Class A: Critical systems, 4-hour RPO, daily backups
- Class B: Important systems, 24-hour RPO, daily backups
- Class C: Standard systems, 72-hour RPO, weekly backups
- Class D: Development, best effort
- Class E: No backup required

**Cloud-Native Backup Services:**
- AWS: AWS Backup, S3 versioning, EBS snapshots
- Azure: Azure Backup, Site Recovery, blob versioning
- GCP: Cloud Storage versioning, persistent disk snapshots

**DR Testing Requirements:**
- Annual DR test minimum for critical systems
- Document test results and lessons learned
- Validate RTO/RPO can be achieved
- Test restoration procedures, not just backups

**Common Failures:**
- Backups exist but never tested
- Backup retention too short
- No cross-region replication
- Backup credentials exposed
- No notification on backup failures`,
    date: '2024-02-25',
  },
  {
    id: 'tips-003',
    title: 'Evidence Collection for Cloud Audits',
    category: 'Audit Tips',
    summary: 'How to gather and organize audit evidence efficiently.',
    imageUrl: '/src/assets/awareness/evidence-collection.jpg',
    content: `Effective evidence collection streamlines audits and supports findings:

**Types of Evidence:**
1. **Screenshots**: Console configurations, settings pages
2. **Exports**: CSV/JSON reports, credential reports
3. **CLI Output**: Command results with timestamps
4. **Logs**: Audit logs, access logs, change history
5. **Documentation**: Policies, procedures, approvals

**Naming Convention:**
\`[Date]_[CloudProvider]_[Category]_[Description].[ext]\`
Example: \`2024-02-15_AWS_IAM_MFA-Status-Report.csv\`

**Evidence Standards:**
- Include timestamps on all evidence
- Capture full context (URL, account ID visible)
- Use consistent naming conventions
- Organize by control or finding
- Maintain chain of custody

**Automation Tips:**
- Use cloud CLIs with --output json for parseable results
- Schedule automatic exports for recurring evidence
- Use cloud-native compliance tools for reports
- Leverage Security Hub/Defender for consolidated findings

**Storage:**
- Secure, access-controlled location
- Retention per audit requirements
- Encrypted at rest
- Version controlled if possible`,
    date: '2024-03-01',
  },
  {
    id: 'weekly-005',
    title: 'Understanding Shared Responsibility Model',
    category: 'Weekly Awareness',
    summary: 'Clarifying security responsibilities between cloud providers and customers.',
    imageUrl: '/src/assets/awareness/shared-responsibility.jpg',
    content: `The shared responsibility model defines who secures what in cloud environments:

**Provider Responsibilities (OF the Cloud):**
- Physical data center security
- Hardware and infrastructure
- Hypervisor and virtualization layer
- Network infrastructure
- Managed service internals

**Customer Responsibilities (IN the Cloud):**
- Identity and access management
- Data encryption and protection
- Network security (security groups, NACLs)
- Operating system patching (IaaS)
- Application security
- Compliance validation

**Model Variations by Service Type:**
- **IaaS**: Most customer responsibility
- **PaaS**: Shared more with provider
- **SaaS**: Least customer responsibility

**Audit Implications:**
- Understand what controls you can audit
- Request SOC 2 reports for provider controls
- Focus on customer-side configurations
- Document responsibility boundaries clearly

**Common Misunderstandings:**
- "The cloud is secure" ≠ "My data is secure"
- Encryption options exist but must be enabled
- Compliance is customer responsibility
- Default configurations are rarely secure`,
    date: '2024-03-05',
  },
  {
    id: 'misconfig-004',
    title: 'Logging and Monitoring Gaps',
    category: 'Misconfigurations',
    summary: 'Common logging failures that leave organizations blind to security events.',
    imageUrl: '/src/assets/awareness/logging-monitoring.jpg',
    content: `Insufficient logging creates dangerous blind spots:

**AWS Logging Gaps:**
- CloudTrail not enabled in all regions
- S3 data events not logged
- VPC Flow Logs disabled
- CloudWatch Logs retention too short
- No centralized log aggregation

**Azure Logging Gaps:**
- Diagnostic settings not configured
- Azure AD logs not exported
- NSG Flow Logs disabled
- Activity logs not retained
- No Microsoft Sentinel integration

**GCP Logging Gaps:**
- Data Access logs disabled
- VPC Flow Logs not enabled
- Log sinks not configured
- Insufficient retention period
- No Security Command Center

**Critical Events to Log:**
- Authentication successes and failures
- Privilege escalation attempts
- Resource creation and deletion
- Configuration changes
- Data access (especially sensitive data)

**Detection Requirements:**
- Real-time alerting for critical events
- Regular log review processes
- Correlation across log sources
- Retention for forensic investigation`,
    date: '2024-03-10',
  },
  {
    id: 'bestpractice-004',
    title: 'Kubernetes Security in Cloud Environments',
    category: 'Best Practices',
    summary: 'Securing managed Kubernetes services across AWS, Azure, and GCP.',
    imageUrl: '/src/assets/awareness/kubernetes-security.jpg',
    content: `Kubernetes security requires attention to multiple layers:

**Control Plane Security:**
- Enable authorized IP ranges for API access
- Use private clusters where possible
- Rotate certificates regularly
- Enable audit logging

**Authentication & Authorization:**
- Integrate with cloud IAM (IRSA, Workload Identity, Pod Identity)
- Implement RBAC with least privilege
- Avoid cluster-admin for regular operations
- Use namespaces for isolation

**Network Security:**
- Implement Network Policies
- Use service mesh for mTLS
- Restrict pod-to-pod communication
- Enable egress controls

**Workload Security:**
- Scan container images for vulnerabilities
- Use read-only root filesystems
- Run as non-root users
- Implement Pod Security Standards

**Monitoring:**
- Enable Defender for Containers / GuardDuty EKS
- Collect container logs centrally
- Monitor for anomalous behavior
- Alert on privilege escalation attempts`,
    date: '2024-03-15',
  },
];
