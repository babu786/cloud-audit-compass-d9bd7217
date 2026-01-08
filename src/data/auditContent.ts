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
  {
    id: 'weekly-002',
    title: 'Understanding CIS Benchmark Levels',
    category: 'Weekly Awareness',
    summary: 'A guide to Level 1 and Level 2 CIS Benchmark profiles and when to apply each.',
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
];
