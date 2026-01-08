export interface CLICommand {
  id: string;
  title: string;
  description: string;
  command: string;
  provider: 'AWS' | 'Azure' | 'GCP';
  category: 'iam' | 'network' | 'logging' | 'storage' | 'compute' | 'encryption';
  tags: string[];
  output?: string;
  notes?: string;
}

export const cliCommands: CLICommand[] = [
  // AWS - IAM
  {
    id: 'aws-iam-1',
    title: 'List all IAM users',
    description: 'Get a list of all IAM users in the account',
    command: 'aws iam list-users --query "Users[*].[UserName,CreateDate,PasswordLastUsed]" --output table',
    provider: 'AWS',
    category: 'iam',
    tags: ['users', 'list', 'inventory']
  },
  {
    id: 'aws-iam-2',
    title: 'Check MFA status for all users',
    description: 'List users and their MFA device status',
    command: 'aws iam list-users --query "Users[*].UserName" --output text | xargs -I {} sh -c \'mfa=$(aws iam list-mfa-devices --user-name "{}" --query "MFADevices[0].SerialNumber" --output text); echo "{}: ${mfa:-NO MFA}"\'',
    provider: 'AWS',
    category: 'iam',
    tags: ['mfa', 'authentication', 'security'],
    notes: 'Users without MFA should be flagged for remediation'
  },
  {
    id: 'aws-iam-3',
    title: 'Generate credential report',
    description: 'Generate and download IAM credential report for analysis',
    command: 'aws iam generate-credential-report && sleep 5 && aws iam get-credential-report --query "Content" --output text | base64 -d',
    provider: 'AWS',
    category: 'iam',
    tags: ['credentials', 'report', 'audit'],
    notes: 'Review for users without MFA, old access keys, inactive users'
  },
  {
    id: 'aws-iam-4',
    title: 'List policies attached to a user',
    description: 'Show all managed and inline policies for a specific user',
    command: 'aws iam list-attached-user-policies --user-name USERNAME && aws iam list-user-policies --user-name USERNAME',
    provider: 'AWS',
    category: 'iam',
    tags: ['policies', 'permissions', 'user'],
    notes: 'Replace USERNAME with the actual username'
  },
  {
    id: 'aws-iam-5',
    title: 'Check root account access keys',
    description: 'Verify root account does not have access keys',
    command: 'aws iam get-account-summary --query "SummaryMap.AccountAccessKeysPresent"',
    provider: 'AWS',
    category: 'iam',
    tags: ['root', 'access-keys', 'security'],
    notes: 'Value should be 0 - root should not have access keys'
  },
  {
    id: 'aws-iam-6',
    title: 'List all IAM roles',
    description: 'Get inventory of all IAM roles in the account',
    command: 'aws iam list-roles --query "Roles[*].[RoleName,CreateDate,Arn]" --output table',
    provider: 'AWS',
    category: 'iam',
    tags: ['roles', 'inventory', 'iam']
  },
  {
    id: 'aws-iam-7',
    title: 'Find unused IAM credentials',
    description: 'List access keys not used in the last 90 days',
    command: 'aws iam list-users --query "Users[*].UserName" --output text | xargs -I {} aws iam list-access-keys --user-name {} --output json',
    provider: 'AWS',
    category: 'iam',
    tags: ['access-keys', 'unused', 'cleanup']
  },

  // AWS - Network
  {
    id: 'aws-net-1',
    title: 'Find security groups with 0.0.0.0/0 ingress',
    description: 'List security groups allowing traffic from anywhere',
    command: 'aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==\'0.0.0.0/0\']]].[GroupId,GroupName,Description]" --output table',
    provider: 'AWS',
    category: 'network',
    tags: ['security-groups', 'open-access', 'firewall']
  },
  {
    id: 'aws-net-2',
    title: 'Find open SSH ports (22)',
    description: 'Security groups with SSH open to the world',
    command: 'aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*].[GroupId,GroupName]" --output table',
    provider: 'AWS',
    category: 'network',
    tags: ['ssh', 'port-22', 'security-groups'],
    notes: 'Critical - SSH should never be open to 0.0.0.0/0'
  },
  {
    id: 'aws-net-3',
    title: 'Find open RDP ports (3389)',
    description: 'Security groups with RDP open to the world',
    command: 'aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=3389" "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[*].[GroupId,GroupName]" --output table',
    provider: 'AWS',
    category: 'network',
    tags: ['rdp', 'port-3389', 'security-groups'],
    notes: 'Critical - RDP should never be open to 0.0.0.0/0'
  },
  {
    id: 'aws-net-4',
    title: 'List VPCs and their CIDR blocks',
    description: 'Inventory of all VPCs and their IP ranges',
    command: 'aws ec2 describe-vpcs --query "Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0]]" --output table',
    provider: 'AWS',
    category: 'network',
    tags: ['vpc', 'cidr', 'inventory']
  },
  {
    id: 'aws-net-5',
    title: 'List VPC Flow Logs',
    description: 'Check which VPCs have flow logs enabled',
    command: 'aws ec2 describe-flow-logs --query "FlowLogs[*].[FlowLogId,ResourceId,FlowLogStatus,LogDestinationType]" --output table',
    provider: 'AWS',
    category: 'network',
    tags: ['flow-logs', 'monitoring', 'vpc'],
    notes: 'All VPCs should have flow logs enabled'
  },
  {
    id: 'aws-net-6',
    title: 'Find unused security groups',
    description: 'List security groups not attached to any ENI',
    command: 'aws ec2 describe-security-groups --query "SecurityGroups[*].GroupId" --output text | xargs -I {} aws ec2 describe-network-interfaces --filters "Name=group-id,Values={}" --query "NetworkInterfaces[0].NetworkInterfaceId" --output text',
    provider: 'AWS',
    category: 'network',
    tags: ['security-groups', 'unused', 'cleanup']
  },

  // AWS - Logging
  {
    id: 'aws-log-1',
    title: 'Check CloudTrail status',
    description: 'List all CloudTrail trails and their status',
    command: 'aws cloudtrail describe-trails --query "trailList[*].[Name,S3BucketName,IsMultiRegionTrail,LogFileValidationEnabled]" --output table',
    provider: 'AWS',
    category: 'logging',
    tags: ['cloudtrail', 'audit', 'trails']
  },
  {
    id: 'aws-log-2',
    title: 'Verify CloudTrail is logging',
    description: 'Check if trails are actively logging events',
    command: 'aws cloudtrail get-trail-status --name TRAIL_NAME --query "[IsLogging,LatestDeliveryTime]"',
    provider: 'AWS',
    category: 'logging',
    tags: ['cloudtrail', 'status', 'monitoring'],
    notes: 'Replace TRAIL_NAME with actual trail name'
  },
  {
    id: 'aws-log-3',
    title: 'Check S3 bucket logging',
    description: 'Verify server access logging for a bucket',
    command: 'aws s3api get-bucket-logging --bucket BUCKET_NAME',
    provider: 'AWS',
    category: 'logging',
    tags: ['s3', 'access-logs', 'buckets'],
    notes: 'Replace BUCKET_NAME with actual bucket name'
  },
  {
    id: 'aws-log-4',
    title: 'Check AWS Config status',
    description: 'Verify AWS Config is recording',
    command: 'aws configservice describe-configuration-recorders --query "ConfigurationRecorders[*].[name,recordingGroup.allSupported]" --output table',
    provider: 'AWS',
    category: 'logging',
    tags: ['config', 'recording', 'compliance']
  },
  {
    id: 'aws-log-5',
    title: 'List CloudWatch Log Groups',
    description: 'Inventory of all log groups and retention',
    command: 'aws logs describe-log-groups --query "logGroups[*].[logGroupName,retentionInDays,storedBytes]" --output table',
    provider: 'AWS',
    category: 'logging',
    tags: ['cloudwatch', 'logs', 'retention']
  },

  // AWS - Storage
  {
    id: 'aws-stor-1',
    title: 'List all S3 buckets',
    description: 'Get inventory of all S3 buckets',
    command: 'aws s3api list-buckets --query "Buckets[*].[Name,CreationDate]" --output table',
    provider: 'AWS',
    category: 'storage',
    tags: ['s3', 'inventory', 'buckets']
  },
  {
    id: 'aws-stor-2',
    title: 'Check S3 Block Public Access (account)',
    description: 'Verify account-level public access block',
    command: 'aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)',
    provider: 'AWS',
    category: 'storage',
    tags: ['s3', 'public-access', 'account-level']
  },
  {
    id: 'aws-stor-3',
    title: 'Check bucket encryption',
    description: 'Verify default encryption for a bucket',
    command: 'aws s3api get-bucket-encryption --bucket BUCKET_NAME',
    provider: 'AWS',
    category: 'storage',
    tags: ['s3', 'encryption', 'buckets'],
    notes: 'Replace BUCKET_NAME with actual bucket name'
  },
  {
    id: 'aws-stor-4',
    title: 'Find unencrypted EBS volumes',
    description: 'List EBS volumes without encryption',
    command: 'aws ec2 describe-volumes --query "Volumes[?Encrypted==`false`].[VolumeId,Size,State]" --output table',
    provider: 'AWS',
    category: 'storage',
    tags: ['ebs', 'encryption', 'volumes']
  },
  {
    id: 'aws-stor-5',
    title: 'Check bucket versioning',
    description: 'Verify versioning is enabled for a bucket',
    command: 'aws s3api get-bucket-versioning --bucket BUCKET_NAME',
    provider: 'AWS',
    category: 'storage',
    tags: ['s3', 'versioning', 'backup'],
    notes: 'Replace BUCKET_NAME with actual bucket name'
  },

  // AWS - Compute
  {
    id: 'aws-comp-1',
    title: 'List EC2 instances with public IPs',
    description: 'Find instances directly exposed to internet',
    command: 'aws ec2 describe-instances --query "Reservations[*].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]" --output table',
    provider: 'AWS',
    category: 'compute',
    tags: ['ec2', 'public-ip', 'exposure']
  },
  {
    id: 'aws-comp-2',
    title: 'Check EC2 IMDSv2 status',
    description: 'Find instances not using IMDSv2',
    command: 'aws ec2 describe-instances --query "Reservations[*].Instances[?MetadataOptions.HttpTokens!=`required`].[InstanceId,Tags[?Key==`Name`].Value|[0]]" --output table',
    provider: 'AWS',
    category: 'compute',
    tags: ['ec2', 'imds', 'metadata'],
    notes: 'IMDSv2 should be required for all instances'
  },
  {
    id: 'aws-comp-3',
    title: 'List Lambda functions',
    description: 'Inventory of all Lambda functions',
    command: 'aws lambda list-functions --query "Functions[*].[FunctionName,Runtime,LastModified]" --output table',
    provider: 'AWS',
    category: 'compute',
    tags: ['lambda', 'inventory', 'serverless']
  },
  {
    id: 'aws-comp-4',
    title: 'Check Lambda function policy',
    description: 'Review resource-based policy for a function',
    command: 'aws lambda get-policy --function-name FUNCTION_NAME',
    provider: 'AWS',
    category: 'compute',
    tags: ['lambda', 'policy', 'permissions'],
    notes: 'Replace FUNCTION_NAME with actual function name'
  },

  // AWS - Encryption
  {
    id: 'aws-enc-1',
    title: 'List KMS keys',
    description: 'Inventory of all KMS keys',
    command: 'aws kms list-keys --query "Keys[*].KeyId" --output table',
    provider: 'AWS',
    category: 'encryption',
    tags: ['kms', 'keys', 'inventory']
  },
  {
    id: 'aws-enc-2',
    title: 'Check KMS key rotation',
    description: 'Verify key rotation is enabled',
    command: 'aws kms get-key-rotation-status --key-id KEY_ID',
    provider: 'AWS',
    category: 'encryption',
    tags: ['kms', 'rotation', 'keys'],
    notes: 'Replace KEY_ID with actual key ID'
  },
  {
    id: 'aws-enc-3',
    title: 'Describe KMS key',
    description: 'Get detailed information about a KMS key',
    command: 'aws kms describe-key --key-id KEY_ID --query "KeyMetadata.[KeyId,KeyState,Description,KeyManager]"',
    provider: 'AWS',
    category: 'encryption',
    tags: ['kms', 'details', 'keys'],
    notes: 'Replace KEY_ID with actual key ID'
  },

  // Azure - IAM
  {
    id: 'azure-iam-1',
    title: 'List all Azure AD users',
    description: 'Get a list of all users in the directory',
    command: 'az ad user list --query "[].{Name:displayName,UPN:userPrincipalName,Enabled:accountEnabled}" --output table',
    provider: 'Azure',
    category: 'iam',
    tags: ['users', 'azure-ad', 'list']
  },
  {
    id: 'azure-iam-2',
    title: 'List role assignments',
    description: 'Show all RBAC assignments for the subscription',
    command: 'az role assignment list --query "[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}" --output table',
    provider: 'Azure',
    category: 'iam',
    tags: ['rbac', 'roles', 'permissions']
  },
  {
    id: 'azure-iam-3',
    title: 'Find Owner role assignments',
    description: 'List all principals with Owner role',
    command: 'az role assignment list --role "Owner" --query "[].{Principal:principalName,Type:principalType,Scope:scope}" --output table',
    provider: 'Azure',
    category: 'iam',
    tags: ['rbac', 'owner', 'privileged'],
    notes: 'Owner assignments should be minimized'
  },
  {
    id: 'azure-iam-4',
    title: 'List service principals',
    description: 'Get all service principals in Azure AD',
    command: 'az ad sp list --all --query "[].{Name:displayName,AppId:appId,Type:servicePrincipalType}" --output table',
    provider: 'Azure',
    category: 'iam',
    tags: ['service-principals', 'applications', 'azure-ad']
  },
  {
    id: 'azure-iam-5',
    title: 'List custom role definitions',
    description: 'Show all custom RBAC roles',
    command: 'az role definition list --custom-role-only --query "[].{Name:roleName,Type:roleType}" --output table',
    provider: 'Azure',
    category: 'iam',
    tags: ['rbac', 'custom-roles', 'permissions']
  },

  // Azure - Network
  {
    id: 'azure-net-1',
    title: 'List all NSGs',
    description: 'Get inventory of all Network Security Groups',
    command: 'az network nsg list --query "[].{Name:name,RG:resourceGroup,Location:location}" --output table',
    provider: 'Azure',
    category: 'network',
    tags: ['nsg', 'inventory', 'firewall']
  },
  {
    id: 'azure-net-2',
    title: 'List NSG rules',
    description: 'Show all rules for a specific NSG',
    command: 'az network nsg rule list --nsg-name NSG_NAME --resource-group RG_NAME --output table',
    provider: 'Azure',
    category: 'network',
    tags: ['nsg', 'rules', 'firewall'],
    notes: 'Replace NSG_NAME and RG_NAME with actual values'
  },
  {
    id: 'azure-net-3',
    title: 'List all public IPs',
    description: 'Inventory of public IP addresses',
    command: 'az network public-ip list --query "[].{Name:name,IP:ipAddress,Allocation:publicIpAllocationMethod,Associated:ipConfiguration.id}" --output table',
    provider: 'Azure',
    category: 'network',
    tags: ['public-ip', 'inventory', 'exposure']
  },
  {
    id: 'azure-net-4',
    title: 'Check Network Watcher status',
    description: 'Verify Network Watcher is enabled',
    command: 'az network watcher list --query "[].{Name:name,Location:location,State:provisioningState}" --output table',
    provider: 'Azure',
    category: 'network',
    tags: ['network-watcher', 'monitoring', 'regions']
  },
  {
    id: 'azure-net-5',
    title: 'List virtual networks',
    description: 'Get inventory of all VNets',
    command: 'az network vnet list --query "[].{Name:name,RG:resourceGroup,AddressSpace:addressSpace.addressPrefixes[0]}" --output table',
    provider: 'Azure',
    category: 'network',
    tags: ['vnet', 'inventory', 'network']
  },

  // Azure - Logging
  {
    id: 'azure-log-1',
    title: 'List Activity Log profiles',
    description: 'Check activity log export settings',
    command: 'az monitor log-profiles list --query "[].{Name:name,Retention:retentionPolicy.days,Enabled:retentionPolicy.enabled}" --output table',
    provider: 'Azure',
    category: 'logging',
    tags: ['activity-log', 'retention', 'monitoring']
  },
  {
    id: 'azure-log-2',
    title: 'List Log Analytics workspaces',
    description: 'Get inventory of Log Analytics workspaces',
    command: 'az monitor log-analytics workspace list --query "[].{Name:name,RG:resourceGroup,Retention:retentionInDays}" --output table',
    provider: 'Azure',
    category: 'logging',
    tags: ['log-analytics', 'workspace', 'monitoring']
  },
  {
    id: 'azure-log-3',
    title: 'Check diagnostic settings',
    description: 'List diagnostic settings for a resource',
    command: 'az monitor diagnostic-settings list --resource RESOURCE_ID',
    provider: 'Azure',
    category: 'logging',
    tags: ['diagnostic', 'logging', 'monitoring'],
    notes: 'Replace RESOURCE_ID with actual resource ID'
  },

  // Azure - Storage
  {
    id: 'azure-stor-1',
    title: 'List storage accounts',
    description: 'Get inventory of all storage accounts',
    command: 'az storage account list --query "[].{Name:name,RG:resourceGroup,Kind:kind,Replication:sku.name}" --output table',
    provider: 'Azure',
    category: 'storage',
    tags: ['storage', 'inventory', 'accounts']
  },
  {
    id: 'azure-stor-2',
    title: 'Check public blob access',
    description: 'Find storage accounts allowing public blob access',
    command: 'az storage account list --query "[?allowBlobPublicAccess==true].{Name:name,RG:resourceGroup}" --output table',
    provider: 'Azure',
    category: 'storage',
    tags: ['storage', 'public-access', 'blobs']
  },
  {
    id: 'azure-stor-3',
    title: 'Check secure transfer required',
    description: 'Verify HTTPS is required for storage accounts',
    command: 'az storage account list --query "[].{Name:name,SecureTransfer:enableHttpsTrafficOnly}" --output table',
    provider: 'Azure',
    category: 'storage',
    tags: ['storage', 'https', 'encryption']
  },
  {
    id: 'azure-stor-4',
    title: 'Check storage encryption',
    description: 'Verify encryption settings for storage accounts',
    command: 'az storage account list --query "[].{Name:name,Encryption:encryption.services.blob.enabled,KeySource:encryption.keySource}" --output table',
    provider: 'Azure',
    category: 'storage',
    tags: ['storage', 'encryption', 'security']
  },

  // Azure - Compute
  {
    id: 'azure-comp-1',
    title: 'List all VMs',
    description: 'Get inventory of all virtual machines',
    command: 'az vm list --query "[].{Name:name,RG:resourceGroup,Size:hardwareProfile.vmSize,OS:storageProfile.osDisk.osType}" --output table',
    provider: 'Azure',
    category: 'compute',
    tags: ['vm', 'inventory', 'compute']
  },
  {
    id: 'azure-comp-2',
    title: 'Check VM disk encryption',
    description: 'Verify disk encryption status',
    command: 'az vm encryption show --name VM_NAME --resource-group RG_NAME',
    provider: 'Azure',
    category: 'compute',
    tags: ['vm', 'encryption', 'disk'],
    notes: 'Replace VM_NAME and RG_NAME with actual values'
  },
  {
    id: 'azure-comp-3',
    title: 'List VM extensions',
    description: 'Show installed extensions on a VM',
    command: 'az vm extension list --vm-name VM_NAME --resource-group RG_NAME --output table',
    provider: 'Azure',
    category: 'compute',
    tags: ['vm', 'extensions', 'security'],
    notes: 'Replace VM_NAME and RG_NAME with actual values'
  },

  // Azure - Encryption
  {
    id: 'azure-enc-1',
    title: 'List Key Vaults',
    description: 'Get inventory of all Key Vaults',
    command: 'az keyvault list --query "[].{Name:name,RG:resourceGroup,Location:location}" --output table',
    provider: 'Azure',
    category: 'encryption',
    tags: ['keyvault', 'inventory', 'keys']
  },
  {
    id: 'azure-enc-2',
    title: 'Check Key Vault properties',
    description: 'Review Key Vault security settings',
    command: 'az keyvault show --name VAULT_NAME --query "{SoftDelete:properties.enableSoftDelete,PurgeProtection:properties.enablePurgeProtection}"',
    provider: 'Azure',
    category: 'encryption',
    tags: ['keyvault', 'security', 'settings'],
    notes: 'Replace VAULT_NAME with actual vault name'
  },
  {
    id: 'azure-enc-3',
    title: 'List Key Vault keys',
    description: 'Show all keys in a Key Vault',
    command: 'az keyvault key list --vault-name VAULT_NAME --output table',
    provider: 'Azure',
    category: 'encryption',
    tags: ['keyvault', 'keys', 'inventory'],
    notes: 'Replace VAULT_NAME with actual vault name'
  },

  // GCP - IAM
  {
    id: 'gcp-iam-1',
    title: 'Get IAM policy',
    description: 'Show project-level IAM policy',
    command: 'gcloud projects get-iam-policy PROJECT_ID --format="table(bindings.role,bindings.members)"',
    provider: 'GCP',
    category: 'iam',
    tags: ['iam', 'bindings', 'roles'],
    notes: 'Replace PROJECT_ID with actual project ID'
  },
  {
    id: 'gcp-iam-2',
    title: 'List service accounts',
    description: 'Get inventory of all service accounts',
    command: 'gcloud iam service-accounts list --format="table(email,displayName,disabled)"',
    provider: 'GCP',
    category: 'iam',
    tags: ['service-accounts', 'inventory', 'iam']
  },
  {
    id: 'gcp-iam-3',
    title: 'List service account keys',
    description: 'Show keys for a service account',
    command: 'gcloud iam service-accounts keys list --iam-account=SA_EMAIL --format="table(name,validAfterTime,validBeforeTime)"',
    provider: 'GCP',
    category: 'iam',
    tags: ['service-accounts', 'keys', 'credentials'],
    notes: 'Replace SA_EMAIL with service account email'
  },
  {
    id: 'gcp-iam-4',
    title: 'Find primitive role assignments',
    description: 'Look for Owner/Editor/Viewer roles',
    command: 'gcloud projects get-iam-policy PROJECT_ID --format=json | grep -E "roles/(owner|editor|viewer)"',
    provider: 'GCP',
    category: 'iam',
    tags: ['iam', 'primitive-roles', 'permissions'],
    notes: 'Prefer predefined roles over primitive roles'
  },
  {
    id: 'gcp-iam-5',
    title: 'Check for public IAM bindings',
    description: 'Find allUsers or allAuthenticatedUsers bindings',
    command: 'gcloud projects get-iam-policy PROJECT_ID --format=json | grep -E "allUsers|allAuthenticatedUsers"',
    provider: 'GCP',
    category: 'iam',
    tags: ['iam', 'public', 'permissions'],
    notes: 'Critical - review any public bindings carefully'
  },

  // GCP - Network
  {
    id: 'gcp-net-1',
    title: 'List firewall rules',
    description: 'Get inventory of all firewall rules',
    command: 'gcloud compute firewall-rules list --format="table(name,network,direction,allowed,sourceRanges)"',
    provider: 'GCP',
    category: 'network',
    tags: ['firewall', 'rules', 'inventory']
  },
  {
    id: 'gcp-net-2',
    title: 'Find open firewall rules',
    description: 'Firewall rules allowing 0.0.0.0/0',
    command: 'gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0" --format="table(name,network,allowed,sourceRanges)"',
    provider: 'GCP',
    category: 'network',
    tags: ['firewall', 'open-access', 'rules']
  },
  {
    id: 'gcp-net-3',
    title: 'List VPC networks',
    description: 'Get inventory of all VPC networks',
    command: 'gcloud compute networks list --format="table(name,autoCreateSubnetworks,routingConfig.routingMode)"',
    provider: 'GCP',
    category: 'network',
    tags: ['vpc', 'networks', 'inventory']
  },
  {
    id: 'gcp-net-4',
    title: 'Check VPC subnets',
    description: 'List all subnets with flow log status',
    command: 'gcloud compute networks subnets list --format="table(name,region,ipCidrRange,enableFlowLogs)"',
    provider: 'GCP',
    category: 'network',
    tags: ['subnets', 'flow-logs', 'vpc']
  },
  {
    id: 'gcp-net-5',
    title: 'Find SSH firewall rules',
    description: 'Firewall rules allowing SSH from anywhere',
    command: 'gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0 AND allowed[].ports:22" --format="table(name,network)"',
    provider: 'GCP',
    category: 'network',
    tags: ['firewall', 'ssh', 'port-22']
  },

  // GCP - Logging
  {
    id: 'gcp-log-1',
    title: 'List log sinks',
    description: 'Show configured log export sinks',
    command: 'gcloud logging sinks list --format="table(name,destination,filter)"',
    provider: 'GCP',
    category: 'logging',
    tags: ['logging', 'sinks', 'export']
  },
  {
    id: 'gcp-log-2',
    title: 'Check audit log config',
    description: 'View data access audit log settings',
    command: 'gcloud projects get-iam-policy PROJECT_ID --format=json | jq ".auditConfigs"',
    provider: 'GCP',
    category: 'logging',
    tags: ['audit-logs', 'data-access', 'logging'],
    notes: 'Replace PROJECT_ID with actual project ID'
  },
  {
    id: 'gcp-log-3',
    title: 'List log buckets',
    description: 'Show log buckets and retention',
    command: 'gcloud logging buckets list --location=global --format="table(name,retentionDays,locked)"',
    provider: 'GCP',
    category: 'logging',
    tags: ['logging', 'retention', 'buckets']
  },

  // GCP - Storage
  {
    id: 'gcp-stor-1',
    title: 'List Cloud Storage buckets',
    description: 'Get inventory of all buckets',
    command: 'gcloud storage buckets list --format="table(name,location,storageClass)"',
    provider: 'GCP',
    category: 'storage',
    tags: ['storage', 'buckets', 'inventory']
  },
  {
    id: 'gcp-stor-2',
    title: 'Check bucket IAM policy',
    description: 'Review IAM policy for a bucket',
    command: 'gcloud storage buckets get-iam-policy gs://BUCKET_NAME',
    provider: 'GCP',
    category: 'storage',
    tags: ['storage', 'iam', 'permissions'],
    notes: 'Replace BUCKET_NAME with actual bucket name'
  },
  {
    id: 'gcp-stor-3',
    title: 'Check uniform bucket access',
    description: 'Verify uniform bucket-level access',
    command: 'gcloud storage buckets describe gs://BUCKET_NAME --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)"',
    provider: 'GCP',
    category: 'storage',
    tags: ['storage', 'uniform-access', 'buckets'],
    notes: 'Replace BUCKET_NAME with actual bucket name'
  },

  // GCP - Compute
  {
    id: 'gcp-comp-1',
    title: 'List compute instances',
    description: 'Get inventory of all VMs',
    command: 'gcloud compute instances list --format="table(name,zone,machineType,status,networkInterfaces[0].accessConfigs[0].natIP)"',
    provider: 'GCP',
    category: 'compute',
    tags: ['compute', 'vms', 'inventory']
  },
  {
    id: 'gcp-comp-2',
    title: 'Find instances with external IPs',
    description: 'VMs with public IP addresses',
    command: 'gcloud compute instances list --filter="networkInterfaces[0].accessConfigs[0].natIP:*" --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)"',
    provider: 'GCP',
    category: 'compute',
    tags: ['compute', 'external-ip', 'vms']
  },
  {
    id: 'gcp-comp-3',
    title: 'Check Shielded VM status',
    description: 'Verify shielded VM features',
    command: 'gcloud compute instances list --format="table(name,shieldedInstanceConfig.enableSecureBoot,shieldedInstanceConfig.enableVtpm)"',
    provider: 'GCP',
    category: 'compute',
    tags: ['compute', 'shielded-vm', 'security']
  },
  {
    id: 'gcp-comp-4',
    title: 'Check instance service account',
    description: 'View service account attached to instances',
    command: 'gcloud compute instances list --format="table(name,serviceAccounts[0].email,serviceAccounts[0].scopes)"',
    provider: 'GCP',
    category: 'compute',
    tags: ['compute', 'service-account', 'permissions']
  },

  // GCP - Encryption
  {
    id: 'gcp-enc-1',
    title: 'List KMS keyrings',
    description: 'Get inventory of KMS keyrings',
    command: 'gcloud kms keyrings list --location=global --format="table(name)"',
    provider: 'GCP',
    category: 'encryption',
    tags: ['kms', 'keyrings', 'inventory']
  },
  {
    id: 'gcp-enc-2',
    title: 'List KMS keys',
    description: 'Show keys in a keyring',
    command: 'gcloud kms keys list --keyring=KEYRING_NAME --location=global --format="table(name,purpose,rotationPeriod)"',
    provider: 'GCP',
    category: 'encryption',
    tags: ['kms', 'keys', 'inventory'],
    notes: 'Replace KEYRING_NAME with actual keyring name'
  },
  {
    id: 'gcp-enc-3',
    title: 'Check key IAM policy',
    description: 'Review who has access to a KMS key',
    command: 'gcloud kms keys get-iam-policy KEY_NAME --keyring=KEYRING_NAME --location=global',
    provider: 'GCP',
    category: 'encryption',
    tags: ['kms', 'iam', 'permissions'],
    notes: 'Replace KEY_NAME and KEYRING_NAME with actual values'
  }
];

export const categoryLabels: Record<string, string> = {
  iam: 'Identity & Access',
  network: 'Network Security',
  logging: 'Logging & Monitoring',
  storage: 'Storage Security',
  compute: 'Compute Security',
  encryption: 'Encryption & Keys'
};
