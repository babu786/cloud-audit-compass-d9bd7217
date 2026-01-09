import { AuditControl } from '@/data/auditContent';

export interface ValidationError {
  row: number;
  field: string;
  message: string;
}

export interface ParseResult {
  controls: Partial<AuditControl>[];
  errors: ValidationError[];
  isValid: boolean;
}

const VALID_SEVERITIES = ['Low', 'Medium', 'High', 'Critical'] as const;
const VALID_PROVIDERS = ['AWS', 'Azure', 'GCP'] as const;
const VALID_FRAMEWORKS = ['CIS Benchmark', 'ISO 27001', 'Internal Baseline'] as const;
const VALID_CATEGORIES = ['iam', 'network', 'logging', 'storage', 'compute', 'encryption', 'databricks', 'security', 'governance'] as const;

export function parseCSV(csvText: string): ParseResult {
  const lines = csvText.trim().split('\n');
  const errors: ValidationError[] = [];
  const controls: Partial<AuditControl>[] = [];

  if (lines.length < 2) {
    errors.push({ row: 0, field: 'file', message: 'CSV must have a header row and at least one data row' });
    return { controls: [], errors, isValid: false };
  }

  const headers = parseCSVLine(lines[0]);
  const requiredHeaders = ['id', 'title', 'severity', 'cloudProvider', 'framework', 'category', 'whatToCheck', 'whyItMatters', 'consoleSteps', 'expectedConfig', 'commonMisconfigs', 'fixHint'];
  
  const missingHeaders = requiredHeaders.filter(h => !headers.includes(h));
  if (missingHeaders.length > 0) {
    errors.push({ row: 0, field: 'headers', message: `Missing required headers: ${missingHeaders.join(', ')}` });
    return { controls: [], errors, isValid: false };
  }

  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    
    const values = parseCSVLine(lines[i]);
    const control: Partial<AuditControl> = {};
    
    headers.forEach((header, index) => {
      const value = values[index]?.trim() || '';
      
      if (header === 'consoleSteps' || header === 'commonMisconfigs') {
        (control as any)[header] = value.split('|').map(s => s.trim()).filter(Boolean);
      } else {
        (control as any)[header] = value;
      }
    });

    const rowErrors = validateControl(control, i + 1);
    errors.push(...rowErrors);
    
    if (rowErrors.length === 0) {
      controls.push(control);
    }
  }

  return { controls, errors, isValid: errors.length === 0 };
}

function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  
  return result;
}

export function parseJSON(jsonText: string): ParseResult {
  const errors: ValidationError[] = [];
  const controls: Partial<AuditControl>[] = [];

  try {
    const parsed = JSON.parse(jsonText);
    const controlsArray = parsed.controls || parsed;

    if (!Array.isArray(controlsArray)) {
      errors.push({ row: 0, field: 'structure', message: 'JSON must contain an array of controls or an object with "controls" array' });
      return { controls: [], errors, isValid: false };
    }

    controlsArray.forEach((control: any, index: number) => {
      const rowErrors = validateControl(control, index + 1);
      errors.push(...rowErrors);
      
      if (rowErrors.length === 0) {
        controls.push(control);
      }
    });

  } catch (e) {
    errors.push({ row: 0, field: 'json', message: `Invalid JSON: ${e instanceof Error ? e.message : 'Unknown error'}` });
  }

  return { controls, errors, isValid: errors.length === 0 };
}

function validateControl(control: Partial<AuditControl>, row: number): ValidationError[] {
  const errors: ValidationError[] = [];

  // Required string fields
  const requiredStrings: (keyof AuditControl)[] = ['id', 'title', 'whatToCheck', 'whyItMatters', 'expectedConfig', 'fixHint'];
  requiredStrings.forEach(field => {
    if (!control[field] || typeof control[field] !== 'string' || !String(control[field]).trim()) {
      errors.push({ row, field, message: `${field} is required` });
    }
  });

  // Severity validation
  if (!control.severity || !VALID_SEVERITIES.includes(control.severity as any)) {
    errors.push({ row, field: 'severity', message: `severity must be one of: ${VALID_SEVERITIES.join(', ')}` });
  }

  // Cloud provider validation
  if (!control.cloudProvider || !VALID_PROVIDERS.includes(control.cloudProvider as any)) {
    errors.push({ row, field: 'cloudProvider', message: `cloudProvider must be one of: ${VALID_PROVIDERS.join(', ')}` });
  }

  // Framework validation
  if (!control.framework || !VALID_FRAMEWORKS.includes(control.framework as any)) {
    errors.push({ row, field: 'framework', message: `framework must be one of: ${VALID_FRAMEWORKS.join(', ')}` });
  }

  // Category validation
  if (!control.category || !VALID_CATEGORIES.includes(control.category as any)) {
    errors.push({ row, field: 'category', message: `category must be one of: ${VALID_CATEGORIES.join(', ')}` });
  }

  // Array fields validation
  if (!Array.isArray(control.consoleSteps) || control.consoleSteps.length === 0) {
    errors.push({ row, field: 'consoleSteps', message: 'consoleSteps must be an array with at least one item' });
  }

  if (!Array.isArray(control.commonMisconfigs) || control.commonMisconfigs.length === 0) {
    errors.push({ row, field: 'commonMisconfigs', message: 'commonMisconfigs must be an array with at least one item' });
  }

  return errors;
}

export function generateCSVTemplate(): string {
  const headers = 'id,title,severity,cloudProvider,framework,category,whatToCheck,whyItMatters,consoleSteps,cliCheck,expectedConfig,commonMisconfigs,fixHint';
  const exampleRow1 = '"CUSTOM-001","Enable MFA for All Users","High","AWS","Internal Baseline","iam","Verify that MFA is enabled for all IAM users","MFA adds an extra layer of security preventing unauthorized access","Step 1: Go to IAM Console|Step 2: Check each user\'s MFA status|Step 3: Enable MFA for users without it","aws iam list-users --query \'Users[*].UserName\'","All IAM users should have MFA enabled","MFA not enabled|Virtual MFA on personal device|SMS MFA instead of TOTP","Enable virtual or hardware MFA via IAM > Users > Security Credentials"';
  const exampleRow2 = '"CUSTOM-002","Encrypt S3 Buckets at Rest","Critical","AWS","CIS Benchmark","storage","Verify all S3 buckets have encryption enabled","Encryption protects data confidentiality if storage is compromised","Step 1: Navigate to S3 Console|Step 2: Select bucket|Step 3: Check encryption settings","aws s3api get-bucket-encryption --bucket <bucket-name>","Default encryption should be SSE-S3 or SSE-KMS","No encryption configured|Client-side encryption without key management|Using deprecated encryption","Enable default encryption via S3 > Bucket > Properties > Default encryption"';

  return `${headers}\n${exampleRow1}\n${exampleRow2}`;
}

export function generateJSONTemplate(): string {
  const template = {
    controls: [
      {
        id: "CUSTOM-001",
        title: "Enable MFA for All Users",
        severity: "High",
        cloudProvider: "AWS",
        framework: "Internal Baseline",
        category: "iam",
        whatToCheck: "Verify that MFA is enabled for all IAM users",
        whyItMatters: "MFA adds an extra layer of security preventing unauthorized access",
        consoleSteps: [
          "Step 1: Go to IAM Console",
          "Step 2: Check each user's MFA status",
          "Step 3: Enable MFA for users without it"
        ],
        cliCheck: "aws iam list-users --query 'Users[*].UserName'",
        expectedConfig: "All IAM users should have MFA enabled",
        commonMisconfigs: [
          "MFA not enabled",
          "Virtual MFA on personal device",
          "SMS MFA instead of TOTP"
        ],
        fixHint: "Enable virtual or hardware MFA via IAM > Users > Security Credentials"
      },
      {
        id: "CUSTOM-002",
        title: "Encrypt S3 Buckets at Rest",
        severity: "Critical",
        cloudProvider: "AWS",
        framework: "CIS Benchmark",
        category: "storage",
        whatToCheck: "Verify all S3 buckets have encryption enabled",
        whyItMatters: "Encryption protects data confidentiality if storage is compromised",
        consoleSteps: [
          "Step 1: Navigate to S3 Console",
          "Step 2: Select bucket",
          "Step 3: Check encryption settings"
        ],
        cliCheck: "aws s3api get-bucket-encryption --bucket <bucket-name>",
        expectedConfig: "Default encryption should be SSE-S3 or SSE-KMS",
        commonMisconfigs: [
          "No encryption configured",
          "Client-side encryption without key management",
          "Using deprecated encryption"
        ],
        fixHint: "Enable default encryption via S3 > Bucket > Properties > Default encryption"
      }
    ]
  };

  return JSON.stringify(template, null, 2);
}

export function downloadTemplate(format: 'csv' | 'json'): void {
  const content = format === 'csv' ? generateCSVTemplate() : generateJSONTemplate();
  const mimeType = format === 'csv' ? 'text/csv' : 'application/json';
  const filename = `audit-controls-template.${format}`;

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
