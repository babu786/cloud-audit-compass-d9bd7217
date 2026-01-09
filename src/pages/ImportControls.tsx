import { useState, useCallback } from 'react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { FileDropzone } from '@/components/import/FileDropzone';
import { ImportPreviewTable } from '@/components/import/ImportPreviewTable';
import { useImportedControls } from '@/hooks/useImportedControls';
import { parseCSV, parseJSON, downloadTemplate, ParseResult } from '@/utils/importControls';
import { Download, FileText, FileJson, Upload, Trash2, CheckCircle, Lock, LogOut } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useLanguage } from '@/i18n/LanguageContext';
import { AuditControl } from '@/data/auditContent';
import { useAdminAuth } from '@/hooks/useAdminAuth';

export default function ImportControls() {
  const { t } = useLanguage();
  const { toast } = useToast();
  const { addControls, importedControls, clearAllImported, importedCount } = useImportedControls();
  const { isAdmin, openLoginModal, logout } = useAdminAuth();
  
  const [parseResult, setParseResult] = useState<ParseResult | null>(null);
  const [fileType, setFileType] = useState<'csv' | 'json' | null>(null);

  const handleFileSelect = useCallback((file: File, content: string) => {
    const isJSON = file.name.endsWith('.json');
    setFileType(isJSON ? 'json' : 'csv');
    
    const result = isJSON ? parseJSON(content) : parseCSV(content);
    setParseResult(result);

    if (result.errors.length > 0) {
      toast({
        title: "Validation Issues Found",
        description: `${result.errors.length} error(s) detected. Please fix and re-upload.`,
        variant: "destructive",
      });
    } else if (result.controls.length > 0) {
      toast({
        title: "File Parsed Successfully",
        description: `${result.controls.length} control(s) ready to import.`,
      });
    }
  }, [toast]);

  const handleImport = useCallback(() => {
    if (!parseResult || parseResult.controls.length === 0) return;

    addControls(parseResult.controls as Partial<AuditControl>[]);
    
    toast({
      title: "Import Successful!",
      description: `${parseResult.controls.length} control(s) have been added.`,
    });

    setParseResult(null);
    setFileType(null);
  }, [parseResult, addControls, toast]);

  const handleClearAll = useCallback(() => {
    clearAllImported();
    toast({
      title: "Controls Cleared",
      description: "All imported controls have been removed.",
    });
  }, [clearAllImported, toast]);

  const handleLogout = () => {
    logout();
    setParseResult(null);
    setFileType(null);
    toast({
      title: "Logged Out",
      description: "You have been logged out.",
    });
  };

  // Show login required view if not admin
  if (!isAdmin) {
    return (
      <AppLayout>
        <div className="container py-8 max-w-4xl">
          <div className="space-y-2 mb-8">
            <h1 className="text-3xl font-bold tracking-tight">Import Controls</h1>
            <p className="text-muted-foreground">
              Bulk import audit controls from CSV or JSON files
            </p>
          </div>

          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-16 text-center">
              <div className="rounded-full bg-primary/10 p-4 mb-4">
                <Lock className="h-8 w-8 text-primary" />
              </div>
              <h2 className="text-xl font-semibold mb-2">Admin Access Required</h2>
              <p className="text-muted-foreground mb-6 max-w-md">
                You need to login as an administrator to import controls. This helps maintain data integrity and security.
              </p>
              <Button onClick={openLoginModal} size="lg" className="gap-2">
                <Lock className="h-4 w-4" />
                Login to Continue
              </Button>
            </CardContent>
          </Card>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="container py-8 max-w-4xl">
        <div className="flex items-center justify-between mb-8">
          <div className="space-y-2">
            <h1 className="text-3xl font-bold tracking-tight">Import Controls</h1>
            <p className="text-muted-foreground">
              Bulk import audit controls from CSV or JSON files
            </p>
          </div>
          <Button variant="outline" onClick={handleLogout} className="gap-2">
            <LogOut className="h-4 w-4" />
            Logout
          </Button>
        </div>

        {/* Template Downloads */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Download className="h-5 w-5" />
              Download Templates
            </CardTitle>
            <CardDescription>
              Download template files with example data and correct structure
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Button
                variant="outline"
                onClick={() => downloadTemplate('csv')}
                className="gap-2"
              >
                <FileText className="h-4 w-4" />
                Download CSV Template
              </Button>
              <Button
                variant="outline"
                onClick={() => downloadTemplate('json')}
                className="gap-2"
              >
                <FileJson className="h-4 w-4" />
                Download JSON Template
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* File Upload */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Upload className="h-5 w-5" />
              Upload Controls
            </CardTitle>
            <CardDescription>
              Upload a CSV or JSON file containing your audit controls
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FileDropzone onFileSelect={handleFileSelect} />
            
            {parseResult && (
              <>
                <ImportPreviewTable 
                  controls={parseResult.controls} 
                  errors={parseResult.errors} 
                />
                
                {parseResult.controls.length > 0 && parseResult.errors.length === 0 && (
                  <Button
                    onClick={handleImport}
                    className="w-full gap-2"
                    size="lg"
                  >
                    <CheckCircle className="h-4 w-4" />
                    Import {parseResult.controls.length} Control(s)
                  </Button>
                )}
              </>
            )}
          </CardContent>
        </Card>

        {/* Imported Controls Status */}
        {importedCount > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Imported Controls</CardTitle>
              <CardDescription>
                You have {importedCount} custom control(s) imported
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-sm text-muted-foreground">
                  These controls are stored locally and will persist across sessions.
                </div>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleClearAll}
                  className="gap-2"
                >
                  <Trash2 className="h-4 w-4" />
                  Clear All
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Field Reference */}
        <Card className="mt-6">
          <CardHeader>
            <CardTitle className="text-lg">Field Reference</CardTitle>
            <CardDescription>
              Required fields and valid values for import
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-sm space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium mb-2">Required Fields</h4>
                  <ul className="space-y-1 text-muted-foreground">
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">id</code> - Unique identifier</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">title</code> - Control title</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">severity</code> - Low, Medium, High, Critical</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">cloudProvider</code> - AWS, Azure, GCP</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">framework</code> - CIS Benchmark, ISO 27001, Internal Baseline</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">category</code> - iam, network, logging, etc.</li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium mb-2">Content Fields</h4>
                  <ul className="space-y-1 text-muted-foreground">
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">whatToCheck</code> - Description</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">whyItMatters</code> - Importance</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">consoleSteps</code> - Steps (pipe-separated in CSV)</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">cliCheck</code> - CLI command (optional)</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">expectedConfig</code> - Expected state</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">commonMisconfigs</code> - Issues (pipe-separated in CSV)</li>
                    <li>• <code className="text-xs bg-secondary px-1 py-0.5 rounded">fixHint</code> - Remediation guidance</li>
                  </ul>
                </div>
              </div>
              <p className="text-muted-foreground mt-4">
                <strong>CSV Note:</strong> For array fields (consoleSteps, commonMisconfigs), use pipe (<code className="bg-secondary px-1 py-0.5 rounded">|</code>) to separate items.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
}
