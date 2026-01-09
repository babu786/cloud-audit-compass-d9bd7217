import { AuditControl } from '@/data/auditContent';
import { ValidationError } from '@/utils/importControls';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';

interface ImportPreviewTableProps {
  controls: Partial<AuditControl>[];
  errors: ValidationError[];
}

export function ImportPreviewTable({ controls, errors }: ImportPreviewTableProps) {
  const errorsByRow = errors.reduce((acc, err) => {
    if (!acc[err.row]) acc[err.row] = [];
    acc[err.row].push(err);
    return acc;
  }, {} as Record<number, ValidationError[]>);

  const errorsByField = errors.reduce((acc, err) => {
    if (!acc[err.field]) acc[err.field] = [];
    acc[err.field].push(err);
    return acc;
  }, {} as Record<string, ValidationError[]>);

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500/10 text-red-500 border-red-500/20';
      case 'High': return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case 'Low': return 'bg-green-500/10 text-green-500 border-green-500/20';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getErrorIcon = (field: string) => {
    const requiredFields = ['id', 'title', 'severity', 'cloudProvider', 'framework', 'category'];
    if (requiredFields.includes(field)) {
      return <XCircle className="h-4 w-4 text-destructive" />;
    }
    return <AlertTriangle className="h-4 w-4 text-amber-500" />;
  };

  if (controls.length === 0 && errors.length === 0) {
    return null;
  }

  const validControlsCount = controls.length;
  const affectedRows = Object.keys(errorsByRow).length;

  return (
    <div className="space-y-4">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="flex items-center gap-2 p-3 rounded-lg bg-secondary/50 border">
          <Info className="h-5 w-5 text-muted-foreground" />
          <div>
            <div className="text-xs text-muted-foreground">Total Rows</div>
            <div className="font-semibold">{controls.length + affectedRows}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 p-3 rounded-lg bg-green-500/10 border border-green-500/20">
          <CheckCircle2 className="h-5 w-5 text-green-500" />
          <div>
            <div className="text-xs text-muted-foreground">Valid</div>
            <div className="font-semibold text-green-600">{validControlsCount}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/20">
          <XCircle className="h-5 w-5 text-destructive" />
          <div>
            <div className="text-xs text-muted-foreground">Errors</div>
            <div className="font-semibold text-destructive">{errors.length}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
          <AlertTriangle className="h-5 w-5 text-amber-500" />
          <div>
            <div className="text-xs text-muted-foreground">Affected Rows</div>
            <div className="font-semibold text-amber-600">{affectedRows}</div>
          </div>
        </div>
      </div>

      {/* Errors by Field - Collapsible */}
      {errors.length > 0 && (
        <Accordion type="single" collapsible defaultValue="errors" className="border rounded-lg">
          <AccordionItem value="errors" className="border-0">
            <AccordionTrigger className="px-4 py-3 hover:no-underline">
              <div className="flex items-center gap-2 text-destructive">
                <AlertCircle className="h-5 w-5" />
                <span className="font-medium">{errors.length} validation error(s) found</span>
              </div>
            </AccordionTrigger>
            <AccordionContent className="px-4 pb-4">
              <div className="space-y-3">
                {Object.entries(errorsByField).map(([field, fieldErrors]) => (
                  <div key={field} className="rounded-lg border bg-card p-3">
                    <div className="flex items-center gap-2 mb-2">
                      {getErrorIcon(field)}
                      <span className="font-medium capitalize">{field}</span>
                      <Badge variant="outline" className="ml-auto text-xs">
                        {fieldErrors.length} error{fieldErrors.length > 1 ? 's' : ''}
                      </Badge>
                    </div>
                    <ul className="space-y-1 text-sm text-muted-foreground pl-6">
                      {fieldErrors.slice(0, 5).map((err, i) => (
                        <li key={i} className="list-disc">
                          <span className="font-mono text-xs bg-secondary px-1 rounded">Row {err.row}</span>
                          {' '}{err.message}
                        </li>
                      ))}
                      {fieldErrors.length > 5 && (
                        <li className="text-muted-foreground italic">
                          ... and {fieldErrors.length - 5} more
                        </li>
                      )}
                    </ul>
                  </div>
                ))}
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      )}

      {/* Valid Controls Preview */}
      {controls.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-green-600 font-medium">
            <CheckCircle2 className="h-5 w-5" />
            <span>{controls.length} valid control(s) ready to import</span>
          </div>
          
          <div className="border rounded-lg overflow-hidden">
            <ScrollArea className="h-72">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-secondary/80 backdrop-blur-sm">
                  <tr>
                    <th className="text-left p-3 font-semibold text-foreground">ID</th>
                    <th className="text-left p-3 font-semibold text-foreground">Title</th>
                    <th className="text-left p-3 font-semibold text-foreground">Severity</th>
                    <th className="text-left p-3 font-semibold text-foreground">Provider</th>
                    <th className="text-left p-3 font-semibold text-foreground">Category</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {controls.map((control, index) => {
                    const hasErrors = errorsByRow[index + 1];
                    return (
                      <tr 
                        key={control.id || index}
                        className={cn(
                          "transition-colors",
                          hasErrors ? "bg-destructive/5" : "hover:bg-secondary/30"
                        )}
                      >
                        <td className="p-3">
                          <code className="font-mono text-xs bg-secondary px-1.5 py-0.5 rounded">
                            {control.id}
                          </code>
                        </td>
                        <td className="p-3 max-w-xs">
                          <span className="line-clamp-1" title={control.title}>
                            {control.title}
                          </span>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline" className={cn("font-medium", getSeverityColor(control.severity))}>
                            {control.severity}
                          </Badge>
                        </td>
                        <td className="p-3">
                          <Badge variant="secondary" className="font-normal">
                            {control.cloudProvider}
                          </Badge>
                        </td>
                        <td className="p-3">
                          <span className="capitalize text-muted-foreground">{control.category}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </ScrollArea>
          </div>
        </div>
      )}
    </div>
  );
}
