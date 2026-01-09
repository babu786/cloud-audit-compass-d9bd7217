import { AuditControl } from '@/data/auditContent';
import { ValidationError } from '@/utils/importControls';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, CheckCircle2 } from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';

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

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500/10 text-red-500 border-red-500/20';
      case 'High': return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case 'Low': return 'bg-green-500/10 text-green-500 border-green-500/20';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  if (controls.length === 0 && errors.length === 0) {
    return null;
  }

  return (
    <div className="space-y-4">
      {/* Error Summary */}
      {errors.length > 0 && (
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
          <div className="flex items-center gap-2 text-destructive font-medium mb-2">
            <AlertCircle className="h-4 w-4" />
            <span>{errors.length} validation error(s) found</span>
          </div>
          <ScrollArea className="max-h-32">
            <ul className="text-sm space-y-1 text-destructive/80">
              {errors.slice(0, 10).map((err, i) => (
                <li key={i}>
                  Row {err.row}: {err.field} - {err.message}
                </li>
              ))}
              {errors.length > 10 && (
                <li className="text-muted-foreground">
                  ... and {errors.length - 10} more errors
                </li>
              )}
            </ul>
          </ScrollArea>
        </div>
      )}

      {/* Valid Controls Preview */}
      {controls.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-green-500 font-medium">
            <CheckCircle2 className="h-4 w-4" />
            <span>{controls.length} valid control(s) ready to import</span>
          </div>
          
          <ScrollArea className="h-64 border rounded-lg">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-background border-b">
                <tr>
                  <th className="text-left p-3 font-medium">ID</th>
                  <th className="text-left p-3 font-medium">Title</th>
                  <th className="text-left p-3 font-medium">Severity</th>
                  <th className="text-left p-3 font-medium">Provider</th>
                  <th className="text-left p-3 font-medium">Category</th>
                </tr>
              </thead>
              <tbody>
                {controls.map((control, index) => {
                  const hasErrors = errorsByRow[index + 1];
                  return (
                    <tr 
                      key={control.id || index}
                      className={cn(
                        "border-b last:border-0 transition-colors",
                        hasErrors ? "bg-destructive/5" : "hover:bg-secondary/30"
                      )}
                    >
                      <td className="p-3 font-mono text-xs">{control.id}</td>
                      <td className="p-3 max-w-xs truncate">{control.title}</td>
                      <td className="p-3">
                        <Badge variant="outline" className={getSeverityColor(control.severity)}>
                          {control.severity}
                        </Badge>
                      </td>
                      <td className="p-3">{control.cloudProvider}</td>
                      <td className="p-3 capitalize">{control.category}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </ScrollArea>
        </div>
      )}
    </div>
  );
}
