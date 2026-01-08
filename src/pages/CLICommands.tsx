import { useState, useMemo } from 'react';
import { Search, Copy, Check, Terminal, Filter } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useLanguage } from '@/i18n/LanguageContext';
import { cliCommands, CLICommand, categoryLabels } from '@/data/cliCommands';
import { toast } from 'sonner';

type ProviderFilter = 'All' | 'AWS' | 'Azure' | 'GCP';
type CategoryFilter = 'all' | 'iam' | 'network' | 'logging' | 'storage' | 'compute' | 'encryption';

const providerColors: Record<string, string> = {
  AWS: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
  Azure: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
  GCP: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
};

const categoryColors: Record<string, string> = {
  iam: 'bg-purple-500/10 text-purple-600 dark:text-purple-400',
  network: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400',
  logging: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
  storage: 'bg-green-500/10 text-green-600 dark:text-green-400',
  compute: 'bg-pink-500/10 text-pink-600 dark:text-pink-400',
  encryption: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400',
};

export default function CLICommands() {
  const { t } = useLanguage();
  const [searchQuery, setSearchQuery] = useState('');
  const [providerFilter, setProviderFilter] = useState<ProviderFilter>('All');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredCommands = useMemo(() => {
    return cliCommands.filter((cmd) => {
      const matchesProvider = providerFilter === 'All' || cmd.provider === providerFilter;
      const matchesCategory = categoryFilter === 'all' || cmd.category === categoryFilter;
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        searchQuery === '' ||
        cmd.title.toLowerCase().includes(searchLower) ||
        cmd.description.toLowerCase().includes(searchLower) ||
        cmd.command.toLowerCase().includes(searchLower) ||
        cmd.tags.some((tag) => tag.toLowerCase().includes(searchLower));
      return matchesProvider && matchesCategory && matchesSearch;
    });
  }, [searchQuery, providerFilter, categoryFilter]);

  const copyToClipboard = async (command: string, id: string) => {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedId(id);
      toast.success(t.cli.copied);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      toast.error(t.cli.copyFailed);
    }
  };

  const providers: ProviderFilter[] = ['All', 'AWS', 'Azure', 'GCP'];
  const categories: { id: CategoryFilter; label: string }[] = [
    { id: 'all', label: t.cli.allCategories },
    { id: 'iam', label: t.categories.iam },
    { id: 'network', label: t.categories.network },
    { id: 'logging', label: t.categories.logging },
    { id: 'storage', label: t.categories.storage },
    { id: 'compute', label: t.categories.compute },
    { id: 'encryption', label: t.categories.encryption },
  ];

  // Group by category for display
  const groupedCommands = useMemo(() => {
    const groups: Record<string, CLICommand[]> = {};
    filteredCommands.forEach((cmd) => {
      if (!groups[cmd.category]) {
        groups[cmd.category] = [];
      }
      groups[cmd.category].push(cmd);
    });
    return groups;
  }, [filteredCommands]);

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-3">
            <Terminal className="h-8 w-8 text-primary" />
            <h1 className="text-3xl md:text-4xl font-bold text-foreground">
              {t.cli.title}
            </h1>
          </div>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            {t.cli.subtitle}
          </p>
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder={t.cli.searchPlaceholder}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
          {searchQuery && (
            <Button
              variant="ghost"
              size="sm"
              className="absolute right-2 top-1/2 -translate-y-1/2 h-6 px-2"
              onClick={() => setSearchQuery('')}
            >
              {t.common.clear}
            </Button>
          )}
        </div>

        {/* Filters */}
        <div className="space-y-4 mb-6">
          {/* Provider Filter */}
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground mr-2">{t.cli.provider}:</span>
            {providers.map((provider) => (
              <Button
                key={provider}
                variant={providerFilter === provider ? 'default' : 'outline'}
                size="sm"
                onClick={() => setProviderFilter(provider)}
                className={providerFilter === provider ? '' : provider !== 'All' ? providerColors[provider] : ''}
              >
                {provider === 'All' ? t.cli.allProviders : provider}
              </Button>
            ))}
          </div>

          {/* Category Filter */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-muted-foreground mr-2 ml-6">{t.cli.category}:</span>
            {categories.map((cat) => (
              <Button
                key={cat.id}
                variant={categoryFilter === cat.id ? 'default' : 'outline'}
                size="sm"
                onClick={() => setCategoryFilter(cat.id)}
              >
                {cat.label}
              </Button>
            ))}
          </div>
        </div>

        {/* Results count */}
        <div className="mb-4 text-sm text-muted-foreground">
          {filteredCommands.length} {t.cli.commandsFound}
        </div>

        {/* Commands Grid */}
        {filteredCommands.length > 0 ? (
          <div className="space-y-8">
            {Object.entries(groupedCommands).map(([category, commands]) => (
              <div key={category}>
                <h2 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
                  <Badge className={categoryColors[category]}>{categoryLabels[category]}</Badge>
                  <span className="text-sm text-muted-foreground font-normal">({commands.length})</span>
                </h2>
                <div className="grid gap-4 md:grid-cols-2">
                  {commands.map((cmd) => (
                    <CommandCard
                      key={cmd.id}
                      command={cmd}
                      onCopy={copyToClipboard}
                      isCopied={copiedId === cmd.id}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <Terminal className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>{t.cli.noResults}</p>
          </div>
        )}
      </div>
    </AppLayout>
  );
}

interface CommandCardProps {
  command: CLICommand;
  onCopy: (command: string, id: string) => void;
  isCopied: boolean;
}

function CommandCard({ command, onCopy, isCopied }: CommandCardProps) {
  return (
    <Card className="group hover:border-primary/50 transition-colors">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1">
            <CardTitle className="text-base">{command.title}</CardTitle>
            <CardDescription className="mt-1">{command.description}</CardDescription>
          </div>
          <Badge variant="outline" className={providerColors[command.provider]}>
            {command.provider}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="relative">
          <pre className="bg-muted/50 rounded-lg p-3 text-xs overflow-x-auto font-mono text-foreground/90 pr-10">
            <code>{command.command}</code>
          </pre>
          <Button
            variant="ghost"
            size="icon"
            className="absolute top-2 right-2 h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
            onClick={() => onCopy(command.command, command.id)}
          >
            {isCopied ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </Button>
        </div>
        
        {command.notes && (
          <p className="text-xs text-amber-600 dark:text-amber-400 bg-amber-500/10 rounded px-2 py-1">
            💡 {command.notes}
          </p>
        )}
        
        <div className="flex flex-wrap gap-1">
          {command.tags.map((tag) => (
            <Badge key={tag} variant="secondary" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
