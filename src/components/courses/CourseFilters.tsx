import { Filter } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useLanguage } from '@/i18n/LanguageContext';

interface CourseFiltersProps {
  category: string;
  difficulty: string;
  onCategoryChange: (value: string) => void;
  onDifficultyChange: (value: string) => void;
  onReset: () => void;
}

export function CourseFilters({
  category,
  difficulty,
  onCategoryChange,
  onDifficultyChange,
  onReset,
}: CourseFiltersProps) {
  const { t } = useLanguage();

  const categories = [
    { value: 'all', label: t.courses?.allCategories || 'All Categories' },
    { value: 'General', label: 'General' },
    { value: 'AWS', label: 'AWS' },
    { value: 'Azure', label: 'Azure' },
    { value: 'GCP', label: 'GCP' },
  ];

  const difficulties = [
    { value: 'all', label: t.courses?.allLevels || 'All Levels' },
    { value: 'Beginner', label: t.courses?.beginner || 'Beginner' },
    { value: 'Intermediate', label: t.courses?.intermediate || 'Intermediate' },
    { value: 'Advanced', label: t.courses?.advanced || 'Advanced' },
  ];

  const hasFilters = category !== 'all' || difficulty !== 'all';

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Filter className="h-4 w-4" />
        <span>{t.courses?.filters || 'Filters'}:</span>
      </div>

      <Select value={category} onValueChange={onCategoryChange}>
        <SelectTrigger className="w-[160px]">
          <SelectValue placeholder={t.courses?.category || 'Category'} />
        </SelectTrigger>
        <SelectContent>
          {categories.map((cat) => (
            <SelectItem key={cat.value} value={cat.value}>
              {cat.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={difficulty} onValueChange={onDifficultyChange}>
        <SelectTrigger className="w-[160px]">
          <SelectValue placeholder={t.courses?.difficulty || 'Difficulty'} />
        </SelectTrigger>
        <SelectContent>
          {difficulties.map((diff) => (
            <SelectItem key={diff.value} value={diff.value}>
              {diff.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={onReset}>
          {t.courses?.clearFilters || 'Clear Filters'}
        </Button>
      )}
    </div>
  );
}
