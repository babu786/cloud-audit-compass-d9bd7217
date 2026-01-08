export const en = {
  // Common
  common: {
    cancel: 'Cancel',
    save: 'Save',
    delete: 'Delete',
    edit: 'Edit',
    add: 'Add',
    search: 'Search',
    filters: 'Filters',
    resetFilters: 'Reset filters',
    showing: 'Showing',
    of: 'of',
    controls: 'controls',
    noResults: 'No results found',
    loading: 'Loading...',
    confirm: 'Confirm',
    yes: 'Yes',
    no: 'No',
    clear: 'Clear',
  },

  // Navigation
  nav: {
    auditControls: 'Audit Controls',
    guidedMode: 'Guided Mode',
    awareness: 'Awareness',
    faq: 'FAQ',
    cliCommands: 'CLI Commands',
    glossary: 'Glossary',
    cloudSecurity: 'Cloud Security',
    auditGuidancePortal: 'Audit Guidance Portal',
  },

  // Index page
  index: {
    title: 'Cloud Security Audit Controls',
    subtitle: 'Step-by-step guidance for auditing cloud infrastructure security. Select your cloud providers, frameworks, and categories to filter relevant controls.',
    searchPlaceholder: 'Search by ID, title, or description...',
    startGuidedAudit: 'Start Guided Audit',
    severity: 'Severity',
    clearAllFilters: 'Clear all filters',
    noControlsMatch: 'No controls match your filters.',
  },

  // Guided Audit page
  guided: {
    title: 'Guided Audit Mode',
    subtitle: 'Focus on one control at a time. Select your audit scope to begin.',
    controlsSelected: 'controls selected',
    startGuidedAudit: 'Start Guided Audit',
    backToControls: '← Back to all controls',
    changeScope: 'Change scope',
    previous: 'Previous',
    next: 'Next',
    exitToControls: 'Exit to Controls',
    noControlsMatch: 'No controls match your selection.',
    updateSelection: 'Update Selection',
    whatToCheck: 'What to Check',
    whyItMatters: 'Why It Matters',
    stepByStep: 'Step-by-Step Instructions',
    cliCommand: 'CLI Command',
    expectedConfig: 'Expected Secure Configuration',
    commonMisconfigs: 'Common Misconfigurations',
    hardeningHint: 'Hardening Hint',
  },

  // Awareness page
  awareness: {
    title: 'Security Awareness & Knowledge',
    subtitle: 'Stay updated with the latest cloud security insights, common misconfigurations, and best practices for effective auditing.',
    allArticles: 'All Articles',
    weeklyAwareness: 'Weekly Awareness',
    misconfigurations: 'Misconfigurations',
    bestPractices: 'Best Practices',
    auditTips: 'Audit Tips',
    noArticles: 'No articles in this category yet.',
    adminLogin: 'Admin Login',
    logout: 'Logout',
    addArticle: 'Add Article',
    editArticle: 'Edit Article',
    deleteArticle: 'Delete Article',
    confirmDelete: 'Are you sure you want to delete this article?',
    deleteWarning: 'This action cannot be undone.',
  },

  // Add/Edit Article Modal
  articleForm: {
    addTitle: 'Add Awareness Article',
    editTitle: 'Edit Awareness Article',
    title: 'Title',
    titlePlaceholder: 'Article title...',
    category: 'Category',
    selectCategory: 'Select category',
    date: 'Date',
    image: 'Article Image (optional)',
    clickToUpload: 'Click to upload image',
    summary: 'Summary',
    summaryPlaceholder: 'Brief summary of the article...',
    content: 'Content',
    contentPlaceholder: 'Full article content...',
  },

  // Admin Login Modal
  adminLogin: {
    title: 'Admin Login',
    email: 'Email',
    emailPlaceholder: 'admin@example.com',
    password: 'Password',
    passwordPlaceholder: 'Enter password',
    loginButton: 'Login',
    invalidCredentials: 'Invalid email or password',
  },

  // Filter labels
  filters: {
    cloudProvider: 'Cloud Provider',
    framework: 'Framework',
    category: 'Category',
    severity: 'Severity',
  },

  // Cloud Providers
  providers: {
    aws: 'Amazon Web Services',
    azure: 'Microsoft Azure',
    gcp: 'Google Cloud Platform',
  },

  // Frameworks
  frameworks: {
    cis: 'CIS Benchmark',
    iso: 'ISO 27001 Mapping',
    internal: 'Internal Baseline',
  },

  // Categories
  categories: {
    iam: 'Identity & Access Management',
    network: 'Network Security',
    logging: 'Logging & Monitoring',
    storage: 'Storage Security',
    compute: 'Compute Security',
    encryption: 'Encryption & Key Management',
  },

  // Theme
  theme: {
    light: 'Light',
    dark: 'Dark',
    system: 'System',
  },

  // Language
  language: {
    english: 'English',
    hindi: 'हिंदी',
    selectLanguage: 'Select Language',
  },

  // FAQ
  faq: {
    title: 'Frequently Asked Questions',
    subtitle: 'Common questions, misconfiguration guidance, cloud quirks, and auditor discussion points.',
    searchPlaceholder: 'Search FAQ...',
    categories: {
      all: 'All Questions',
      common: 'Common Questions',
      misconfig: 'What If I Find...?',
      quirks: 'Cloud Quirks',
      interview: 'Interview Points',
    },
    noResults: 'No matching questions found.',
    relatedControls: 'Related Controls',
    expandAll: 'Expand All',
    collapseAll: 'Collapse All',
    questionsFound: 'questions found',
  },

  // CLI Commands
  cli: {
    title: 'CLI Command Library',
    subtitle: 'Ready-to-use CLI commands for cloud security auditing. Click to copy any command.',
    searchPlaceholder: 'Search commands...',
    allProviders: 'All Providers',
    allCategories: 'All Categories',
    provider: 'Provider',
    category: 'Category',
    commandsFound: 'commands found',
    noResults: 'No matching commands found.',
    copied: 'Command copied to clipboard!',
    copyFailed: 'Failed to copy command',
  },

  // Glossary
  glossary: {
    title: 'Security Glossary',
    subtitle: 'Cloud security terms, acronyms, and definitions with cross-references to controls and FAQ.',
    searchPlaceholder: 'Search terms, acronyms, or definitions...',
    categories: {
      all: 'All Terms',
      identity: 'Identity & Access',
      network: 'Network Security',
      storage: 'Storage & Data',
      compute: 'Compute & Containers',
      compliance: 'Compliance & Frameworks',
      general: 'General Security',
    },
    termsFound: 'terms found',
    noResults: 'No matching terms found.',
    relatedTerms: 'Related Terms',
    relatedControls: 'Related Controls',
    relatedFAQs: 'Related FAQs',
    usedIn: 'Used in',
    alsoKnownAs: 'Also known as',
    acronymFor: 'Acronym for',
    jumpToLetter: 'Jump to',
  },
};

export type Translations = typeof en;
