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
    databricks: 'Azure Databricks',
    security: 'Security Services',
    governance: 'Governance & Compliance',
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
    showRelated: 'Show Related',
    hideRelated: 'Hide Related',
    copyDefinition: 'Copy definition',
    copied: 'Copied!',
    bookmarked: 'Bookmarked',
    addBookmark: 'Add to bookmarks',
    removeBookmark: 'Remove from bookmarks',
    bookmarkedTerms: 'Bookmarked',
    noBookmarks: 'No bookmarked terms yet.',
    pressToSearch: 'Press / to search',
  },

  // PWA
  pwa: {
    offlineReady: 'App ready for offline use',
    offlineMode: "You're offline",
    contentAvailable: 'All content is available offline',
    installApp: 'Install App',
    installTitle: 'Install Audit Portal',
    installDescription: 'Get full offline access to all security audit guidance',
    installButton: 'Install Now',
    installInstructions: 'Installation Instructions',
    iosInstructions: 'Tap Share → Add to Home Screen',
    androidInstructions: 'Tap menu → Install app',
    desktopInstructions: 'Click install icon in address bar',
    updateAvailable: 'Update available',
    updateNow: 'Update now',
    dismiss: 'Dismiss',
  },

  // Landing page
  landing: {
    heroTitle: 'Cloud Security Audit Portal',
    heroSubtitle: 'Master cloud security auditing with step-by-step guidance for AWS, Azure, and GCP. Built for security professionals and learners.',
    getStarted: 'Get Started',
    learnMore: 'Learn More',
    featuresTitle: 'Everything You Need for Cloud Security',
    featuresSubtitle: 'Comprehensive tools and resources to master cloud security auditing',
    feature1Title: 'Audit Controls Library',
    feature1Desc: '500+ security controls covering AWS, Azure, and GCP with detailed guidance.',
    feature2Title: 'Guided Audit Mode',
    feature2Desc: 'Step-by-step walkthroughs for thorough and consistent audits.',
    feature3Title: 'CLI Command Library',
    feature3Desc: 'Ready-to-use commands for security verification and testing.',
    feature4Title: 'Security Awareness',
    feature4Desc: 'Latest insights, best practices, and security knowledge.',
    whoIsFor: 'Who Is This For?',
    auditors: 'Security Auditors',
    auditorsDesc: 'Streamline your cloud security assessments with structured controls.',
    engineers: 'Cloud Engineers',
    engineersDesc: 'Implement security best practices in your cloud infrastructure.',
    compliance: 'Compliance Teams',
    complianceDesc: 'Map controls to frameworks like CIS and ISO 27001.',
    learners: 'Security Learners',
    learnersDesc: 'Learn cloud security fundamentals with practical examples.',
    freeResources: 'Free Resources',
    freeResourcesSubtitle: 'Access these resources without signing up',
    ctaTitle: 'Ready to Start Auditing?',
    ctaSubtitle: 'Join security professionals using our portal for cloud security assessments.',
    signUp: 'Sign Up Free',
    login: 'Login',
  },
};

export type Translations = typeof en;
