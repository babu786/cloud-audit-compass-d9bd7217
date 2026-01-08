import { Translations } from './en';

export const hi: Translations = {
  // Common
  common: {
    cancel: 'रद्द करें',
    save: 'सहेजें',
    delete: 'हटाएं',
    edit: 'संपादित करें',
    add: 'जोड़ें',
    search: 'खोजें',
    filters: 'फ़िल्टर',
    resetFilters: 'फ़िल्टर रीसेट करें',
    showing: 'दिखा रहे हैं',
    of: 'में से',
    controls: 'नियंत्रण',
    noResults: 'कोई परिणाम नहीं मिला',
    loading: 'लोड हो रहा है...',
    confirm: 'पुष्टि करें',
    yes: 'हाँ',
    no: 'नहीं',
    clear: 'साफ़ करें',
  },

  // Navigation
  nav: {
    auditControls: 'ऑडिट नियंत्रण',
    guidedMode: 'मार्गदर्शित मोड',
    awareness: 'जागरूकता',
    faq: 'सामान्य प्रश्न',
    cliCommands: 'CLI कमांड',
    glossary: 'शब्दावली',
    cloudSecurity: 'क्लाउड सुरक्षा',
    auditGuidancePortal: 'ऑडिट मार्गदर्शन पोर्टल',
  },

  // Index page
  index: {
    title: 'क्लाउड सुरक्षा ऑडिट नियंत्रण',
    subtitle: 'क्लाउड इंफ्रास्ट्रक्चर सुरक्षा ऑडिटिंग के लिए चरण-दर-चरण मार्गदर्शन। प्रासंगिक नियंत्रणों को फ़िल्टर करने के लिए अपने क्लाउड प्रदाता, फ्रेमवर्क और श्रेणियां चुनें।',
    searchPlaceholder: 'ID, शीर्षक या विवरण से खोजें...',
    startGuidedAudit: 'मार्गदर्शित ऑडिट शुरू करें',
    severity: 'गंभीरता',
    clearAllFilters: 'सभी फ़िल्टर साफ़ करें',
    noControlsMatch: 'आपके फ़िल्टर से कोई नियंत्रण मेल नहीं खाता।',
  },

  // Guided Audit page
  guided: {
    title: 'मार्गदर्शित ऑडिट मोड',
    subtitle: 'एक समय में एक नियंत्रण पर ध्यान दें। शुरू करने के लिए अपना ऑडिट दायरा चुनें।',
    controlsSelected: 'नियंत्रण चुने गए',
    startGuidedAudit: 'मार्गदर्शित ऑडिट शुरू करें',
    backToControls: '← सभी नियंत्रणों पर वापस जाएं',
    changeScope: 'दायरा बदलें',
    previous: 'पिछला',
    next: 'अगला',
    exitToControls: 'नियंत्रणों पर लौटें',
    noControlsMatch: 'आपके चयन से कोई नियंत्रण मेल नहीं खाता।',
    updateSelection: 'चयन अपडेट करें',
    whatToCheck: 'क्या जांचें',
    whyItMatters: 'यह क्यों मायने रखता है',
    stepByStep: 'चरण-दर-चरण निर्देश',
    cliCommand: 'CLI कमांड',
    expectedConfig: 'अपेक्षित सुरक्षित कॉन्फ़िगरेशन',
    commonMisconfigs: 'सामान्य गलत कॉन्फ़िगरेशन',
    hardeningHint: 'सुरक्षा सुझाव',
  },

  // Awareness page
  awareness: {
    title: 'सुरक्षा जागरूकता और ज्ञान',
    subtitle: 'नवीनतम क्लाउड सुरक्षा अंतर्दृष्टि, सामान्य गलत कॉन्फ़िगरेशन और प्रभावी ऑडिटिंग के लिए सर्वोत्तम प्रथाओं के साथ अपडेट रहें।',
    allArticles: 'सभी लेख',
    weeklyAwareness: 'साप्ताहिक जागरूकता',
    misconfigurations: 'गलत कॉन्फ़िगरेशन',
    bestPractices: 'सर्वोत्तम प्रथाएं',
    auditTips: 'ऑडिट टिप्स',
    noArticles: 'इस श्रेणी में अभी तक कोई लेख नहीं है।',
    adminLogin: 'एडमिन लॉगिन',
    logout: 'लॉगआउट',
    addArticle: 'लेख जोड़ें',
    editArticle: 'लेख संपादित करें',
    deleteArticle: 'लेख हटाएं',
    confirmDelete: 'क्या आप वाकई इस लेख को हटाना चाहते हैं?',
    deleteWarning: 'यह क्रिया पूर्ववत नहीं की जा सकती।',
  },

  // Add/Edit Article Modal
  articleForm: {
    addTitle: 'जागरूकता लेख जोड़ें',
    editTitle: 'जागरूकता लेख संपादित करें',
    title: 'शीर्षक',
    titlePlaceholder: 'लेख का शीर्षक...',
    category: 'श्रेणी',
    selectCategory: 'श्रेणी चुनें',
    date: 'तारीख',
    image: 'लेख की छवि (वैकल्पिक)',
    clickToUpload: 'छवि अपलोड करने के लिए क्लिक करें',
    summary: 'सारांश',
    summaryPlaceholder: 'लेख का संक्षिप्त सारांश...',
    content: 'सामग्री',
    contentPlaceholder: 'पूर्ण लेख सामग्री...',
  },

  // Admin Login Modal
  adminLogin: {
    title: 'एडमिन लॉगिन',
    email: 'ईमेल',
    emailPlaceholder: 'admin@example.com',
    password: 'पासवर्ड',
    passwordPlaceholder: 'पासवर्ड दर्ज करें',
    loginButton: 'लॉगिन',
    invalidCredentials: 'अमान्य ईमेल या पासवर्ड',
  },

  // Filter labels
  filters: {
    cloudProvider: 'क्लाउड प्रदाता',
    framework: 'फ्रेमवर्क',
    category: 'श्रेणी',
    severity: 'गंभीरता',
  },

  // Cloud Providers
  providers: {
    aws: 'अमेज़न वेब सर्विसेज',
    azure: 'माइक्रोसॉफ्ट एज़्योर',
    gcp: 'गूगल क्लाउड प्लेटफॉर्म',
  },

  // Frameworks
  frameworks: {
    cis: 'CIS बेंचमार्क',
    iso: 'ISO 27001 मैपिंग',
    internal: 'आंतरिक बेसलाइन',
  },

  // Categories
  categories: {
    iam: 'पहचान और पहुंच प्रबंधन',
    network: 'नेटवर्क सुरक्षा',
    logging: 'लॉगिंग और मॉनिटरिंग',
    storage: 'स्टोरेज सुरक्षा',
    compute: 'कंप्यूट सुरक्षा',
    encryption: 'एन्क्रिप्शन और कुंजी प्रबंधन',
  },

  // Theme
  theme: {
    light: 'लाइट',
    dark: 'डार्क',
    system: 'सिस्टम',
  },

  // Language
  language: {
    english: 'English',
    hindi: 'हिंदी',
    selectLanguage: 'भाषा चुनें',
  },

  // FAQ
  faq: {
    title: 'अक्सर पूछे जाने वाले प्रश्न',
    subtitle: 'सामान्य प्रश्न, गलत कॉन्फ़िगरेशन मार्गदर्शन, क्लाउड विशेषताएं और ऑडिटर चर्चा बिंदु।',
    searchPlaceholder: 'FAQ खोजें...',
    categories: {
      all: 'सभी प्रश्न',
      common: 'सामान्य प्रश्न',
      misconfig: 'अगर मिले तो...?',
      quirks: 'क्लाउड विशेषताएं',
      interview: 'साक्षात्कार बिंदु',
    },
    noResults: 'कोई मेल खाने वाले प्रश्न नहीं मिले।',
    relatedControls: 'संबंधित नियंत्रण',
    expandAll: 'सभी खोलें',
    collapseAll: 'सभी बंद करें',
    questionsFound: 'प्रश्न मिले',
  },

  // CLI Commands
  cli: {
    title: 'CLI कमांड लाइब्रेरी',
    subtitle: 'क्लाउड सुरक्षा ऑडिटिंग के लिए तैयार CLI कमांड। कॉपी करने के लिए क्लिक करें।',
    searchPlaceholder: 'कमांड खोजें...',
    allProviders: 'सभी प्रदाता',
    allCategories: 'सभी श्रेणियां',
    provider: 'प्रदाता',
    category: 'श्रेणी',
    commandsFound: 'कमांड मिले',
    noResults: 'कोई मेल खाने वाले कमांड नहीं मिले।',
    copied: 'कमांड क्लिपबोर्ड में कॉपी हो गया!',
    copyFailed: 'कमांड कॉपी करने में विफल',
  },

  // Glossary
  glossary: {
    title: 'सुरक्षा शब्दावली',
    subtitle: 'नियंत्रण और FAQ के क्रॉस-रेफरेंस के साथ क्लाउड सुरक्षा शब्द, संक्षिप्त रूप और परिभाषाएं।',
    searchPlaceholder: 'शब्द, संक्षिप्त रूप या परिभाषाएं खोजें...',
    categories: {
      all: 'सभी शब्द',
      identity: 'पहचान और पहुंच',
      network: 'नेटवर्क सुरक्षा',
      storage: 'स्टोरेज और डेटा',
      compute: 'कंप्यूट और कंटेनर',
      compliance: 'अनुपालन और फ्रेमवर्क',
      general: 'सामान्य सुरक्षा',
    },
    termsFound: 'शब्द मिले',
    noResults: 'कोई मेल खाने वाले शब्द नहीं मिले।',
    relatedTerms: 'संबंधित शब्द',
    relatedControls: 'संबंधित नियंत्रण',
    relatedFAQs: 'संबंधित FAQ',
    usedIn: 'में उपयोग किया गया',
    alsoKnownAs: 'इसे भी कहते हैं',
    acronymFor: 'का संक्षिप्त रूप',
    jumpToLetter: 'पर जाएं',
  },
};
