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
  },

  // Navigation
  nav: {
    auditControls: 'ऑडिट नियंत्रण',
    guidedMode: 'मार्गदर्शित मोड',
    awareness: 'जागरूकता',
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
};
