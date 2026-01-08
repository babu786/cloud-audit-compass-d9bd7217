import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { ThemeProvider } from "next-themes";
import { LanguageProvider } from "@/i18n/LanguageContext";
import { OfflineIndicator } from "@/components/pwa/OfflineIndicator";
import { InstallPrompt } from "@/components/pwa/InstallPrompt";
import { PWAUpdatePrompt } from "@/components/pwa/PWAUpdatePrompt";
import { FloatingActions } from "@/components/ui/FloatingActions";
import Index from "./pages/Index";
import GuidedAudit from "./pages/GuidedAudit";
import Awareness from "./pages/Awareness";
import FAQ from "./pages/FAQ";
import CLICommands from "./pages/CLICommands";
import Glossary from "./pages/Glossary";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

function AnimatedRoutes() {
  const location = useLocation();
  
  return (
    <div key={location.pathname} className="animate-page-enter">
      <Routes location={location}>
        <Route path="/" element={<Index />} />
        <Route path="/guided" element={<GuidedAudit />} />
        <Route path="/awareness" element={<Awareness />} />
        <Route path="/faq" element={<FAQ />} />
        <Route path="/cli" element={<CLICommands />} />
        <Route path="/glossary" element={<Glossary />} />
        {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </div>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <LanguageProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <OfflineIndicator />
          <InstallPrompt />
          <PWAUpdatePrompt />
          <FloatingActions />
          <BrowserRouter>
            <AnimatedRoutes />
          </BrowserRouter>
        </TooltipProvider>
      </LanguageProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
