import { useEffect } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { ThemeProvider } from "next-themes";
import { LanguageProvider } from "@/i18n/LanguageContext";
import { AdminAuthProvider } from "@/contexts/AdminAuthContext";
import { FirebaseAuthProvider } from "@/contexts/FirebaseAuthContext";
import { OfflineIndicator } from "@/components/pwa/OfflineIndicator";
import { InstallPrompt } from "@/components/pwa/InstallPrompt";
import { PWAUpdatePrompt } from "@/components/pwa/PWAUpdatePrompt";
import { FloatingActions } from "@/components/ui/FloatingActions";
import { KeyboardShortcutsModal } from "@/components/ui/KeyboardShortcutsModal";

// Scroll to top on route change
function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return null;
}
import Landing from "./pages/Landing";
import Index from "./pages/Index";
import GuidedAudit from "./pages/GuidedAudit";
import Awareness from "./pages/Awareness";
import FAQ from "./pages/FAQ";
import CLICommands from "./pages/CLICommands";
import Glossary from "./pages/Glossary";
import ImportControls from "./pages/ImportControls";
import AdminDashboard from "./pages/AdminDashboard";
import Profile from "./pages/Profile";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import ForgotPassword from "./pages/ForgotPassword";
import VerifyEmail from "./pages/VerifyEmail";
import NotFound from "./pages/NotFound";
import Courses from "./pages/Courses";
import CourseDetail from "./pages/CourseDetail";
import LessonView from "./pages/LessonView";
import QuizView from "./pages/QuizView";
import MyLearning from "./pages/MyLearning";
import Certificate from "./pages/Certificate";
import ProtectedRoute from "./components/auth/ProtectedRoute";

const queryClient = new QueryClient();

function AnimatedRoutes() {
  const location = useLocation();
  
  return (
    <div key={location.pathname} className="animate-page-enter">
      <Routes location={location}>
        <Route path="/" element={<Landing />} />
        <Route path="/audit" element={<Index />} />
        <Route path="/guided" element={<GuidedAudit />} />
        <Route path="/cli" element={<CLICommands />} />
        <Route path="/awareness" element={<Awareness />} />
        <Route path="/faq" element={<FAQ />} />
        <Route path="/glossary" element={<Glossary />} />
        <Route path="/import" element={<ProtectedRoute><ImportControls /></ProtectedRoute>} />
        <Route path="/admin" element={<ProtectedRoute><AdminDashboard /></ProtectedRoute>} />
        <Route path="/profile" element={<ProtectedRoute><Profile /></ProtectedRoute>} />
        <Route path="/courses" element={<Courses />} />
        <Route path="/courses/:id" element={<ProtectedRoute><CourseDetail /></ProtectedRoute>} />
        <Route path="/courses/:courseId/lesson/:lessonId" element={<ProtectedRoute><LessonView /></ProtectedRoute>} />
        <Route path="/courses/:courseId/quiz" element={<ProtectedRoute><QuizView /></ProtectedRoute>} />
        <Route path="/my-learning" element={<ProtectedRoute><MyLearning /></ProtectedRoute>} />
        <Route path="/certificate/:id" element={<ProtectedRoute><Certificate /></ProtectedRoute>} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/verify-email" element={<VerifyEmail />} />
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
        <AdminAuthProvider>
          <BrowserRouter>
            <ScrollToTop />
            <FirebaseAuthProvider>
              <TooltipProvider>
                <Toaster />
                <Sonner />
                <OfflineIndicator />
                <InstallPrompt />
                <PWAUpdatePrompt />
                <FloatingActions />
                <KeyboardShortcutsModal />
                <AnimatedRoutes />
              </TooltipProvider>
            </FirebaseAuthProvider>
          </BrowserRouter>
        </AdminAuthProvider>
      </LanguageProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
