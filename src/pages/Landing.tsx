import { Link } from 'react-router-dom';
import { 
  Shield, 
  Compass, 
  Terminal, 
  BookOpen, 
  Users, 
  GraduationCap, 
  Building2, 
  UserCheck,
  ArrowRight,
  CheckCircle,
  Cloud,
  Lock,
  Award,
  PlayCircle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useLanguage } from '@/i18n/LanguageContext';
import { AppLayout } from '@/components/layout/AppLayout';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';

export default function Landing() {
  const { t } = useLanguage();
  const { user } = useFirebaseAuth();

  const features = [
    {
      icon: Shield,
      title: t.landing.feature1Title,
      description: t.landing.feature1Desc,
    },
    {
      icon: Compass,
      title: t.landing.feature2Title,
      description: t.landing.feature2Desc,
    },
    {
      icon: Terminal,
      title: t.landing.feature3Title,
      description: t.landing.feature3Desc,
    },
    {
      icon: BookOpen,
      title: t.landing.feature4Title,
      description: t.landing.feature4Desc,
    },
  ];

  const audiences = [
    {
      icon: UserCheck,
      title: t.landing.auditors,
      description: t.landing.auditorsDesc,
    },
    {
      icon: Building2,
      title: t.landing.engineers,
      description: t.landing.engineersDesc,
    },
    {
      icon: Users,
      title: t.landing.compliance,
      description: t.landing.complianceDesc,
    },
    {
      icon: GraduationCap,
      title: t.landing.learners,
      description: t.landing.learnersDesc,
    },
  ];

  const freeResources = [
    { name: t.nav.awareness, href: '/awareness', icon: BookOpen },
    { name: t.nav.faq, href: '/faq', icon: CheckCircle },
    { name: t.nav.glossary, href: '/glossary', icon: Lock },
  ];

  return (
    <AppLayout>
      <div className="min-h-screen">
        {/* Hero Section */}
        <section className="relative py-20 md:py-32 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />
          <div className="container relative">
            <div className="max-w-4xl mx-auto text-center">
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary mb-6">
                <Cloud className="h-4 w-4" />
                <span className="text-sm font-medium">AWS • Azure • GCP</span>
              </div>
              <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6 bg-gradient-to-r from-foreground via-foreground to-foreground/70 bg-clip-text">
                {t.landing.heroTitle}
              </h1>
              <p className="text-lg md:text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
                {t.landing.heroSubtitle}
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Button asChild size="lg" className="min-w-[160px]">
                  <Link to="/login">
                    {t.landing.getStarted}
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
                <Button asChild variant="outline" size="lg" className="min-w-[160px]">
                  <a href="#features">
                    {t.landing.learnMore}
                  </a>
                </Button>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="py-20 bg-secondary/30">
          <div className="container">
            <div className="text-center mb-12">
              <h2 className="text-3xl md:text-4xl font-bold mb-4">{t.landing.featuresTitle}</h2>
              <p className="text-muted-foreground max-w-2xl mx-auto">{t.landing.featuresSubtitle}</p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
              {features.map((feature, index) => (
                <Card key={index} className="relative overflow-hidden group hover:shadow-lg transition-all duration-300 hover:-translate-y-1">
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                  <CardHeader>
                    <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                      <feature.icon className="h-6 w-6 text-primary" />
                    </div>
                    <CardTitle className="text-lg">{feature.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{feature.description}</CardDescription>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Training & Certification Banner - Show only to non-logged-in users */}
        {!user && (
          <section className="py-12 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-r from-primary/10 via-primary/5 to-primary/10" />
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-primary/20 via-transparent to-transparent opacity-50" />
            <div className="container relative">
              <Card className="border-primary/30 bg-gradient-to-br from-card via-card to-primary/5 shadow-xl overflow-hidden">
                <div className="absolute top-0 right-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
                <div className="absolute bottom-0 left-0 w-48 h-48 bg-primary/10 rounded-full blur-3xl translate-y-1/2 -translate-x-1/2" />
                <CardContent className="relative p-8 md:p-12">
                  <div className="flex flex-col lg:flex-row items-center gap-8">
                    <div className="flex-1 text-center lg:text-left">
                      <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/20 text-primary text-sm font-medium mb-4">
                        <Award className="h-4 w-4" />
                        <span>Training & Certification</span>
                      </div>
                      <h3 className="text-2xl md:text-3xl font-bold mb-3">
                        Get Certified in Cloud Security
                      </h3>
                      <p className="text-muted-foreground mb-6 max-w-xl">
                        Access 8+ expert-led courses covering AWS, Azure, GCP, Kubernetes security, and more. 
                        Complete interactive quizzes and earn digital certificates to showcase your skills.
                      </p>
                      <div className="flex flex-wrap items-center justify-center lg:justify-start gap-6 mb-6">
                        <div className="flex items-center gap-2 text-sm">
                          <PlayCircle className="h-5 w-5 text-primary" />
                          <span>8+ Courses</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                          <CheckCircle className="h-5 w-5 text-primary" />
                          <span>Interactive Quizzes</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                          <Award className="h-5 w-5 text-primary" />
                          <span>Digital Certificates</span>
                        </div>
                      </div>
                      <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-3">
                        <Button asChild size="lg" className="min-w-[180px]">
                          <Link to="/signup">
                            Start Learning Free
                            <ArrowRight className="ml-2 h-4 w-4" />
                          </Link>
                        </Button>
                        <Button asChild variant="outline" size="lg">
                          <Link to="/login">
                            Login to Access
                          </Link>
                        </Button>
                      </div>
                    </div>
                    <div className="hidden md:flex flex-shrink-0">
                      <div className="relative">
                        <div className="w-48 h-48 rounded-2xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center border border-primary/20">
                          <GraduationCap className="h-24 w-24 text-primary/80" />
                        </div>
                        <div className="absolute -top-3 -right-3 w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center border border-primary/30">
                          <Award className="h-6 w-6 text-primary" />
                        </div>
                        <div className="absolute -bottom-3 -left-3 w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center border border-primary/30">
                          <CheckCircle className="h-5 w-5 text-primary" />
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>
        )}


        <section className="py-20">
          <div className="container">
            <div className="text-center mb-12">
              <h2 className="text-3xl md:text-4xl font-bold mb-4">{t.landing.whoIsFor}</h2>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
              {audiences.map((audience, index) => (
                <Card key={index} className="text-center hover:shadow-lg transition-all duration-300 hover:-translate-y-1">
                  <CardHeader>
                    <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                      <audience.icon className="h-8 w-8 text-primary" />
                    </div>
                    <CardTitle className="text-lg">{audience.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{audience.description}</CardDescription>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Free Resources Section */}
        <section className="py-20 bg-secondary/30">
          <div className="container">
            <div className="text-center mb-12">
              <h2 className="text-3xl md:text-4xl font-bold mb-4">{t.landing.freeResources}</h2>
              <p className="text-muted-foreground">{t.landing.freeResourcesSubtitle}</p>
            </div>
            <div className="grid md:grid-cols-3 gap-6 max-w-3xl mx-auto">
              {freeResources.map((resource, index) => (
                <Link
                  key={index}
                  to={resource.href}
                  className="group"
                >
                  <Card className="text-center hover:shadow-lg transition-all duration-300 hover:-translate-y-1 h-full">
                    <CardHeader>
                      <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform">
                        <resource.icon className="h-6 w-6 text-primary" />
                      </div>
                      <CardTitle className="text-lg group-hover:text-primary transition-colors">
                        {resource.name}
                      </CardTitle>
                    </CardHeader>
                  </Card>
                </Link>
              ))}
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-20">
          <div className="container">
            <Card className="max-w-3xl mx-auto text-center p-8 md:p-12 bg-gradient-to-br from-primary/5 via-background to-primary/5 border-primary/20">
              <CardHeader>
                <CardTitle className="text-2xl md:text-3xl">{t.landing.ctaTitle}</CardTitle>
                <CardDescription className="text-base">{t.landing.ctaSubtitle}</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Button asChild size="lg">
                  <Link to="/signup">
                    {t.landing.signUp}
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
                <Button asChild variant="outline" size="lg">
                  <Link to="/login">
                    {t.landing.login}
                  </Link>
                </Button>
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </AppLayout>
  );
}
