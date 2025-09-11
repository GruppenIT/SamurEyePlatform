import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Search, Users, Worm, AlertTriangle, Activity } from "lucide-react";
import { useLocation } from "wouter";

export default function Landing() {
  const [, setLocation] = useLocation();

  const handleLogin = () => setLocation("/login");

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-background to-accent/5"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="pt-20 pb-16 text-center lg:pt-32">
            <div className="flex justify-center mb-8">
              <div className="w-20 h-20 bg-primary rounded-2xl flex items-center justify-center">
                <Shield className="w-10 h-10 text-primary-foreground" />
              </div>
            </div>
            
            <h1 className="text-4xl md:text-6xl font-bold text-foreground mb-6">
              SamurEye
            </h1>
            
            <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto">
              Plataforma de Validação de Exposição Adversarial
            </p>
            
            <p className="text-lg text-muted-foreground mb-12 max-w-2xl mx-auto">
              Valide continuamente sua postura de segurança com verificações automatizadas 
              de superfície de ataque, higiene de Active Directory e eficácia de EDR/AV.
            </p>
            
            <div className="flex gap-4 justify-center">
              <Button 
                size="lg" 
                className="text-lg px-8 py-4"
                onClick={handleLogin}
                data-testid="button-login"
              >
                Fazer Login
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="py-16 bg-card/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-foreground mb-4">
              Recursos Principais
            </h2>
            <p className="text-xl text-muted-foreground">
              Uma solução completa para validação contínua de segurança
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {/* Attack Surface */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center mb-4">
                  <Search className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-foreground">Attack Surface</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Mapeamento contínuo da superfície de ataque com nmap e nuclei. 
                  Identifique portas abertas, serviços expostos e vulnerabilidades conhecidas.
                </p>
              </CardContent>
            </Card>

            {/* AD Hygiene */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-accent/20 rounded-lg flex items-center justify-center mb-4">
                  <Users className="w-6 h-6 text-accent" />
                </div>
                <CardTitle className="text-foreground">Higiene AD</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Análise automatizada de Active Directory para identificar contas 
                  com senhas antigas, políticas fracas e configurações de risco.
                </p>
              </CardContent>
            </Card>

            {/* EDR/AV Testing */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-chart-5/20 rounded-lg flex items-center justify-center mb-4">
                  <Worm className="w-6 h-6 text-chart-5" />
                </div>
                <CardTitle className="text-foreground">Teste EDR/AV</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Validação da eficácia de soluções EDR e antivírus usando 
                  arquivos EICAR em ambiente controlado e seguro.
                </p>
              </CardContent>
            </Card>

            {/* Threat Intelligence */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-destructive/20 rounded-lg flex items-center justify-center mb-4">
                  <AlertTriangle className="w-6 h-6 text-destructive" />
                </div>
                <CardTitle className="text-foreground">Threat Intelligence</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Engine inteligente para correlação de achados e geração 
                  automática de ameaças com classificação de severidade.
                </p>
              </CardContent>
            </Card>

            {/* Real-time Monitoring */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-chart-4/20 rounded-lg flex items-center justify-center mb-4">
                  <Activity className="w-6 h-6 text-chart-4" />
                </div>
                <CardTitle className="text-foreground">Monitoramento</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Acompanhamento em tempo real de execuções, dashboards 
                  interativos e alertas automáticos para ameaças críticas.
                </p>
              </CardContent>
            </Card>

            {/* Security First */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center mb-4">
                  <Shield className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-foreground">Security-First</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Armazenamento criptografado de credenciais, controle de acesso 
                  baseado em funções e auditoria completa de ações.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="py-16">
        <div className="max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
          <h2 className="text-3xl font-bold text-foreground mb-4">
            Pronto para Fortalecer sua Segurança?
          </h2>
          <p className="text-xl text-muted-foreground mb-8">
            Comece a validar sua postura de segurança de forma contínua e automatizada.
          </p>
          <div className="flex gap-4 justify-center">
            <Button 
              size="lg" 
              onClick={handleLogin}
              data-testid="button-login-cta"
            >
              Fazer Login
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
