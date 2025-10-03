import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Search, Users, Worm, AlertTriangle, Activity, ExternalLink } from "lucide-react";
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
            
            <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
              Valide continuamente sua postura de segurança com verificações automatizadas 
              de superfície de ataque, higiene de Active Directory e eficácia de EDR/AV.
            </p>
            
            <p className="text-sm text-muted-foreground/80 mb-12">
              Uma solução profissional da <span className="font-semibold text-primary">GSecDo</span> para empresas que levam cibersegurança a sério
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

            {/* AD Security */}
            <Card className="bg-card border-border">
              <CardHeader>
                <div className="w-12 h-12 bg-accent/20 rounded-lg flex items-center justify-center mb-4">
                  <Users className="w-6 h-6 text-accent" />
                </div>
                <CardTitle className="text-foreground">AD Security</CardTitle>
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

      {/* About Company Section */}
      <div className="py-16 bg-card/30">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-foreground mb-4">
              Sobre a GSecDo
            </h2>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
              Especialistas em cibersegurança desenvolvendo soluções inovadoras 
              para proteger empresas contra ameaças digitais
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl font-semibold text-foreground mb-4">
                Nossa Missão
              </h3>
              <p className="text-muted-foreground mb-6">
                Fornecemos ferramentas de classe empresarial para validação contínua 
                de segurança, permitindo que organizações identifiquem e mitiguem 
                riscos antes que se tornem incidentes.
              </p>
              <div className="flex flex-col sm:flex-row gap-4">
                <Button 
                  variant="outline" 
                  className="w-full sm:w-auto"
                  onClick={() => window.open('https://www.samureye.com.br', '_blank', 'noopener,noreferrer')}
                  data-testid="link-samureye-site"
                >
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Site do Produto
                </Button>
                <Button 
                  variant="outline" 
                  className="w-full sm:w-auto"
                  onClick={() => window.open('https://www.gsecdo.com.br', '_blank', 'noopener,noreferrer')}
                  data-testid="link-gsecdo-site"
                >
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Outras Soluções
                </Button>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">24/7</div>
                <div className="text-sm text-muted-foreground">Monitoramento</div>
              </Card>
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">100%</div>
                <div className="text-sm text-muted-foreground">Automatizado</div>
              </Card>
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">{"< 1min"}</div>
                <div className="text-sm text-muted-foreground">Detecção</div>
              </Card>
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">Zero</div>
                <div className="text-sm text-muted-foreground">Falso Positivo</div>
              </Card>
            </div>
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

      {/* Footer with Trademark */}
      <footer className="bg-card/50 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
            <div className="text-center md:text-left">
              <p className="text-sm text-muted-foreground">
                © 2024 GSecDo. Todos os direitos reservados.
              </p>
              <p className="text-xs text-muted-foreground/80 mt-1">
                SamurEye® é uma marca registrada da GSecDo Soluções em Cibersegurança Ltda.
              </p>
            </div>
            
            <div className="flex space-x-6">
              <button
                onClick={() => window.open('https://www.samureye.com.br', '_blank', 'noopener,noreferrer')}
                className="text-sm text-muted-foreground hover:text-primary transition-colors"
                data-testid="footer-link-samureye"
              >
                www.samureye.com.br
              </button>
              <button
                onClick={() => window.open('https://www.gsecdo.com.br', '_blank', 'noopener,noreferrer')}
                className="text-sm text-muted-foreground hover:text-primary transition-colors"
                data-testid="footer-link-gsecdo"
              >
                www.gsecdo.com.br
              </button>
            </div>
          </div>
          
          <div className="mt-6 pt-6 border-t border-border/50 text-center">
            <p className="text-xs text-muted-foreground/60">
              Plataforma de Validação de Exposição Adversarial • Segurança Empresarial • Compliance & Auditoria
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
