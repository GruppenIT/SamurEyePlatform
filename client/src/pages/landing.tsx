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
              Uma solução profissional da <span className="font-semibold text-primary">Gruppen</span> (Gruppen Serviços de Informática Ltda) para empresas que levam cibersegurança a sério
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
              Sobre a Gruppen
            </h2>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
              Empresa gaúcha de tecnologia e segurança da informação fundada em 2005
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl font-semibold text-foreground mb-4">
                Nossa História
              </h3>
              <p className="text-muted-foreground mb-6">
                Somos uma empresa gaúcha de tecnologia e segurança da informação fundada em 2005. 
                Desde então, crescemos constantemente junto do mercado de tecnologia, com foco no 
                fornecimento de soluções sustentáveis de TI e sempre à frente das novidades e 
                necessidades do setor. A modificação no mercado e no mundo é o que nos move e 
                mantém até hoje nessa jornada.
              </p>
              
              <div className="bg-card/50 border border-border rounded-lg p-6 mb-6">
                <p className="text-muted-foreground italic mb-4">
                  "É o nosso trabalho estarmos atualizados e à frente de novidades. O jeito que 
                  encaramos e nos adaptamos à constante modificação da tecnologia no mundo através 
                  da busca de ferramentas inovadoras que estão ligadas aos nossos princípios e a 
                  transmissão dessas inovações para nossos clientes, é o que expande o sucesso da 
                  Gruppen it".
                </p>
                <p className="text-sm text-primary font-semibold">
                  Felipe Jacobs
                </p>
                <p className="text-xs text-muted-foreground">
                  CEO da Gruppen it
                </p>
              </div>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <Button 
                  variant="outline" 
                  className="w-full sm:w-auto"
                  onClick={() => window.open('https://www.gruppen.com.br', '_blank', 'noopener,noreferrer')}
                  data-testid="link-gruppen-site"
                >
                  <ExternalLink className="w-4 h-4 mr-2" />
                  www.gruppen.com.br
                </Button>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">2005</div>
                <div className="text-sm text-muted-foreground">Fundação</div>
              </Card>
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">19+</div>
                <div className="text-sm text-muted-foreground">Anos de Experiência</div>
              </Card>
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">100%</div>
                <div className="text-sm text-muted-foreground">Brasileira</div>
              </Card>
              <Card className="text-center p-6">
                <div className="text-3xl font-bold text-primary mb-2">RS</div>
                <div className="text-sm text-muted-foreground">Rio Grande do Sul</div>
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
                © 2024 Gruppen Serviços de Informática Ltda. Todos os direitos reservados.
              </p>
              <p className="text-xs text-muted-foreground/80 mt-1">
                SamurEye® é uma solução desenvolvida pela Gruppen it.
              </p>
            </div>
            
            <div className="flex space-x-6">
              <button
                onClick={() => window.open('https://www.gruppen.com.br', '_blank', 'noopener,noreferrer')}
                className="text-sm text-muted-foreground hover:text-primary transition-colors"
                data-testid="footer-link-gruppen"
              >
                www.gruppen.com.br
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
