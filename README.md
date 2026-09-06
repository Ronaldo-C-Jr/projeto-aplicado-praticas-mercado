# Projeto Aplicado: Práticas de Mercado — Aplicação Web Segura com Esteira CI/CD

**Aluno:** Ronaldo dos Santos Costa Junior
**Disciplina:** Projeto Aplicado: Práticas de Mercado
**Professor:** Ziraldo Aurélio Cardoso de Oliveira
**Curso:** Pós-Graduação *Lato Sensu* — Segurança da Informação e Análise Forense — UNCISAL

---

## 1. Visão Geral

Este repositório documenta a implementação, de ponta a ponta, de uma aplicação web segura publicada em nuvem pública, aplicando os princípios de *Secure by Design* e *Secure by Default*. O projeto integra três eixos por meio de uma esteira de automação (CI/CD):

- **Eixo 1 — Infraestrutura:** servidor em nuvem (Google Cloud, *free tier*), Debian 13, Nginx, HTTPS e *hardening* de segurança.
- **Eixo 2 — Repositório:** versionamento público no GitHub com prevenção de vazamento de credenciais.
- **Eixo 3 — Aplicação:** protótipo web (login, página interna, logout) desenvolvido com auxílio de IA e mitigando categorias da OWASP Top 10:2025.
- **CI/CD:** deploy automático do GitHub para o servidor a cada `git push origin main`.

### Endereços de acesso

| Recurso | Endereço |
|---|---|
| Aplicação (IP público) | `https://35.239.146.150` |
| Aplicação (nome que resolve para o mesmo IP) | `https://35.239.146.150.sslip.io` |
| Repositório | `https://github.com/Ronaldo-C-Jr/projeto-aplicado-praticas-mercado` |

### Credenciais de teste (demonstração)

- **Usuário:** `admin`
- **Senha:** `UncisalPQC2026`

---

## 2. Eixo 1 — Infraestrutura (Cloud Free Tier)

### 2.1 Hospedagem

| Item | Configuração |
|---|---|
| Provedor | Google Cloud Platform — *Always Free* |
| Instância | `e2-micro` (região `us-central1`, Iowa) |
| Sistema operacional | Debian GNU/Linux 13 (trixie) |
| Servidor web | Nginx |
| IP público | `35.239.146.150` (estático/reservado) |
| Biblioteca criptográfica | OpenSSL 3.5.7 (suporte nativo a PQC) |

Todas as etapas de criação e configuração da instância foram executadas pelo aluno diretamente no console do provedor.

### 2.2 Segurança do acesso (metas mínimas)

- **Acesso SSH por chave, senha desabilitada.** A autenticação por senha foi desativada em `/etc/ssh/sshd_config.d/99-hardening.conf` (`PasswordAuthentication no`), mantendo apenas autenticação por chave pública.
- **Firewall com *least privilege*.** Regra de firewall do GCP liberando apenas as portas **80** e **443** para a internet (`0.0.0.0/0`), associadas à instância por *network tag*. A porta 22 (gerência) permanece restrita e protegida pelo Fail2Ban.
- **Fail2Ban na porta 22.** Configurado em `/etc/fail2ban/jail.local` com **tolerância de 4 tentativas** (`maxretry = 4`) e **banimento de 24 horas** (`bantime = 86400`), janela de detecção de 10 minutos e *backend* `systemd`. O serviço já registrou e baniu automaticamente tentativas de força bruta reais durante a operação.

### 2.3 Criptografia e HTTPS

- **Certbot 5.8.0** (instalado em ambiente isolado para atender à exigência de versão ≥ 5.4).
- **Certificado para o IP público** emitido diretamente pela Let's Encrypt (perfil `shortlived`, obrigatório para certificados de endereço IP), salvo em `/etc/letsencrypt/live/35.239.146.150/`.
- **Renovação automática** por *timer* do systemd (`certbot-renew.timer`, execução duas vezes ao dia), com *deploy-hook* que recarrega o Nginx após cada renovação. Simulação de renovação (`--dry-run`) validada com sucesso.
- **Redirecionamento automático HTTP → HTTPS** configurado no Nginx (bloco da porta 80 com `return 301 https://...`).
- **Hardening TLS** em `/etc/nginx/snippets/ssl-hardening.conf`: TLS 1.2 e 1.3 apenas, HSTS (`max-age=63072000`), e grupos de troca de chave com **criptografia pós-quântica** (`X25519MLKEM768`).

### 2.4 Evidência — Qualys SSL Labs

Resultado do teste: **Nota A+**, com **PQC (Post-Quantum Cryptography) key exchange: Supported** (`X25519MLKEM768`), TLS 1.3 habilitado e HSTS de longa duração.

Evidência anexada em [`docs/ssllabs-resultado.pdf`](docs/ssllabs-resultado.pdf).

> **Nota metodológica (transparência):** ver a seção 7.

---

## 3. Eixo 2 — Repositório (Versionamento Seguro)

- **Plataforma:** GitHub, repositório **público**.
- **Autenticação das operações:** *commit* e *push* autenticados por token (via Git Credential Manager), não por senha. Recomenda-se manter a Autenticação em Duas Etapas (2FA) ativa na conta.
- **Prevenção de vazamento (`.gitignore`):** o repositório bloqueia o versionamento de arquivos sensíveis — `.env`, chaves privadas de SSH (`*.pem`, `*.key`, `id_ed25519`, `*_ed25519`), credenciais de nuvem (`service-account*.json`, `credentials.json`), bancos locais (`*.sqlite`, `*.db`) e demais segredos.
- **Nenhuma credencial real** está exposta no repositório. A chave privada usada pelo CI/CD reside apenas no servidor e no cofre de *Secrets* do GitHub — nunca no código.

---

## 4. Eixo 3 — Aplicação Web (Desenvolvimento com IA)

### 4.1 Tecnologia e estrutura

- **Pilha:** HTML5, CSS3 e JavaScript puro (*Vanilla JS*), sem *frameworks*, sem *backend* e sem banco de dados.
- **Desenvolvimento assistido por IA:** código escrito e auditado com auxílio de IA no IDE **Google Antigravity**. A interação incluiu a geração inicial orientada por requisitos de segurança e uma etapa de **auditoria/refatoração** (correção de rótulo de categoria OWASP e remoção de credenciais expostas na tela de login).

| Arquivo | Função |
|---|---|
| `index.html` | Tela de login |
| `dashboard.html` | Página interna protegida (acessível apenas autenticado) |
| `app.js` | Lógica de segurança, autenticação, sessão e sanitização |
| `style.css` | Estilos (100% locais, sem recursos externos) |

### 4.2 Mitigações OWASP Top 10:2025

Em atendimento ao requisito de mitigar, no mínimo, três categorias, foram implementadas as seguintes:

| Categoria (OWASP Top 10:2025) | Onde no código | Como é prevenida |
|---|---|---|
| **A07 — Authentication Failures** | `app.js` — `computeSHA256()`, `generateSecureToken()`, `createSession()` / `hasActiveSession()` / `terminateSession()`, `initDashboardPage()`, `recordFailedAttempt()` / `checkLockoutStatus()` | Senha nunca armazenada em texto puro (comparação por hash SHA-256 via Web Crypto API); token de sessão gerado por CSPRNG (`crypto.randomUUID`); página interna protegida por verificação de sessão no carregamento, com redirecionamento ao login se ausente; logout que purga a sessão; bloqueio temporário após 4 tentativas malsucedidas (mitigação de força bruta). |
| **A05 — Injection** | `app.js` — `sanitizeInput()`, `displaySafeAlert()` | Sanitização/escape de caracteres de marcação (`< > " ' &`) nas entradas; escrita no DOM exclusivamente via `textContent` (nunca `innerHTML`); ausência total de `eval` ou execução dinâmica de código, mitigando XSS. |
| **A02 — Security Misconfiguration** | `index.html` e `dashboard.html` (meta CSP); `/etc/nginx/snippets/ssl-hardening.conf` (servidor) | *Content-Security-Policy* restritiva declarada por `<meta>` (`default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`); nenhuma dependência ou requisição a fontes externas; no servidor, HSTS e restrição de protocolos/cifras TLS. |

**Mitigação adicional (bônus):** **A04 — Cryptographic Failures** é mitigada pela camada de transporte do Eixo 1 — todo o tráfego trafega sob TLS 1.3 com HSTS, protegendo os dados em trânsito.

---

## 5. CI/CD — Integração e Entrega Contínuas

Fluxo automatizado **Antigravity → GitHub → Nuvem**, conforme exigido.

- **Ferramenta:** GitHub Actions.
- **Workflow:** [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml).
- **Gatilho:** todo `git push` na branch `main`.
- **Ação:** o pipeline carrega a chave SSH do cofre, conecta-se ao servidor e sincroniza os arquivos do site (via `rsync`) para `/var/www/uncisal` (diretório servido pelo Nginx em produção).
- **Gestão segura de credenciais (GitHub Secrets):**

| Secret | Conteúdo |
|---|---|
| `SSH_PRIVATE_KEY` | Chave SSH privada **dedicada** ao deploy (separada da chave pessoal do aluno) |
| `SERVER_HOST` | Endereço do servidor |
| `SERVER_USER` | Usuário de acesso ao servidor |

Nenhuma credencial fica exposta no arquivo de *workflow* — todas são referenciadas a partir do cofre de *Secrets*.

---

## 6. Checklist Final de Entrega

- [x] Aplicação web no ar e acessível por IP público (Eixo 1)
- [x] Nginx com HTTPS (Certbot/Let's Encrypt) e redirecionamento automático HTTP → HTTPS (Eixo 1)
- [x] Qualys SSL Labs: **Nota A (obtido A+)** com PQC ativado (Eixo 1) — ver seção 7
- [x] Acesso por chave SSH e Fail2Ban na porta 22 (4 erros / 24 h) (Eixo 1)
- [x] Código versionado em repositório público no GitHub, conta configurada (Eixo 2)
- [x] `.gitignore` configurado, sem chaves/senhas expostas (Eixo 2)
- [x] Login, página interna e logout, desenvolvidos com auxílio de IA via Antigravity (Eixo 3)
- [x] README documenta as 3 categorias OWASP mitigadas e onde estão no código (Eixo 3)
- [x] Fluxo de implantação automatizado com CI/CD via GitHub Actions

---

## 7. Considerações Técnicas e de Transparência

Em coerência com a postura de segurança que o projeto busca demonstrar, registram-se abertamente as seguintes decisões:

**7.1 Teste do SSL Labs e o requisito de "somente IP".**
O teste público do Qualys SSL Labs (SSL Server Test) **não avalia endereços de IP** — ao informar um IP, a ferramenta redireciona para o produto *Qualys CertView*. Há, portanto, uma tensão entre os requisitos do escopo ("acesso apenas por IP público" e "Nota A no SSL Labs"). Para atender a ambos sem adquirir um domínio:

- Foi utilizado o serviço gratuito **sslip.io**, que fornece o nome `35.239.146.150.sslip.io` — este resolve exatamente para o IP público `35.239.146.150`. Nenhum domínio foi adquirido.
- A configuração TLS avaliada pelo SSL Labs sobre esse nome é **idêntica** à servida no IP público (mesmo Nginx, mesmos protocolos, mesmas cifras, mesmo grupo PQC).
- Adicionalmente, **um certificado da Let's Encrypt foi emitido diretamente para o IP público**, atendendo à letra do requisito de certificado para IP.

Dessa forma, o projeto satisfaz simultaneamente o acesso por IP (com certificado de IP) e a comprovação de Nota A + PQC no SSL Labs.

**7.2 Natureza da autenticação (aplicação sem backend).**
Como o escopo permite solução exclusivamente *front-end*, a autenticação é uma **simulação client-side**: a lógica e o hash da credencial residem no `app.js`, que por natureza é público. Num ambiente de produção real, a validação de credenciais e o controle de sessão ocorreriam no servidor. As mitigações OWASP implementadas são reais no código; a ressalva refere-se apenas ao modelo de execução sem servidor de autenticação.

**7.3 Exibição do token de sessão.**
A página interna exibe o token de sessão apenas para fins didáticos (evidenciar a geração criptográfica). Em produção, tokens de sessão não devem ser exibidos na interface.

---

## 8. Estrutura do Repositório

```
projeto-aplicado-praticas-mercado/
├── index.html
├── dashboard.html
├── app.js
├── style.css
├── .gitignore
├── README.md
├── .github/
│   └── workflows/
│       └── deploy.yml
└── docs/
    └── ssllabs-resultado.pdf
```
