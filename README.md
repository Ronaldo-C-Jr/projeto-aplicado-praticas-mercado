# Projeto Aplicado: Práticas de Mercado e Segurança Front-End

Aplicação web front-end desenvolvida exclusivamente com **HTML, CSS e JavaScript puro (Vanilla JS)**, sem dependências externas, sem bibliotecas de terceiros e sem backend, implementando práticas de segurança defensiva baseadas no **OWASP Top 10**.

---

## 🔐 Credenciais de Teste

Para acessar o painel protegido (`dashboard.html`), utilize as credenciais abaixo na tela de login (`index.html`):

| Campo | Valor |
| :--- | :--- |
| **Usuário** | `admin` |
| **Senha** | `UncisalPQC2026` |

> **Nota de Segurança:** A senha não é armazenada em texto puro no código. O sistema valida apenas o hash criptográfico **SHA-256** calculado localmente via **Web Crypto API (`window.crypto.subtle`)**:
> `a0779707aa4f882a4ec725e5f169d8d72d5af0eb790984c9c64094feb173cc1c`

---

## 🛡️ Mitigações OWASP Implementadas

1. **[OWASP A07 - Identification and Authentication Failures]**
   - Hashing irreversível de senha com **SHA-256** (`crypto.subtle`).
   - Gerenciamento de sessão com token criptograficamente seguro (`crypto.randomUUID()`) armazenado em `sessionStorage` (destruído ao fechar a aba).
   - Verificação obrigatória de sessão ao acessar o `dashboard.html`, com redirecionamento imediato caso não haja autenticação ativa.
   - Encerramento completo de sessão no **Logout**.
   - Proteção contra ataques de força bruta (*rate limiting / lockout*): após **4 tentativas incorretas consecutivas**, novas tentativas são bloqueadas por **3 minutos**, com persistência em `localStorage` para evitar bypass por recarregamento da página.

2. **[OWASP A05 - Injection / Cross-Site Scripting (XSS)]**
   - Sanitização de todas as entradas fornecidas pelo usuário.
   - Manipulação estrita do DOM através da propriedade `textContent` e nós nativos. Proibição absoluta do uso de `innerHTML`, `outerHTML` ou `insertAdjacentHTML`.
   - Ausência total de avaliação dinâmica de código (`eval`, `new Function()`, etc.).

3. **[OWASP A02 - Security Misconfiguration]**
   - Meta tag com **Content-Security-Policy (CSP)** restritiva em todas as páginas:
     ```html
     <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self';">
     ```
   - Operação 100% local, sem chamadas a CDNs externos, fontes remotas ou bibliotecas de terceiros.

---

## 🚀 Como Executar

Abra o arquivo `index.html` em qualquer navegador web moderno:
```bash
# Exemplo via terminal ou diretamente no explorador de arquivos:
start index.html
```