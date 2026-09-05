/**
 * ============================================================================
 * APLICAÇÃO WEB FRONT-END SEGURA - PRÁTICAS DE MERCADO & OWASP
 * ============================================================================
 * 
 * Este script implementa práticas defensivas alinhadas ao padrão OWASP Top 10:
 * - [OWASP A07 - Identification and Authentication Failures]
 * - [OWASP A05 - Injection / Cross-Site Scripting (XSS)]
 * - [OWASP A02 - Security Misconfiguration]
 * 
 * Desenvolvido exclusivamente com JavaScript puro (Vanilla JS), sem frameworks
 * e sem dependências externas.
 */

'use strict';

// ============================================================================
// [OWASP A07 - Identification and Authentication Failures]
// Constantes de credenciais e segurança de autenticação
// A senha NUNCA é armazenada em texto puro. Armazena-se apenas o hash SHA-256.
// Credencial de teste: admin / UncisalPQC2026
// ============================================================================
const AUTH_CONFIG = {
  EXPECTED_USER: 'admin',
  // Hash SHA-256 da senha "UncisalPQC2026"
  EXPECTED_HASH: 'a0779707aa4f882a4ec725e5f169d8d72d5af0eb790984c9c64094feb173cc1c',
  MAX_FAILED_ATTEMPTS: 4,
  LOCKOUT_DURATION_MS: 3 * 60 * 1000 // 3 minutos de bloqueio temporário
};

// Chaves de armazenamento
const STORAGE_KEYS = {
  // [OWASP A07] Sessão volátil mantida apenas durante o ciclo da aba
  SESSION_TOKEN: 'sec_auth_token',
  SESSION_USER: 'sec_auth_user',
  SESSION_TIME: 'sec_auth_time',
  // [OWASP A07] Bloqueio contra força bruta persistido entre abas/reloads
  FAILED_ATTEMPTS: 'sec_lockout_attempts',
  LOCKOUT_UNTIL: 'sec_lockout_until'
};

// ============================================================================
// [OWASP A05 - Injection / Cross-Site Scripting (XSS)]
// Sanitização de entradas do usuário e mitigação de injeção
// ============================================================================

/**
 * [OWASP A05] Sanitiza strings fornecidas pelo usuário, removendo caracteres
 * potencialmente maliciosos e tags HTML que poderiam viabilizar ataques de injeção.
 * 
 * @param {unknown} input - Dado bruto fornecido pelo usuário
 * @returns {string} String limpa e segura
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return '';
  }
  // Remove espaços extras e caracteres típicos de tags para neutralizar injeções
  return input.trim().replace(/[<>'"&]/g, (char) => {
    switch (char) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case "'": return '&#39;';
      case '"': return '&quot;';
      case '&': return '&amp;';
      default: return '';
    }
  });
}

/**
 * [OWASP A05] Exibe mensagens na interface manipulando o DOM EXCLUSIVAMENTE
 * através da propriedade `textContent`.
 * O uso de `innerHTML`, `outerHTML` ou `eval` é TERMINANTEMENTE PROIBIDO.
 * 
 * @param {HTMLElement} element - Elemento de destino
 * @param {string} message - Mensagem em texto puro
 * @param {'error' | 'warning' | 'success'} type - Tipo do alerta
 */
function displaySafeAlert(element, message, type) {
  if (!element) return;

  // Garante a remoção de classes anteriores
  element.className = 'alert';
  element.classList.add(`alert-${type}`);

  // [OWASP A05] textContent garante que qualquer HTML fornecido seja interpretado
  // estritamente como texto puro, neutralizando qualquer vetor de XSS.
  element.textContent = message;
  element.style.display = 'block';
}

/**
 * Oculta a área de alerta.
 * @param {HTMLElement} element - Elemento do alerta
 */
function hideAlert(element) {
  if (!element) return;
  element.textContent = '';
  element.style.display = 'none';
}

// ============================================================================
// [OWASP A07 - Identification and Authentication Failures]
// Criptografia, Hashing Seguro e Gerenciamento de Sessão
// ============================================================================

/**
 * [OWASP A07] Calcula o hash criptográfico SHA-256 de uma string utilizando
 * a Web Crypto API nativa do navegador (crypto.subtle).
 * 
 * A senha digitada pelo usuário nunca é exposta em logs, transitada ou guardada
 * em texto puro. Apenas a função de mão única (digest) é avaliada.
 * 
 * @param {string} text - Texto a ser submetido ao hash
 * @returns {Promise<string>} Hash hexadecimal em minúsculas
 */
async function computeSHA256(text) {
  // [OWASP A05] Não usamos eval ou bibliotecas de terceiros; usamos a API oficial do navegador
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * [OWASP A07] Gera um token de sessão criptograficamente forte utilizando
 * entropia do sistema operacional via crypto.randomUUID() ou crypto.getRandomValues().
 * 
 * @returns {string} Token aleatório e seguro
 */
function generateSecureToken() {
  if (typeof window.crypto.randomUUID === 'function') {
    return window.crypto.randomUUID();
  }
  // Fallback seguro usando CSPRNG
  const randomBytes = new Uint8Array(16);
  window.crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * [OWASP A07] Obtém o número atual de tentativas falhas de login.
 * @returns {number}
 */
function getFailedAttempts() {
  const attempts = localStorage.getItem(STORAGE_KEYS.FAILED_ATTEMPTS);
  return attempts ? parseInt(attempts, 10) || 0 : 0;
}

/**
 * [OWASP A07] Verifica se a aplicação está em período de bloqueio temporário (lockout)
 * devido a repetidos erros de login (mitigação de ataques de força bruta).
 * 
 * @returns {{ isLocked: boolean, remainingMs: number }}
 */
function checkLockoutStatus() {
  const lockoutUntil = localStorage.getItem(STORAGE_KEYS.LOCKOUT_UNTIL);
  if (!lockoutUntil) {
    return { isLocked: false, remainingMs: 0 };
  }

  const now = Date.now();
  const lockoutTime = parseInt(lockoutUntil, 10);

  if (now < lockoutTime) {
    return { isLocked: true, remainingMs: lockoutTime - now };
  }

  // Se o tempo expirou, remove o bloqueio e reseta as tentativas
  localStorage.removeItem(STORAGE_KEYS.LOCKOUT_UNTIL);
  localStorage.setItem(STORAGE_KEYS.FAILED_ATTEMPTS, '0');
  return { isLocked: false, remainingMs: 0 };
}

/**
 * [OWASP A07] Registra uma tentativa de login com falha e aciona o bloqueio
 * temporário caso o limite de 4 tentativas seja atingido.
 */
function recordFailedAttempt() {
  const attempts = getFailedAttempts() + 1;
  localStorage.setItem(STORAGE_KEYS.FAILED_ATTEMPTS, attempts.toString());

  if (attempts >= AUTH_CONFIG.MAX_FAILED_ATTEMPTS) {
    const lockoutUntil = Date.now() + AUTH_CONFIG.LOCKOUT_DURATION_MS;
    localStorage.setItem(STORAGE_KEYS.LOCKOUT_UNTIL, lockoutUntil.toString());
  }
}

/**
 * [OWASP A07] Reseta contadores de falhas após autenticação bem-sucedida.
 */
function resetFailedAttempts() {
  localStorage.removeItem(STORAGE_KEYS.FAILED_ATTEMPTS);
  localStorage.removeItem(STORAGE_KEYS.LOCKOUT_UNTIL);
}

/**
 * [OWASP A07] Inicia uma nova sessão autenticada no sessionStorage.
 * @param {string} username - Nome do usuário autenticado
 */
function createSession(username) {
  const token = generateSecureToken();
  const loginTime = new Date().toLocaleString('pt-BR');

  // [OWASP A07] Armazenamento estrito em sessionStorage (destruído ao fechar a aba)
  sessionStorage.setItem(STORAGE_KEYS.SESSION_TOKEN, token);
  sessionStorage.setItem(STORAGE_KEYS.SESSION_USER, username);
  sessionStorage.setItem(STORAGE_KEYS.SESSION_TIME, loginTime);
}

/**
 * [OWASP A07] Valida se há uma sessão ativa no sessionStorage.
 * @returns {boolean}
 */
function hasActiveSession() {
  const token = sessionStorage.getItem(STORAGE_KEYS.SESSION_TOKEN);
  const user = sessionStorage.getItem(STORAGE_KEYS.SESSION_USER);
  return Boolean(token && user);
}

/**
 * [OWASP A07] Encerra a sessão atual (Logout), purga os dados confidenciais
 * do sessionStorage e redireciona para a tela de login.
 */
function terminateSession() {
  // [OWASP A07] Limpeza completa da sessão
  sessionStorage.removeItem(STORAGE_KEYS.SESSION_TOKEN);
  sessionStorage.removeItem(STORAGE_KEYS.SESSION_USER);
  sessionStorage.removeItem(STORAGE_KEYS.SESSION_TIME);
  sessionStorage.clear();

  // Redireciona de volta para a tela de autenticação
  window.location.replace('index.html');
}

// ============================================================================
// LÓGICA ESPECÍFICA DA PÁGINA: LOGIN (index.html)
// ============================================================================

let lockoutInterval = null;

/**
 * Inicializa a tela de login (index.html).
 */
function initLoginPage() {
  const loginForm = document.getElementById('loginForm');
  const alertBox = document.getElementById('authAlert');
  const userInput = document.getElementById('username');
  const passInput = document.getElementById('password');
  const btnSubmit = document.getElementById('btnLogin');

  if (!loginForm) return;

  // [OWASP A07] Se o usuário já possui sessão ativa, redireciona ao dashboard
  if (hasActiveSession()) {
    window.location.replace('dashboard.html');
    return;
  }

  /**
   * Atualiza a interface durante o bloqueio temporário por força bruta
   */
  function applyLockoutUI(remainingMs) {
    userInput.disabled = true;
    passInput.disabled = true;
    btnSubmit.disabled = true;

    const remainingSeconds = Math.ceil(remainingMs / 1000);
    const minutes = Math.floor(remainingSeconds / 60);
    const seconds = remainingSeconds % 60;
    const formatted = `${minutes}m ${seconds.toString().padStart(2, '0')}s`;

    // [OWASP A05] Atualização segura via textContent
    displaySafeAlert(
      alertBox,
      `[OWASP A07] Muitas tentativas incorretas (limite: 4). Acesso bloqueado por segurança. Tente novamente em: ${formatted}`,
      'warning'
    );
  }

  /**
   * Monitora o estado de bloqueio
   */
  function checkLockout() {
    const status = checkLockoutStatus();
    if (status.isLocked) {
      applyLockoutUI(status.remainingMs);

      if (!lockoutInterval) {
        lockoutInterval = setInterval(() => {
          const updated = checkLockoutStatus();
          if (updated.isLocked) {
            applyLockoutUI(updated.remainingMs);
          } else {
            clearInterval(lockoutInterval);
            lockoutInterval = null;
            userInput.disabled = false;
            passInput.disabled = false;
            btnSubmit.disabled = false;
            displaySafeAlert(alertBox, 'O período de bloqueio expirou. Você já pode tentar novamente.', 'success');
          }
        }, 1000);
      }
      return true;
    }
    return false;
  }

  // Verifica bloqueio logo ao carregar
  checkLockout();

  // Tratador do formulário de login
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    // Verifica se está sob bloqueio por força bruta
    if (checkLockout()) {
      return;
    }

    // [OWASP A05] Sanitização rigorosa das entradas do usuário
    const rawUser = userInput.value;
    const rawPass = passInput.value;

    const sanitizedUser = sanitizeInput(rawUser);
    const sanitizedPass = rawPass.trim(); // Senhas não devem ter caracteres alterados, apenas trim

    if (!sanitizedUser || !sanitizedPass) {
      displaySafeAlert(alertBox, 'Por favor, preencha todos os campos.', 'error');
      return;
    }

    btnSubmit.disabled = true;
    btnSubmit.textContent = 'Autenticando...';

    try {
      // [OWASP A07] Computa o hash SHA-256 da senha digitada via Web Crypto API
      const inputHash = await computeSHA256(sanitizedPass);

      // [OWASP A07] Validação segura de credenciais: usuário e hash SHA-256
      const isUserValid = (sanitizedUser === AUTH_CONFIG.EXPECTED_USER);
      const isPassValid = (inputHash === AUTH_CONFIG.EXPECTED_HASH);

      if (isUserValid && isPassValid) {
        // [OWASP A07] Sucesso: reseta contadores de força bruta
        resetFailedAttempts();

        // [OWASP A07] Gera token criptográfico e salva a sessão em sessionStorage
        createSession(sanitizedUser);

        displaySafeAlert(alertBox, 'Login efetuado com sucesso! Redirecionando...', 'success');

        // Redireciona para o painel restrito
        setTimeout(() => {
          window.location.replace('dashboard.html');
        }, 600);
      } else {
        // [OWASP A07] Falha de autenticação: registra tentativa incorreta
        recordFailedAttempt();
        const currentAttempts = getFailedAttempts();

        passInput.value = '';
        passInput.focus();

        if (currentAttempts >= AUTH_CONFIG.MAX_FAILED_ATTEMPTS) {
          checkLockout();
        } else {
          const remaining = AUTH_CONFIG.MAX_FAILED_ATTEMPTS - currentAttempts;
          displaySafeAlert(
            alertBox,
            `Usuário ou senha incorretos. Tentativas restantes antes do bloqueio: ${remaining}.`,
            'error'
          );
        }
      }
    } catch (err) {
      // [OWASP A05] Mensagens de erro genéricas e seguras
      displaySafeAlert(alertBox, 'Erro no processo criptográfico de autenticação.', 'error');
    } finally {
      if (!checkLockoutStatus().isLocked) {
        btnSubmit.disabled = false;
        btnSubmit.textContent = 'Entrar';
      }
    }
  });
}

// ============================================================================
// LÓGICA ESPECÍFICA DA PÁGINA: DASHBOARD (dashboard.html)
// ============================================================================

/**
 * Inicializa a página restrita (dashboard.html).
 */
function initDashboardPage() {
  const btnLogout = document.getElementById('btnLogout');
  const userDisplay = document.getElementById('userNameDisplay');
  const timeDisplay = document.getElementById('loginTimeDisplay');
  const tokenDisplay = document.getElementById('tokenDisplay');

  // [OWASP A07 - Authentication Failures]
  // Verificação de sessão mandatória ao carregar a página protegida.
  // Se não houver sessão ativa em sessionStorage, redireciona imediatamente ao login.
  if (!hasActiveSession()) {
    window.location.replace('index.html');
    return;
  }

  // [OWASP A07 & OWASP A05]
  // Recupera as informações da sessão e renderiza de forma estritamente segura via textContent.
  const currentUser = sessionStorage.getItem(STORAGE_KEYS.SESSION_USER) || 'Usuário';
  const currentToken = sessionStorage.getItem(STORAGE_KEYS.SESSION_TOKEN) || 'Desconhecido';
  const currentTime = sessionStorage.getItem(STORAGE_KEYS.SESSION_TIME) || new Date().toLocaleString('pt-BR');

  if (userDisplay) {
    // [OWASP A05] textContent neutraliza qualquer payload malicioso
    userDisplay.textContent = currentUser;
  }

  if (timeDisplay) {
    timeDisplay.textContent = currentTime;
  }

  if (tokenDisplay) {
    tokenDisplay.textContent = currentToken;
  }

  // [OWASP A07] Tratador do botão de logout
  if (btnLogout) {
    btnLogout.addEventListener('click', () => {
      terminateSession();
    });
  }
}

// ============================================================================
// INICIALIZAÇÃO CONTROLADA
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  // Detecta a página ativa e aciona o módulo correspondente
  if (document.getElementById('loginForm')) {
    initLoginPage();
  } else if (document.getElementById('btnLogout')) {
    initDashboardPage();
  }
});
