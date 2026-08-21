# 🔒 License Server — Servidor de Licenciamento de Software

Servidor de validação e gerenciamento de licenças de software desenvolvido em **Node.js** com **Express** e **SQLite3**. Possui suporte nativo para **Hardware Binding (HWID)**, autenticação via **UUID** e **X-API-Key** única, controle de acesso de operadores com **MFA (2FA)** e painel administrativo web em Handlebars.

---

## 🌟 Funcionalidades

- **Validação Estrita de Licenças (`/api/validate`)**:
  - Verificação por `UUID` único e chave individual `X-API-Key`.
  - Checagem de validade (data de expiração ou licença vitalícia).
  - Status ativo/revogado.

- **Trava de Hardware ID (HWID)**:
  - **Auto-vinculação no 1º uso**: O servidor vincula automaticamente a máquina física no primeiro acesso do cliente `.exe`.
  - **Proteção contra Clonagem**: Bloqueia requisições sem HWID ou oriundas de máquinas não autorizadas (`HTTP 401`).
  - **Reset de HWID**: Painel administrativo para resetar o HWID em caso de troca ou formatação de hardware.

- **Painel Administrativo Web (`/admin`)**:
  - Gerenciamento completo de licenças (Criação, Edição, Revogação e Reset de HWID).
  - Gestão de usuários administrativos (Funções: Admin e Operador).
  - Suporte a Autenticação de Dois Fatores (**MFA/2FA via TOTP**).
  - Logs de tentativas de acesso não autorizadas e bloqueio automático de IP (Anti Brute-force / Rate Limiting).

- **Pronto para Produção**:
  - Suporte a HTTP/HTTPS direto ou implantação atrás de proxies reversos (**HAProxy**, **pfSense**, **Nginx**).

---

## 📋 Pré-requisitos

- **Node.js**: Versão 18.x ou superior.
- **NPM**: Versão 9.x ou superior.
- **SQLite3**: Incluído via módulo Node.js (sem necessidade de instalação de serviço externo).

---

## 🚀 Instalação e Configuração

### 1. Clonar o Repositório
```bash
git clone https://github.com/RobsonSk/LicenceServer
cd License-Server
```

### 2. Instalar Dependências
```bash
npm install
```

### 3. Configurar Variáveis de Ambiente
Copie o arquivo de exemplo `.env.example` para `.env`:
```bash
cp .env.example .env
```

Edite o arquivo `.env` ajustando as configurações de ambiente:
```env
# Porta do servidor Node.js
PORT=8443

# Define se o servidor Node usa HTTPS próprio (true) ou HTTP atrás de proxy reverso (false)
USE_HTTPS=false

# Chave secreta para assinatura dos tokens JWT do painel web
JWT_SECRET=defina_uma_chave_secreta_jwt_segura

# URL base pública do servidor
LICENSE_SERVER_URL=http://localhost:8443

# Caminho do banco de dados SQLite
DATABASE_PATH=./licenses.db
```

---

## 🏁 Executando o Servidor

Para iniciar o servidor:

```bash
npm start
```
*O banco de dados SQLite (`licenses.db`) será criado e inicializado automaticamente na primeira execução.*

Acesse no navegador:
- **Painel Administrativo**: [http://localhost:8443/admin](http://localhost:8443/admin)
- **Health Check**: [http://localhost:8443/health](http://localhost:8443/health)

---

## 🧪 Testes e Validação da API

Para testar o fluxo completo de validação e a obrigatoriedade do **HWID**:

### Executar Script de Teste Automatizado
```bash
bash test_hwid_curls.sh
```

### Exemplo de Requisição de Validação pelo Cliente (`.exe`)

**Endpoint:** `POST /api/validate`

**Cabeçalhos:**
```http
Content-Type: application/json
X-API-Key: SUA_X_API_KEY
```

**Corpo da Requisição (JSON):**
```json
{
  "uuid": "ce4b7a12-88f1-4b10-a982-123456789abc",
  "hwid": "a8f3b912c0194821a8f92138e0"
}
```

**Resposta de Sucesso (HTTP 200):**
```json
{
  "status": "ok",
  "valid": true,
  "company_name": "Empresa Exemplo",
  "validUntil": "2030-12-31T23:59:59.000Z",
  "is_lifetime": false,
  "uuid": "ce4b7a12-88f1-4b10-a982-123456789abc",
  "hwid": "a8f3b912c0194821a8f92138e0"
}
```

---

## 📁 Estrutura do Projeto

```text
License-Server/
├── auth.js               # Middleware de autenticação JWT e controle de roles
├── db.js                 # Inicialização do banco de dados SQLite e utilitários
├── routes.js             # Rotas principais da API (/api/validate, admin e auth)
├── server.js             # Ponto de entrada do aplicativo (Servidor HTTP/HTTPS)
├── test_hwid_curls.sh    # Script Bash com cURLs para teste local
├── views/                # Interface Web do Painel Admin (Handlebars)
├── .env.example          # Modelo de arquivo de ambiente
└── .gitignore            # Regras de exclusão do Git
```

---

## 🛡️ Segurança

- **MFA (TOTP)**: Ative o MFA para usuários administradores no Painel Web para maior segurança de acesso.
