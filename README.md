# 🔒 License Server — Servidor de Licenciamento de Software & Atualizações Executáveis

Servidor de validação, gerenciamento de licenças de software e distribuição de atualizações automáticas de executáveis (`.exe`) desenvolvido em **Node.js** com **Express** e **SQLite3**. Possui suporte nativo para **Hardware Binding (HWID)**, autenticação via **UUID** e **X-API-Key** única, verificação/download de versões de `.exe`, controle de acesso de operadores com **MFA (2FA)** e painel administrativo web em Handlebars.

---

## 🌟 Funcionalidades

- **Validação Estrita de Licenças (`/api/validate`)**:
  - Verificação por `UUID` único e chave individual `X-API-Key`.
  - Checagem de validade (data de expiração ou licença vitalícia).
  - Status ativo/revogado.

- **Sistema de Atualização Automática de Executáveis (`.exe`)**:
  - **Endpoint de Verificação (`POST /api/check-update`)**: Consulta a versão mais recente cadastrada para o aplicativo (`app_id`), retornando status de atualização, notas de versão (changelog), hash SHA-256 e se a atualização é obrigatória (`mandatory`).
  - **Endpoint de Download Seguro (`POST /api/download-update`)**: Transmite o binário `.exe` compilado em streaming com validação de licença, suporte a checksum SHA-256 no header HTTP e isolamento de arquivos.

- **Trava de Hardware ID (HWID)**:
  - **Auto-vinculação no 1º uso**: O servidor vincula automaticamente a máquina física no primeiro acesso do cliente `.exe`.
  - **Proteção contra Clonagem**: Bloqueia requisições sem HWID ou oriundas de máquinas não autorizadas (`HTTP 401`).
  - **Reset de HWID**: Painel administrativo para resetar o HWID em caso de troca ou formatação de hardware.

- **Painel Administrativo Web (`/admin`)**:
  - Gerenciamento completo de licenças (Criação, Edição, Revogação e Reset de HWID).
  - Aba **Atualizações Executáveis**: Upload seguro de arquivos `.exe` com geração automática de SHA-256, controle de obrigatoriedade e ativação/desativação de releases.
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

# Diretório para armazenamento dos arquivos executáveis (.exe)
RELEASES_DIR=./storage/releases
```

---

## 🏁 Executando o Servidor

Para iniciar o servidor:

```bash
npm start
```
*O banco de dados SQLite (`licenses.db`) e o diretório de armazenamento (`./storage/releases/`) serão criados e inicializados automaticamente na primeira execução.*

Acesse no navegador:
- **Painel Administrativo**: [http://localhost:8443/admin](http://localhost:8443/admin)
- **Health Check**: [http://localhost:8443/health](http://localhost:8443/health)

---

## 🧪 Testes e Especificações das APIs

### 1. Validação de Licença (`POST /api/validate`)

**Headers:**
```http
Content-Type: application/json
X-API-Key: SUA_X_API_KEY
```

**Body (JSON):**
```json
{
  "uuid": "ce4b7a12-88f1-4b10-a982-123456789abc",
  "hwid": "a8f3b912c0194821a8f92138e0"
}
```

---

### 2. Verificação de Atualização (`POST /api/check-update`)

**Headers:**
```http
Content-Type: application/json
X-API-Key: SUA_X_API_KEY
```

**Body (JSON):**
```json
{
  "uuid": "ce4b7a12-88f1-4b10-a982-123456789abc",
  "hwid": "a8f3b912c0194821a8f92138e0",
  "app_id": "AtualizadorSistemas",
  "current_version": "1.0.0"
}
```

**Resposta com Nova Versão Disponível (HTTP 200):**
```json
{
  "status": "ok",
  "valid": true,
  "has_update": true,
  "latest_version": "1.1.0",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "file_size_bytes": 28410294,
  "mandatory": true,
  "download_url": "http://localhost:8443/api/download-update",
  "release_notes": "Correção de bugs e melhorias de performance."
}
```

---

### 3. Download do Executável (`POST /api/download-update`)

**Headers:**
```http
Content-Type: application/json
X-API-Key: SUA_X_API_KEY
```

**Body (JSON):**
```json
{
  "uuid": "ce4b7a12-88f1-4b10-a982-123456789abc",
  "hwid": "a8f3b912c0194821a8f92138e0",
  "app_id": "AtualizadorSistemas",
  "target_version": "1.1.0"
}
```

**Response (Binary Stream Success - HTTP 200):**
- Headers: `Content-Type: application/octet-stream`, `X-SHA256-Checksum`, `Content-Disposition: attachment; filename="AtualizadorSistemas-v1.1.0.exe"`
- Body: Conteúdo binário bruto do executável.

---

## 📁 Estrutura do Projeto

```text
License-Server/
├── auth.js               # Middleware de autenticação JWT e controle de roles
├── db.js                 # Inicialização do banco de dados SQLite e CRUDs (licenças e releases)
├── routes.js             # Rotas da API (/api/validate, /api/check-update, /api/download-update, admin)
├── server.js             # Ponto de entrada do aplicativo (Servidor HTTP/HTTPS)
├── storage/releases/     # Diretório isolado para armazenamento dos executáveis (.exe)
├── test_hwid_curls.sh    # Script Bash com cURLs para teste local
├── views/                # Interface Web do Painel Admin (Handlebars)
├── .env.example          # Modelo de arquivo de ambiente
└── .gitignore            # Regras de exclusão do Git
```

---

## 🛡️ Segurança

- **MFA (TOTP)**: Ative o MFA para usuários administradores no Painel Web para maior segurança de acesso.
