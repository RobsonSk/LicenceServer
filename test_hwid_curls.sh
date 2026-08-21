#!/usr/bin/env bash

# ==============================================================================
# Script de Teste da Obrigatoriedade de HWID (Servidor Local)
# ==============================================================================
# Uso:
#   bash test_hwid_curls.sh [UUID_OPCIONAL] [API_KEY_OPCIONAL]
#
# Se não informar UUID/API_KEY, o script tentará buscar a primeira licença do banco local.
# ==============================================================================

SERVER_URL="${SERVER_URL:-http://localhost:8443}"
UUID="$1"
API_KEY="$2"

# Se o UUID não for informado via parâmetro, busca no banco SQLite
if [ -z "$UUID" ]; then
  echo "🔍 Buscando licença de teste no banco de dados SQLite local..."
  LICENSE_DATA=$(node -e "
    import sqlite3 from 'sqlite3';
    import { open } from 'sqlite';
    const db = await open({ filename: process.env.DATABASE_PATH || './licenses.db', driver: sqlite3.Database });
    const row = await db.get('SELECT uuid, api_key FROM licenses LIMIT 1');
    if (row) console.log(row.uuid + '|' + row.api_key);
  " 2>/dev/null)

  if [ -n "$LICENSE_DATA" ]; then
    UUID=$(echo "$LICENSE_DATA" | cut -d'|' -f1)
    API_KEY=$(echo "$LICENSE_DATA" | cut -d'|' -f2)
    echo "✔ Licença encontrada no banco: UUID=$UUID"
  fi
fi

if [ -z "$UUID" ] || [ -z "$API_KEY" ]; then
  echo "⚠️ Nenhuma licença encontrada. Usando valores fictícios para demonstração."
  echo "   (Para testar com uma licença real, passe: ./test_hwid_curls.sh <UUID> <X-API-KEY>)"
  UUID="SEU-UUID-AQUI"
  API_KEY="SUA-API-KEY-AQUI"
fi

echo ""
echo "=================================================================="
echo "Servidor: $SERVER_URL"
echo "UUID:     $UUID"
echo "API Key:  $API_KEY"
echo "=================================================================="
echo ""

echo "------------------------------------------------------------------"
echo " 1. TESTE: Cliente Antigo (Sem enviar HWID)"
echo " Esperado: HTTP 401 Unauthorized (Acesso não autorizado)"
echo "------------------------------------------------------------------"
curl -i -X POST "$SERVER_URL/api/validate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"uuid\": \"$UUID\"
  }"
echo -e "\n\n"

echo "------------------------------------------------------------------"
echo " 2. TESTE: Cliente Atualizado (Enviando HWID 'MAQUINA-TESTE-01')"
echo " Esperado: HTTP 200 OK (Licença validada e vinculada no 1º acesso)"
echo "------------------------------------------------------------------"
curl -i -X POST "$SERVER_URL/api/validate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"uuid\": \"$UUID\",
    \"hwid\": \"MAQUINA-TESTE-01\"
  }"
echo -e "\n\n"

echo "------------------------------------------------------------------"
echo " 3. TESTE: Mesma Máquina enviando novamente o mesmo HWID"
echo " Esperado: HTTP 200 OK (Licença validada com sucesso)"
echo "------------------------------------------------------------------"
curl -i -X POST "$SERVER_URL/api/validate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"uuid\": \"$UUID\",
    \"hwid\": \"MAQUINA-TESTE-01\"
  }"
echo -e "\n\n"

echo "------------------------------------------------------------------"
echo " 4. TESTE: Máquina Diferente enviando HWID 'MAQUINA-INTRUSA-99'"
echo " Esperado: HTTP 401 Unauthorized (Rejeitado por HWID divergente)"
echo "------------------------------------------------------------------"
curl -i -X POST "$SERVER_URL/api/validate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"uuid\": \"$UUID\",
    \"hwid\": \"MAQUINA-INTRUSA-99\"
  }"
echo -e "\n\n"
