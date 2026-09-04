#!/usr/bin/env bash
set -e

# ==============================================================================
# Script de Pipeline de Deploy - License Server
# Servidor: live@10.5.1.12
# Destino: /home/live/Licence-server
# ==============================================================================

SERVER_USER="live"
SERVER_IP="10.5.1.12"
DEST_DIR="/home/live/Licence-server"
SSH_OPTS="-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
APP_NAME="licensing-server"

echo "=================================================="
echo "🚀 Iniciando Pipeline de Atualização do Servidor"
echo "=================================================="

# 1. Verificar status do Git
if [ -n "$(git status --porcelain)" ]; then
    echo "📌 Alterações pendentes detectadas no Git:"
    git status -s
    echo ""
    read -p "Deseja criar um commit com essas alterações antes de enviar? (s/N): " CONFIRM_COMMIT
    if [ "$CONFIRM_COMMIT" = "s" ] || [ "$CONFIRM_COMMIT" = "S" ]; then
        read -p "Digite a mensagem do commit: " COMMIT_MSG
        COMMIT_MSG=${COMMIT_MSG:-"update: atualizações do servidor via deploy script"}
        git add .
        git commit -m "$COMMIT_MSG"
        echo "✅ Commit realizado com sucesso!"
    fi
else
    echo "✅ Repositório Git limpo."
fi

echo ""
echo "📤 Sincronizando arquivos com o servidor remoto ($SERVER_USER@$SERVER_IP)..."

# 2. Enviar arquivos via rsync preservando o banco de dados e arquivos de upload do servidor
rsync -avz -e "ssh $SSH_OPTS" \
    --exclude 'node_modules/' \
    --exclude '.git/' \
    --exclude 'licenses.db*' \
    --exclude 'storage/' \
    --exclude '.env' \
    --exclude '.env.local' \
    --exclude 'log/' \
    ./ "$SERVER_USER@$SERVER_IP:$DEST_DIR/"

echo ""
echo "🔄 Reiniciando a aplicação via PM2 no servidor..."

# 3. Reiniciar PM2 no servidor remoto (Carregando PATH do Node/NVM e PM2)
ssh $SSH_OPTS "$SERVER_USER@$SERVER_IP" "
    export PATH=\$PATH:/usr/local/bin:/usr/bin:/bin:\$HOME/.nvm/versions/node/\$(ls \$HOME/.nvm/versions/node 2>/dev/null | tail -n 1)/bin:\$HOME/.nvm/current/bin;
    if [ -s \"\$HOME/.nvm/nvm.sh\" ]; then . \"\$HOME/.nvm/nvm.sh\"; fi;
    PM2_CMD=\$(which pm2 || echo \"pm2\");
    cd $DEST_DIR && (\$PM2_CMD restart $APP_NAME || \$PM2_CMD restart ecosystem.config.cjs || \$PM2_CMD start ecosystem.config.cjs)
"

echo ""
echo "=================================================="
echo "🎉 Pipeline concluído com sucesso!"
echo "=================================================="
