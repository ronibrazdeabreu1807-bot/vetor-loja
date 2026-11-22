# Loja Vetor — standalone (Render, plano grátis)
# Servidor Bun com zero dependências de npm: só bun:sqlite e node:crypto.
FROM oven/bun:1.3.10-slim

WORKDIR /app

COPY package.json ./
COPY server.ts ./
COPY public ./public

# Pasta do banco SQLite (no plano grátis ela é apagada quando o serviço
# dorme; o servidor re-semeia tudo no próximo boot — ver server.ts).
RUN mkdir -p /app/data && chown -R bun:bun /app
USER bun

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD bun -e "const r = await fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/healthz'); if (!r.ok) process.exit(1)"

CMD ["bun", "run", "server.ts"]
