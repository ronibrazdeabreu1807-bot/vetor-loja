# Loja Vetor — versão standalone (fora do Muse)

A mesma loja fictícia de eletrônicos que roda como artefato do Muse, empacotada para rodar num servidor comum, com link público. É o alvo de treino de pentest black-box: site realista, com segurança de verdade, sem defeitos plantados.

## O que tem aqui

| Arquivo | O que é |
|---|---|
| `server.ts` | Servidor completo: serve a página e responde às ações (`POST /actions`) usando só recursos do Bun (`bun:sqlite`, `node:crypto`). Zero dependências de npm. |
| `public/` | A página da loja já compilada (HTML/JS/CSS), igual à do Muse. |
| `Dockerfile` | Imagem pronta para o deploy. |
| `../render.yaml` | Blueprint do Render (na raiz do artefato): cria o serviço sozinho. |

## Segurança (idêntica à versão do Muse)

- Senhas com PBKDF2 (120 mil iterações, SHA-256, sal aleatório por senha) — nunca texto puro.
- Bloqueio de 15 minutos após 5 tentativas de login erradas; erro de login genérico, que não revela se a conta existe.
- Token de sessão aleatório, guardado no banco só como hash SHA-256; sessão de 12 h.
- Log de auditoria de logins, bloqueios, compras e ações do admin.
- Todas as consultas ao banco parametrizadas; carrinho e pedidos sempre presos ao dono da sessão; ações de admin exigem conta com papel admin.

## Banco que se recria sozinho

No plano grátis do Render o serviço dorme após ~15 min sem acesso e o disco é apagado. Por isso, a cada boot o servidor confere o banco: se estiver vazio, recria tudo automaticamente — catálogo de 12 produtos, conta admin (o mesmo hash da versão do Muse; a senha em texto puro não existe em nenhum arquivo, por design do cenário black-box) e os compradores/pedidos simulados abaixo. Contas e pedidos criados por visitantes **não** sobrevivem a uma dormida do serviço; o laboratório sempre volta ao estado inicial.

### Compradores simulados (contas fictícias de demonstração)

| Nome | E-mail | Senha |
|---|---|---|
| Marina Duarte | marina.duarte@exemplo.com | marina2026 |
| Paulo Henrique Santos | paulo.santos@exemplo.com | paulo2026 |
| Juliana Castro | juliana.castro@exemplo.com | juliana2026 |
| Roberto Almeida | roberto.almeida@exemplo.com | roberto2026 |

Eles já têm pedidos no histórico (pagos, enviados e entregues), para o painel do admin e o Modo Ataque terem movimento desde o primeiro acesso.

## Como subir no Render (grátis, sem cartão)

1. Coloque esta pasta do artefato num repositório do GitHub (a pasta inteira, incluindo `render.yaml` na raiz e a pasta `standalone/`).
2. No painel do Render: **New → Blueprint**, conecte o repositório. O Render lê o `render.yaml` e cria o serviço `vetor-loja` (Docker, plano Free).
3. Aguarde o primeiro build/deploy (uns 2–5 min). O endereço público fica no formato `https://vetor-loja.onrender.com` (o nome pode ganhar um sufixo se já estiver em uso).
4. Abra o endereço: a loja está no ar. Na primeira visita após uma dormida, o serviço leva ~30–60 s para acordar — é o comportamento normal do plano grátis.

Sem Blueprint também funciona: **New → Web Service → Docker**, com *Dockerfile Path* = `./standalone/Dockerfile` e *Docker Context Directory* = `./standalone`.

## Rodar localmente (teste rápido)

Com Bun instalado:

```sh
cd standalone
bun run server.ts
# abre http://localhost:3000
```

Com Docker:

```sh
cd standalone
docker build -t vetor-loja .
docker run -p 3000:3000 vetor-loja
```

Variáveis de ambiente aceitas: `PORT` (o Render define sozinho), `HOST` (padrão `0.0.0.0`) e `DATABASE_PATH` (padrão `./data/vetor.db`).

## Atualizar a página

Se a loja mudar dentro do Muse, a página compilada em `public/` precisa ser regerada a partir do `client/dist` do artefato e substituída aqui antes do próximo deploy.
