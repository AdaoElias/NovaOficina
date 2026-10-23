# Nova Oficina

Sistema de gestão para oficina mecânica: cadastro de clientes, veículos, ordens de serviço, peças/estoque, vendas, fornecedores, usuários e relatórios.

## Stack

- **Backend:** Flask (Python)
- **Banco de dados:** SQLite (desenvolvimento local) / PostgreSQL (produção)
- **Servidor web:** Gunicorn

O aplicativo detecta automaticamente o banco usado. Se a variável de ambiente `DATABASE_URL` estiver definida, conecta ao **PostgreSQL**; caso contrário, usa um **SQLite** local (`oficina.db`).

## Rodando localmente

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# ou: source .venv/bin/activate  # Linux/macOS

pip install -r requirements.txt
python app.py
```

Acesse http://127.0.0.1:5000 — usuário padrão **admin / admin** (será solicitado a troca de senha no primeiro acesso).

## Deploy no Render (produção com PostgreSQL)

Este repositório inclui um `render.yaml` (Blueprint) que cria o serviço web + banco PostgreSQL de uma vez.

1. Crie um repositório no GitHub e faça upload deste projeto.
2. No [Render](https://render.com), use **New → Blueprint** e aponte para o repositório.
3. O Render detecta o `render.yaml`, cria o banco PostgreSQL e conecta automaticamente via `DATABASE_URL`.
4. Defina uma `FLASK_SECRET_KEY` forte (o blueprint gera uma automática).

### Deploy manual (sem Blueprint)

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn wsgi:app`
- **Runtime:** Python 3.12 (arquivo `runtime.txt`)
- **Banco:** crie um PostgreSQL e defina a env `DATABASE_URL` com o connection string dele
- **Env:** `FLASK_SECRET_KEY` (obrigatória em produção)

O primeiro boot executa `wsgi.py`, que cria as tabelas, popula dados padrão e cria o usuário admin.

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `DATABASE_URL` | Em produção | Connection string do PostgreSQL |
| `FLASK_SECRET_KEY` | Em produção | Chave secreta da sessão |
| `PORT` | Não | Porta HTTP (Render define automaticamente) |
| `FLASK_DEBUG` | Não | `1` liga o modo debug (não usar em produção) |

## Estrutura

```
app.py          Rotas e lógica da aplicação
database.py     Conexão com banco (SQLite/PostgreSQL) e criação do schema
wsgi.py         Entrada do Gunicorn (roda init + seed no boot)
templates/      Páginas HTML (Jinja2)
static/         CSS, JS e uploads
render.yaml     Configuração de deploy no Render
```
