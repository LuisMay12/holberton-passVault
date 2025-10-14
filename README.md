# 🔐 Password Vault – Flask Backend

A secure password manager API built with **Flask**, **PostgreSQL**, and **Argon2id encryption**.  
This backend provides endpoints for user authentication, password vault management, and strong encryption of stored credentials.

---

## 🧠 Overview

This project implements a **secure password vault** that allows users to:

- Register and verify their account via email.
- Log in using a master password (Argon2id hashed).
- Store, list, view, and update encrypted credentials.
- Retrieve passwords securely using AES-GCM encryption.
- Authenticate using **JWT Bearer tokens** (stateless, OAuth-style).

Security and simplicity are the main priorities — all passwords are **end-to-end encrypted**, and the master password is never stored or transmitted in plain text.

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-------------|
| **Backend Framework** | Flask (Python 3.11+) |
| **Database** | PostgreSQL |
| **ORM / Migrations** | SQLAlchemy + Alembic |
| **Authentication** | JWT (PyJWT) |
| **Encryption** | Argon2id (KDF) + AES-256-GCM |

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/password-vault.git
cd password-vault
```

### 2️⃣ Create and activate a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

---

## 🐘 Database Setup (PostgreSQL via Docker)

Run PostgreSQL easily in Docker:

```bash
docker run --name mydb   -e POSTGRES_PASSWORD=secret123   -p 5432:5432   -d postgres
```

> This will start a local PostgreSQL server at `localhost:5432` with the default database `postgres` and password `secret123`.

Make sure your `.env` file points to this instance:

```env
DATABASE_URL=postgresql+psycopg2://postgres:secret123@localhost:5432/postgres
SECRET_KEY=change_me
JWT_SECRET_KEY=jwt_secret_change_me
```

---

## 🗃️ Initialize and Migrate the Database

You can create or update the database schema in one of two ways:

### Option A — Full setup (initialize migrations)

```bash
flask --app app:create_app db init
flask --app app:create_app db migrate -m "init schema"
flask --app app:create_app db upgrade
```

### Option B — Only apply migrations (if already initialized)

```bash
flask --app app:create_app db upgrade
```

---

## 🚀 Run the Application

Start the Flask development server:

```bash
flask --app app:create_app run
```

The API will be available at:  
👉 `http://127.0.0.1:5000`

---

## 🔑 Authentication Flow

1. **Signup** – `/auth/signup`  
   Register with email + master password → receive verification token.
2. **Verify** – `/auth/verify?token=...`  
   Verify your email (required before login).
3. **Login** – `/auth/login`  
   Authenticate → receive a **JWT Bearer token**.
4. **Vault** – `/vault/...`  
   Use the token to store, list, update, or retrieve encrypted passwords.

> All vault routes require the header:
> ```
> Authorization: Bearer <your_jwt_token>
> ```

---

## 🔒 Security Notes

- Master passwords are hashed using **Argon2id** — never stored in plain text.
- Vault passwords are encrypted with **AES-256-GCM**, with a unique nonce per entry.
- Email verification tokens expire automatically (default: 30 minutes).
- JWT tokens are stateless — logout simply means deleting the token client-side.
- HTTPS is strongly recommended for any real deployment.

---

## 📡 Example Requests

### Signup
```bash
curl -X POST http://127.0.0.1:5000/auth/signup   -H "Content-Type: application/json"   -d '{"email":"user@example.com","master_password":"CorrectHorseBatteryStaple"}'
```

### Login
```bash
curl -X POST http://127.0.0.1:5000/auth/login   -H "Content-Type: application/json"   -d '{"email":"user@example.com","master_password":"CorrectHorseBatteryStaple"}'
```

### Register new credential
```bash
curl -X POST http://127.0.0.1:5000/vault/register   -H "Authorization: Bearer <JWT_TOKEN>"   -H "Content-Type: application/json"   -d '{"app_name":"GitHub","app_login_url":"https://github.com/login","password":"new_secret","master_password":"CorrectHorseBatteryStaple"}'
```

---

## 🧩 Folder Structure

```
password_vault/
│
├── app.py                   # Flask app factory
├── config.py                # Configuration classes
├── extensions.py            # DB, login manager, migrations, sessions
├── crypto.py                # Encryption, Argon2id + AES-GCM helpers
├── jwt_utils.py             # JWT creation and validation
├── models.py                # SQLAlchemy models
│
├── blueprints/
│   ├── auth/                # Auth endpoints (signup, login, verify)
│   └── vault/               # Vault endpoints (register, list, detail, update)
│
└── migrations/              # Alembic migration scripts
```

---

## 🧰 Useful Commands

| Action | Command |
|--------|----------|
| Run Flask server | `flask --app app:create_app run` |
| Create migration | `flask --app app:create_app db migrate -m "message"` |
| Apply migration | `flask --app app:create_app db upgrade` |
| Check health | `GET /health` |

---

## 🧑‍💻 Development Tips

- Use a `.env` file to manage secrets (Flask automatically loads it via `python-dotenv`).
- Run PostgreSQL in Docker for isolation.
- Use `flask db migrate` whenever you modify models.
- Remember to **never commit `.env` or JWT secrets** to version control.

---

## 🧾 License

This project is open-source and available under the [MIT License](LICENSE).

---

### ✨ Author
Developed with ❤️ for the Holberton Portfolio Project.  
Built with Flask, PostgreSQL, and a focus on simplicity and security.
