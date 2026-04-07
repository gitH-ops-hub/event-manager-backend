# Event Manager Backend

FastAPI backend for Event Manager application.

## Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template)

## Environment Variables Required

```
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net/
DB_NAME=event_manager
JWT_SECRET=your-secret-key-here
ADMIN_EMAIL=admin@eventmanager.com
ADMIN_PASSWORD=Admin@123
FRONTEND_URL=https://gith-ops-hub.github.io
CORS_ORIGINS=*
```

## Local Development

```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```
