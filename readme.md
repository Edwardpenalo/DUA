![alt text](<Screenshot from 2026-03-03 10-12-09.png>)
PARA CORRER

go run .cmd/api/main.go

Para compilar 
go build .cmd/api/main.go

ejecutar frontend npm run dev

# DUA Scanner

Herramienta de auditoría/recon con backend en Go y frontend en React (Vite).

## Estructura del proyecto

- `backend/`: API en Go
- `frontend/`: UI React + Vite

---

## Requisitos

- Go 1.22+ (recomendado 1.23/1.24)
- Node.js 18+ (recomendado 20+)
- npm 9+

Verificar:
```bash
go version
node -v
npm -v
```

---

## Ejecución local

### 1) Backend

```bash
cd backend
go mod tidy
go run ./cmd/api/main.go
```

API local: `http://localhost:8080`  
Health check: `http://localhost:8080/health`

### 2) Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend local: `http://localhost:3000`

---

## Build de producción

### Backend
```bash
cd backend
go build -o api ./cmd/api/main.go
./api
```

### Frontend
```bash
cd frontend
npm run build
npm run preview
```

---

## Variables de entorno

### Backend
- `PORT` (opcional): puerto de la API. Por defecto `8080`.

### Frontend
- `VITE_API_BASE_URL` (opcional): URL base de la API.
  - Ejemplo local: `http://localhost:8080`
  - Ejemplo prod: `https://tu-api.fly.dev`

---

## Endpoint principal

### `POST /scan`

Ejemplo:
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target":"example.com",
    "modules":["http","dns","tech","cms","headers","risk"],
    "options":{
      "timeoutSeconds":10,
      "maxRedirects":5
    }
  }'
```

---

## Módulos disponibles

- `http`
- `dns`
- `dirs`
- `tech`
- `cms`
- `headers`
- `ports`
- `tlsinfo`
- `vuln`
- `risk`

> Nota: algunos módulos dependen de `http` (ej: `tech`, `cms`, `headers`, `dirs`).

---

## Deploy sugerido

- **Backend**: Fly.io
- **Frontend**: Netlify

### Flujo recomendado
1. Desplegar backend (obtener URL pública)
2. Configurar `VITE_API_BASE_URL` en Netlify con esa URL
3. Desplegar frontend

---

## Limpieza de dependencias (importante)

### Backend (Go)
```bash
cd backend
go mod tidy
go mod verify
go test ./...
go build ./cmd/api/main.go
```

### Frontend (Node)
```bash
cd frontend
npm prune
npm outdated
npm run build
```

Para detectar paquetes posiblemente no usados:
```bash
cd frontend
npx depcheck
```

> Revisar manualmente antes de desinstalar (depcheck puede marcar falsos positivos en Vite/TS).

---

## Comandos útiles

```bash
# Backend lint básico
cd backend
go vet ./...

# Frontend lint (si existe script lint)
cd frontend
npm run lint
```

---

## Solución de problemas

### CORS bloqueado
Revisar `withCORS` en `backend/cmd/api/main.go` y agregar tu dominio frontend.

### Error de conexión frontend -> backend
Verificar `VITE_API_BASE_URL` y que el backend esté levantado.

### Puertos ocupados
- Backend: cambiar `PORT`
- Frontend: `npm run dev -- --port 3000`