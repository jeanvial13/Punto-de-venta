# VICMAN - Quick Start

## 🧹 Antes de Subir a GitHub

**El proyecto pesa 513 MB porque incluye `node_modules`.** Ejecuta este script para limpiarlo:

### Windows:
```bash
# Doble click en:
clean-for-github.bat

# O desde PowerShell:
cd "C:\Users\mande\Desktop\Punto de venta"
.\clean-for-github.bat
```

Esto eliminará:
- ❌ `node_modules/` (500+ MB)
- ❌ `package-lock.json`
- ❌ `dist/` y `build/`

**El proyecto ahora pesará menos de 10 MB** ✅

---

## 📤 Subir a GitHub

```bash
cd "C:\Users\mande\Desktop\Punto de venta"

git init
git add .
git commit -m "Initial commit - VICMAN POS System"
git branch -M main

# Crea un repo en GitHub, luego:
git remote add origin https://github.com/TU_USUARIO/vicman.git
git push -u origin main
```

---

## 🐳 Desplegar en Portainer

### 1. En Portainer → Stacks → Add Stack

**Método 1: Git Repository (Recomendado)**
- Nombre: `vicman`
- Repository URL: `https://github.com/TU_USUARIO/vicman`
- Compose path: `docker-compose.yml`

**Método 2: Web Editor**
- Copia y pega el contenido de `docker-compose.yml`

### 2. Variables de Entorno

```env
POSTGRES_PASSWORD=tu_password_seguro
JWT_SECRET=secreto_jwt_cambiar
VITE_API_URL=http://192.168.1.XXX/api
EXTERNAL_PORT=80
```

**IMPORTANTE:** Cambia `192.168.1.XXX` por la IP de tu NAS

### 3. Deploy

Click **Deploy the stack** → Espera 3-5 minutos mientras Docker:
- ✅ Descarga las imágenes base
- ✅ Instala todas las dependencias
- ✅ Construye los contenedores
- ✅ Inicia los servicios

### 4. Inicializar Base de Datos (solo primera vez)

En Portainer:
1. **Containers** → `vicman-backend`
2. **Console** → **Connect** → `/bin/sh`
3. Ejecuta:
```bash
npx prisma migrate deploy
npx prisma db seed
```

### 5. ¡Listo!

Accede a: **http://IP_DE_TU_NAS**

```
Email: admin@pos.com
Contraseña: admin123
```

---

## 📊 Tamaño de Archivos

| Carpeta | Con node_modules | Sin node_modules |
|---------|------------------|------------------|
| VICMAN  | 513 MB 😱        | <10 MB ✅         |

**Docker instalará todo automáticamente** durante el build (toma 3-5 minutos la primera vez)

---

## 🔄 Actualizar Después

```bash
# Hacer cambios
git add .
git commit -m "Update"
git push

# En Portainer: Stack vicman → Pull and redeploy
```

---

## ❓ Troubleshooting

**¿El proyecto sigue pesado?**
```bash
# Verifica que .gitignore funciona:
git status

# No debería mostrar node_modules/
```

**¿Error al hacer git add?**
```bash
# Fuerza la aplicación del .gitignore:
git rm -r --cached .
git add .
```

---

Para más detalles, ve **README.md** y **DEPLOYMENT.md**
