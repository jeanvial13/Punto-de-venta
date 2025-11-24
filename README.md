# VICMAN - Sistema de Punto de Venta y Reparaciones

Sistema profesional POS + Gestión de Reparaciones desarrollado con NestJS, React, PostgreSQL y Docker.

## 🚀 Despliegue en Portainer (NAS)

### Opción 1: Desde Repositorio Git (Recomendado)

1. **Sube el proyecto a GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit - VICMAN POS System"
   git branch -M main
   git remote add origin https://github.com/TU_USUARIO/vicman.git
   git push -u origin main
   ```

2. **En Portainer:**
   - Ve a **Stacks** → **+ Add stack**
   - Nombre: `vicman`
   - Método: **Git Repository**
   - URL: `https://github.com/TU_USUARIO/vicman`
   - Reference: `main`
   - Compose path: `docker-compose.yml`

3. **Variables de Entorno** (en Portainer):
   ```env
   POSTGRES_PASSWORD=tu_password_seguro
   JWT_SECRET=tu_secreto_jwt_cambiar
   VITE_API_URL=http://IP_DE_TU_NAS/api
   EXTERNAL_PORT=80
   ```

4. **Deploy** → Espera 2-3 minutos

5. **Inicializar Base de Datos** (solo primera vez):
   - En Containers, selecciona `vicman-backend`
   - Console → Connect → `/bin/sh`
   - Ejecuta:
   ```bash
   npx prisma migrate deploy
   npx prisma db seed
   ```

### Opción 2: Subir archivos manualmente a Portainer

1. **En Portainer:**
   - Stacks → + Add stack
   - Nombre: `vicman`
   - Método: **Web editor**
   - Pega el contenido de `docker-compose.yml`
   - Agrega las variables de entorno

2. Sigue los pasos 4 y 5 de arriba

---

## 📡 Acceso

- **Frontend**: http://IP_DE_TU_NAS
- **Backend API**: http://IP_DE_TU_NAS/api
- **Documentación API**: http://IP_DE_TU_NAS/api (próximamente Swagger)

**Credenciales por defecto:**
```
Email: admin@pos.com
Contraseña: admin123
```

---

## 🔄 Actualizar

```bash
# Hacer cambios en el código
git add .
git commit -m "Descripción de cambios"
git push

# En Portainer: Stack → vicman → Pull and redeploy
```

---

## 🛠️ Comandos Útiles en Portainer

### Ver logs:
- Containers → selecciona contenedor → Logs

### Ejecutar comandos:
- Containers → selecciona contenedor → Console → Connect

### Backup de base de datos:
```bash
docker exec vicman-db pg_dump -U postgres pos_db > backup_$(date +%Y%m%d).sql
```

### Restaurar backup:
```bash
cat backup.sql | docker exec -i vicman-db psql -U postgres -d pos_db
```

---

## 📝 Estructura del Proyecto

```
VICMAN/
├── backend/              # API NestJS
│   ├── src/
│   ├── prisma/
│   └── Dockerfile
├── frontend/             # React + Vite
│   ├── src/
│   └── Dockerfile
├── docker-compose.yml    # Configuración Docker
├── nginx.conf           # Proxy inverso
├── DEPLOYMENT.md        # Guía de despliegue
└── README.md           # Este archivo
```

---

## 🎯 Características

### Sistema POS
- Ventas completas con múltiples métodos de pago
- Gestión de inventario con Kardex
- Clientes y proveedores
- Caja registradora
- Reportes y analytics

### Sistema de Reparaciones
- Registro de dispositivos (IMEI, fotos)
- Órdenes de trabajo completas
- 9 estados de reparación
- Gestión de repuestos (integrado con inventario)
- Servicios de software
- Asignación de técnicos
- Historial completo

---

## 📞 Soporte

Para problemas o preguntas, revisa los logs en Portainer o contacta al administrador del sistema.

---

**Desarrollado con ❤️ - VICMAN 2025**
