# VICMAN - Sistema POS y Reparaciones

## 🚀 Despliegue Rápido en Portainer

### Paso 1: Crear Stack en Portainer

1. En Portainer, ve a **Stacks** → **Add stack**
2. Nombre: `vicman`
3. Método: **Git Repository**
4. Repository URL: `TU_URL_DE_GITHUB`
5. Compose path: `docker-compose.yml`

### Paso 2: Variables de Entorno

En la sección **Environment variables**, agrega:

```env
DATABASE_URL=postgresql://postgres:postgres@db:5432/pos_db
JWT_SECRET=tu-secreto-super-seguro-cambiar-en-produccion
PORT=3000
VITE_API_URL=http://TU_IP_NAS/api
```

**Importante:** Cambia `TU_IP_NAS` por la IP de tu NAS (ej: `http://192.168.1.100/api`)

### Paso 3: Desplegar

1. Click en **Deploy the stack**
2. Espera a que los contenedores arranquen (~2-3 minutos)

### Paso 4: Inicializar Base de Datos

Una vez desplegado, ejecuta estos comandos **UNA SOLA VEZ**:

**En Portainer:**
1. Ve a **Containers**
2. Busca el contenedor `vicman-backend`
3. Click en **Console** → **Connect**
4. Ejecuta:

```bash
npx prisma migrate deploy
npx prisma db seed
```

### Paso 5: Acceder

- **Frontend**: http://TU_IP_NAS
- **Backend API**: http://TU_IP_NAS/api

**Credenciales:**
```
Email: admin@pos.com
Contraseña: admin123
```

---

## 📋 Puertos Expuestos

- `80` - Nginx (Frontend + API)
- `3000` - Backend (solo para debug, normalmente se accede via Nginx)
- `5432` - PostgreSQL (solo interno, no expuesto)

---

## 🔄 Actualizar la Aplicación

Para actualizar después de hacer cambios:

1. Haz push a GitHub
2. En Portainer, selecciona el stack `vicman`
3. Click en **Pull and redeploy**

---

## 🛠️ Comandos Útiles

### Ver logs del backend:
```bash
docker logs vicman-backend -f
```

### Ver logs de la base de datos:
```bash
docker logs vicman-db -f
```

### Reiniciar un servicio:
```bash
docker restart vicman-backend
```

### Backup de la base de datos:
```bash
docker exec vicman-db pg_dump -U postgres pos_db > backup.sql
```

---

## 🔧 Troubleshooting

### El frontend no se conecta al backend
- Verifica que `VITE_API_URL` tenga la IP correcta
- Debe ser: `http://IP_NAS/api` (sin puerto)

### Error de base de datos
- Verifica que las migraciones se ejecutaron: `npx prisma migrate deploy`
- Revisa logs: `docker logs vicman-backend`

### Puerto 80 ya en uso
En `docker-compose.yml`, cambia:
```yaml
ports:
  - "8080:80"  # Ahora usa puerto 8080
```

---

**¿Necesitas ayuda con algún paso específico?**
