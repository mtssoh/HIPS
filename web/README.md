# HIPS Frontend

Frontend sencillo para el sistema HIPS (Host-based Intrusion Prevention System).

## Características

- **Dashboard interactivo** con estado del sistema
- **Autenticación** con JWT tokens
- **Escáneres de seguridad** para archivos del sistema, usuarios conectados, sniffers, etc.
- **Análisis de logs** para auth, web y mail
- **Análisis de DDoS** para archivos de log personalizados
- **Interfaz responsiva** con Bootstrap 5

## Estructura de archivos

```
web/
├── index.html          # Página principal del dashboard
├── app.js             # Lógica JavaScript y llamadas a la API
└── README.md          # Este archivo
```

## Cómo usar

### 1. Iniciar el backend

Primero asegúrate de que tu API HIPS esté corriendo:

```bash
cd /home/matias/Documentos/HIPS_SO2
python -m app.main
```

La API debería estar disponible en `http://localhost:8000`

### 2. Servir el frontend

Puedes usar cualquier servidor web simple. Aquí algunas opciones:

**Opción 1: Python HTTP Server**
```bash
cd /home/matias/Documentos/HIPS_SO2/web
python3 -m http.server 8001
```

**Opción 2: Node.js http-server (si tienes Node.js)**
```bash
cd /home/matias/Documentos/HIPS_SO2/web
npx http-server -p 8001
```

**Opción 3: PHP Server (si tienes PHP)**
```bash
cd /home/matias/Documentos/HIPS_SO2/web
php -S localhost:8001
```

### 3. Acceder al dashboard

Abre tu navegador y ve a `http://localhost:8001`

### 4. Iniciar sesión

Usa las credenciales por defecto:
- **Usuario:** admin
- **Contraseña:** adminpass

## Funcionalidades disponibles

### Escáneres del Sistema
- **System File Scan:** Verifica la integridad de archivos críticos (/etc/passwd, /etc/shadow)
- **Connected Users:** Lista usuarios conectados al sistema
- **Sniffer Detection:** Detecta herramientas de sniffing de red
- **Memory Usage:** Monitorea procesos con alto uso de memoria
- **TMP Directory:** Revisa archivos sospechosos en /tmp
- **Cron Jobs:** Analiza trabajos cron en busca de actividades sospechosas

### Análisis de Logs
- **Auth Logs:** Analiza logs de autenticación en busca de fallos
- **Web Logs:** Busca errores HTTP 4xx/5xx en logs web
- **Mail Logs:** Detecta actividad sospechosa de correo

### Análisis DDoS
- Permite analizar archivos de log personalizados para detectar ataques DDoS

## Configuración CORS

El backend ya está configurado para permitir requests desde:
- `http://localhost:8001`
- `http://127.0.0.1:8001`

Si usas un puerto diferente, actualiza la configuración CORS en `app/main.py`.

## Notas de seguridad

- Este es un frontend básico para propósitos educativos
- En producción, considera implementar HTTPS
- Valida siempre las entradas del usuario
- Usa tokens JWT con tiempos de expiración apropiados

## Personalización

Puedes personalizar el frontend modificando:
- **Estilos CSS** en el `<style>` de `index.html`
- **Funcionalidad JavaScript** en `app.js`
- **Estructura HTML** en `index.html`

## Troubleshooting

**Error de CORS:**
- Verifica que el backend esté corriendo en puerto 8000
- Asegúrate de que el frontend esté en puerto 8001

**Error de autenticación:**
- Verifica las credenciales (admin/adminpass)
- Revisa que el token JWT esté siendo enviado correctamente

**Error 500:**
- Revisa los logs del backend para más detalles
- Verifica que tengas los permisos necesarios para ejecutar los comandos del sistema
