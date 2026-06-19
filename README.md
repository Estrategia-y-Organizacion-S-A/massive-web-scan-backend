# Massive Web Scan Backend

Este es el backend de la herramienta de monitorización y auditoría masiva de sitios web. Está construido con **FastAPI**, **SQLAlchemy** (SQLite) y **AIOHTTP** para ofrecer un rendimiento asíncrono ultra-rápido durante los escaneos masivos.

## Requisitos Previos
Asegúrate de tener instalado Python 3.9 o superior en tu sistema.

## Instalación y Configuración

1. **Instalar dependencias:**
   Es recomendable usar un entorno virtual. Ejecuta el siguiente comando en la raíz del proyecto backend para instalar todos los paquetes necesarios:
   ```bash
   pip install fastapi uvicorn sqlalchemy aiohttp beautifulsoup4 apscheduler pyjwt python-dotenv python-multipart requests
   ```
   *(Nota: Si ya tienes un archivo `requirements.txt`, puedes usar `pip install -r requirements.txt`)*

2. **Configuración de Variables de Entorno (`.env`):**
   Crea un archivo oculto llamado `.env` en la misma carpeta donde está `main.py`. Este archivo almacena de forma segura las configuraciones y credenciales del sistema.
   Añade el siguiente contenido (puedes personalizar los valores):
   ```env
   # Credenciales de acceso al Panel (Usuario y Contraseña por defecto)
   ADMIN_USER="admin"
   ADMIN_PASS="admin123"

   # Secreto para la firma de Tokens de seguridad JWT (Cambiar en producción)
   JWT_SECRET="super-secret-key-1234"

   # (Opcional) Configuración del Bot de Telegram para recibir alertas de caídas
   TELEGRAM_BOT_TOKEN="tu_token_aqui"
   TELEGRAM_CHAT_ID="tu_id_aqui"
   ```

3. **Base de Datos:**
   La base de datos SQLite (`websites.db`) se generará de forma automática en cuanto inicies el servidor por primera vez, creando las tablas necesarias para las webs, los historiales de incidentes y las gráficas de ping.

## Inicialización del Servidor

Para levantar el servidor backend de desarrollo en caliente (auto-recarga ante cambios), ejecuta:

```bash
python main.py
```
*Opcionalmente, si utilizas uvicorn directamente:*
```bash
uvicorn main:app --reload
```

El servidor estará escuchando en **`http://localhost:8000`**. 

## Endpoints Principales
- `/api/login` (POST): Pasarela de autenticación JWT.
- `/api/websites` (GET, POST): Gestión y alta del inventario de webs a escanear.
- `/api/websites/scan-all` (POST): Desencadena el motor asíncrono de escaneo simultáneo.
- `/api/incidents` (GET): Historial de incidencias registradas.
- `/api/incidents/export` (GET): Descarga del historial en formato CSV (Excel).

## Notas de Rendimiento
El sistema utiliza `asyncio.Semaphore(50)` para limitar la concurrencia a 50 peticiones simultáneas máximas por segundo. Esto evita saturar la red local o causar caídas forzadas en los servidores de destino durante un chequeo masivo agresivo.
