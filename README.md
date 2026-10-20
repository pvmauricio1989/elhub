# El HUB

Portal de acceso a todos los sitios de maurosystem.com, con usuarios y permisos por bloque.

- `public/index.html`: la página (login, bloques, administración)
- `src/worker.js`: API de sesiones, usuarios y portales (Cloudflare Worker + KV)
- `wrangler.jsonc`: configuración del Worker

Publicación: sigue la guía "El HUB: guía de publicación en GitHub y Cloudflare".
Antes de desplegar, reemplaza `PEGA_AQUI_EL_ID_DE_TU_KV` en `wrangler.jsonc`
y define el secreto `ADMIN_INITIAL_PASSWORD` en Cloudflare.
