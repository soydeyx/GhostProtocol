# GhostProtocol

🛡️ Ghost Protocol – Enterprise AppSec Audit Suite

Ghost Protocol es una herramienta de Application Security (AppSec) orientada a la detección, validación y documentación profesional de vulnerabilidades de autenticación expuestas en aplicaciones web, siguiendo principios OWASP y prácticas reales de auditoría defensiva.

Este proyecto fue desarrollado como portfolio profesional, con foco en claridad técnica, legalidad, explicación ejecutiva y evidencia reproducible.

📌 ¿Para qué sirve Ghost Protocol?

Ghost Protocol está diseñado para:

Identificar secretos de autenticación expuestos en el frontend (PINs, códigos, tokens)

Analizar flujos reales de autenticación

Validar de forma segura y no intrusiva si un valor expuesto es realmente aceptado por la aplicación

Generar reportes profesionales estilo OWASP, listos para:

equipos de desarrollo

seguridad

management

auditorías internas

Reducir falsos positivos mediante validación controlada

❗ ¿Qué tipo de vulnerabilidades detecta?

Ghost Protocol se enfoca principalmente en:

Client-Side Authentication Exposure

Broken Authentication

Insecure Design

Business Logic Flaws

Hardcoded Credentials in Frontend

Clasificación OWASP común:

A02:2021 – Cryptographic Failures

A04:2021 – Insecure Design

A07:2021 – Identification and Authentication Failures

⚙️ ¿Cómo funciona internamente?

La herramienta opera en tres fases claras:

 Phase 1 – Static Client-Side Analysis (SAST)

Descarga el HTML público

Analiza el código en busca de:

PINs

secretos

valores numéricos sospechosos

Extrae el fragmento exacto de código vulnerable

 No ejecuta ataques
 No interactúa con el backend

🔹 Phase 2 – Authentication Flow Visualization (Opcional)

Identifica:

formularios de login

campos de autenticación

endpoints (/login, /auth, etc.)

Muestra paso a paso:

cómo se autentica la aplicación

qué datos espera

cómo fluye la autenticación

📌 Pensado para:

Devs

QA

Security Engineers

Auditores no técnicos

🔹 Phase 3 – UI-Level Credential Validation (Controlada)

Si se detecta un secreto expuesto:

Se abre la aplicación usando el flujo nativo

Se inserta el valor encontrado (sin fuerza bruta)

Se envía el formulario normalmente

Se observa el comportamiento

Resultados posibles:

✅ CONFIRMED – El valor es aceptado

⚠️ POTENTIAL – Valor rechazado (riesgo real)

❓ UNDETERMINED – Requiere revisión manual

🚫 No bypass
🚫 No explotación
🚫 No acceso a datos sensibles

🧠 ¿Cuándo SÍ funciona esta herramienta?

Ghost Protocol es especialmente útil en:

Aplicaciones propias

Entornos de desarrollo / staging

Proyectos legacy

Aplicaciones sin backend robusto

Frontends donde:

el PIN está en HTML o JS

la validación depende del cliente

hay lógica sensible expuesta

Ejemplo real:

<input type="hidden" value="1234">

🚫 ¿Cuándo NO es la herramienta adecuada?

Ghost Protocol no está diseñado para:

Ataques de fuerza bruta

Pentesting ofensivo

Bypass de autenticación compleja

Sistemas con:

MFA

OAuth bien implementado

Backend con validación estricta

Interceptar tráfico real de usuarios

👉 Es AppSec defensivo, no hacking ofensivo.

📄 Reportes

La herramienta genera reportes HTML profesionales con:

Executive Summary

OWASP Mapping

CVSS Score

Código vulnerable exacto

Método de descubrimiento

Paso a paso de explotación

Impacto técnico y de negocio

Remediación inmediata y estratégica

Nivel de confianza (Confirmed / Potential)

Identificador único de auditoría

Listos para:

enviar a desarrollo

presentar a management

auditorías internas

🖥️ Interfaz

GUI moderna (CustomTkinter)

Consola en tiempo real

Modo Headless (automático o visual)

Opciones activables según necesidad

Diseñado para uso empresarial

⚠️ Aviso Legal

Esta herramienta está diseñada exclusivamente para pruebas defensivas autorizadas.

El autor no se hace responsable del uso indebido.

Úsela solo en aplicaciones propias o con permiso explícito.

🧩 Tecnologías usadas

Python 3

CustomTkinter

Requests

Selenium

OWASP Methodology

👤 Autor & Créditos

Proyecto desarrollado como portfolio profesional de AppSec

Made by:
IA tools, GPT, Google Labs, Gemini, and DeyX
