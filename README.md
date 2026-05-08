# Detección de Ataques de Autenticación

Objetivo

Monitorear y analizar los registros de seguridad de Windows para identificar intentos de acceso no autorizados mediante técnicas de fuerza bruta.

Metodología

Identificación del Log: Uso del Windows Event Viewer enfocado en el log de Security.

Filtrado Crítico: Monitoreo del Event ID 4625.

Correlación de Datos: Análisis de la dirección IP de origen y el nombre de cuenta objetivo.

<img width="910" height="636" alt="visor de eventos" src="https://github.com/user-attachments/assets/22e95563-e3b8-4ced-bd17-9bf15f80a29e" />

Hallazgos

Evento Detectado: Múltiples fallos de inicio de sesión en un intervalo menor a 1 minuto.

Cuenta Objetivo: admin / invitado.

Origen: 127.0.0.1 (Red Local).

<img width="510" height="255" alt="IP resaltada" src="https://github.com/user-attachments/assets/ebd2db1d-d83e-4351-ae9d-be1ffd9594f0" />

🛡️ Recomendaciones del Analista SOC
Implementar políticas de bloqueo de cuenta tras 5 intentos fallidos.

Habilitar la auditoría de inicios de sesión exitosos (ID 4624) para verificar si el atacante finalmente logró entrar.

En lugar de buscar a mano, usé este comando de PowerShell para listar los últimos 10 fallos de login

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 | Select-Object TimeCreated, Id, Message | Out-GridView

Para este análisis, se ejecutó PowerShell con privilegios de administrador, ya que el acceso a los registros de seguridad está restringido por políticas de control de acceso del sistema (ACLs), garantizando la integridad de las evidencias.

<img width="760" height="744" alt="powershell" src="https://github.com/user-attachments/assets/5d26ef8c-2f8e-4550-a321-fccbe5aa7622" />
