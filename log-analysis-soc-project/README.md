# Log Analysis & Suspicious Activity Detector (SOC Project)

## Descripción
Herramienta desarrollada en Python para el análisis de logs y detección de actividad sospechosa en intentos de autenticación SSH.

El proyecto simula un entorno SOC, identificando posibles ataques de fuerza bruta mediante el análisis de logs.

## Funcionalidades
- Filtrado de eventos de autenticación fallida
- Extracción de direcciones IP sospechosas
- Conteo de intentos fallidos por IP
- Clasificación de alertas por nivel de riesgo
- Detección de actividad sospechosa en ventanas de tiempo
- Generación de reporte automático

## Lógica de detección

### Por volumen:
- ≥ 5 intentos → ALERTA ALTA  
- 3–4 intentos → ALERTA MEDIA  
- < 3 → ALERTA BAJA  

### Por tiempo:
- 5 intentos en ≤10 segundos → ALERTA ALTA  
- 4 intentos → MEDIA  
- 3 intentos → BAJA  

## Tecnologías
- Python
- Análisis de logs
- Seguridad informática (Blue Team)

## Ejecución
```bash
python analyze.py