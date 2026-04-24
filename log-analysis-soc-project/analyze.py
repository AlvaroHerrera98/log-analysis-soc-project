def leer_logs(ruta):
    """
    Lee un archivo de logs desde la ruta especificada
    y devuelve una lista con cada línea del archivo.
    """
    try:
        with open(ruta, "r") as archivo:
            lineas = archivo.readlines()
        return lineas
    except FileNotFoundError:
        print("Error: no se encuentra el archivo", ruta)
        return []

def filtrar_eventos(lineas):
    """
    Filtra las líneas del log para obtener solo los eventos
    que contienen intentos fallidos de login ("Failed password").
    """
    eventos = []

    for linea in lineas:
        if "Failed password" in linea:
            eventos.append(linea)

    return eventos

def extraer_ips(eventos):
    """
    Extrae las direcciones IP de cada evento filtrado.

    La IP se encuentra después de la palabra "from" en cada línea.
    """
    ips = []

    for evento in eventos:
        try:
            partes = evento.split()
            indice = partes.index("from")
            ip = partes[indice + 1]

            if ip.count(".") == 3:
                ips.append(ip)
            else:
                print("Línea inválida:", evento.strip())

        except (ValueError, IndexError):
            print("Línea inválida:", evento.strip())

    return ips

def contar_ips(ips):
    """
    Cuenta cuántas veces aparece cada IP en la lista.

    Devuelve un diccionario con el formato:
    { ip: cantidad_de_intentos }
    """
    conteo = {}

    for ip in ips:
        if ip in conteo:
            conteo[ip] += 1
        else:
            conteo[ip] = 1

    return conteo

def detectar_alertas(conteo_ips):
    """
    Clasifica la actividad por IP según la cantidad total de intentos fallidos.

    - ALERTA ALTA: 5 o más intentos
    - ALERTA MEDIA: 3-4 intentos
    - ALERTA BAJA: menos de 3 intentos
    """
    for ip, intentos in conteo_ips.items():
        if intentos >= 5:
            print("🚨 ALERTA ALTA:", ip, "-", intentos)
        elif intentos >= 3:
            print("⚠️ ALERTA MEDIA:", ip, "-", intentos)
        else:
            print("🔵 ALERTA BAJA:", ip, "-", intentos)

def guardar_reporte(conteo_ips):
    """
    Guarda un reporte en un archivo de texto con la cantidad de intentos
    fallidos por IP y su nivel de severidad.
    """
    with open("reporte.txt", "w") as archivo:
        for ip, intentos in conteo_ips.items():
            if intentos >= 5:
                nivel = "ALTA"
            elif intentos >= 3:
                nivel = "MEDIA"
            else:
                nivel = "BAJA"

            linea = f"{ip} - {intentos} intentos - {nivel}\n"
            archivo.write(linea)

def extraer_tiempo_ip(eventos):
    """
    Extrae la hora y la dirección IP de cada evento válido.

    Devuelve una lista de tuplas con el formato:
    (hora, ip)
    """
    registros = []

    for evento in eventos:
        try:
            partes = evento.split()
            hora = partes[2]

            indice = partes.index("from")
            ip = partes[indice + 1]

            if ip.count(".") == 3:
                registros.append((hora, ip))
            else:
                print("Línea inválida:", evento.strip())

        except (ValueError, IndexError):
            print("Línea inválida:", evento.strip())

    return registros

def hora_a_segundos(hora):
    """
    Convierte una hora en formato HH:MM:SS a segundos totales.
    """
    partes = hora.split(":")
    horas = int(partes[0])
    minutos = int(partes[1])
    segundos = int(partes[2])

    total = horas * 3600 + minutos * 60 + segundos
    return total

def convertir_registros_a_segundos(registros):
    """
    Convierte una lista de tuplas (hora, ip) a una lista de tuplas
    (segundos, ip).
    """
    registros_segundos = []

    for hora, ip in registros:
        segundos = hora_a_segundos(hora)
        registros_segundos.append((segundos, ip))

    return registros_segundos

def agrupar_tiempos_por_ip(registros_segundos):
    """
    Agrupa los tiempos en segundos por dirección IP.

    Devuelve un diccionario con el formato:
    { ip: [tiempo1, tiempo2, tiempo3] }
    """
    tiempos_por_ip = {}

    for segundos, ip in registros_segundos:
        if ip in tiempos_por_ip:
            tiempos_por_ip[ip].append(segundos)
        else:
            tiempos_por_ip[ip] = [segundos]

    return tiempos_por_ip

def detectar_ataque_por_tiempo(tiempos_por_ip):
    """
    Detecta actividad sospechosa por ventana de tiempo.

    Clasificación:
    - ALERTA ALTA: 5 intentos en 10 segundos
    - ALERTA MEDIA: 4 intentos en 10 segundos
    - ALERTA BAJA: 3 intentos en 10 segundos
    """
    for ip, tiempos in tiempos_por_ip.items():
        tiempos.sort()

        for i in range(len(tiempos) - 2):
            if i + 4 < len(tiempos) and tiempos[i + 4] - tiempos[i] <= 10:
                print("🚨 ALERTA ALTA:", ip)
                break

            elif i + 3 < len(tiempos) and tiempos[i + 3] - tiempos[i] <= 10:
                print("⚠️ ALERTA MEDIA:", ip)
                break

            elif i + 2 < len(tiempos) and tiempos[i + 2] - tiempos[i] <= 10:
                print("🔵 ALERTA BAJA:", ip)
                break

def main():
    """
    Función principal que ejecuta el flujo completo del análisis de logs.
    """
    # Detección por volumen total de intentos
    lineas = leer_logs("logs.txt")
    eventos = filtrar_eventos(lineas)
    ips_sospechosas = extraer_ips(eventos)
    conteo_ips = contar_ips(ips_sospechosas)

    detectar_alertas(conteo_ips)
    guardar_reporte(conteo_ips)

    # Detección por ventana de tiempo
    registros = extraer_tiempo_ip(eventos)
    registros_segundos = convertir_registros_a_segundos(registros)
    tiempos_por_ip = agrupar_tiempos_por_ip(registros_segundos)

    detectar_ataque_por_tiempo(tiempos_por_ip)

if __name__ == "__main__":
    main()