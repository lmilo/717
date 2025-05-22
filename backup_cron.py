# backup_cron.py ===============================================  Raiz del proyecto

import os, time
import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent

# Asegúrate de que la ruta al proyecto Django esté en el sys.path
# Esto puede variar dependiendo de tu configuración
sys.path.append("/home/manana/Descargas/717-main")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sevenoneseven.settings")    # Reemplaza 'sena' con el nombre de tu proyecto

import django
django.setup()

from sevenoneseven.utils import *  # Ajusta la ruta de importación cambiar "spa" por su aplicación

# configuración de rutas a comprimir:
file_to_compress = '/home/manana/Descargas/717-main/db.sqlite3'
zip_archive_name = '/home/manana/Descargas/717-main/db.sqlite3.zip'
compress_file_to_zip(file_to_compress, zip_archive_name)
print("...")
time.sleep(2)
print("Compresión correcta...!")
print("...")

subject = "Spa SENA - Backup desde Script de Cron"
body = "Copia de Seguridad de la Base de Datos del Proyecto Spa SENA."
to_emails = ['717days@gmail.com']

# Archivo comprimido como archivo adjunto, ejemplo... cambiar por sus rutas y archivo
file_path = '/home/manana/Descargas/717-main/db.sqlite3.zip'
attachments = []
if os.path.exists(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        attachments.append(('db.sqlite3.zip', file_content, 'application/zip'))
        print("ok lectura")
    except Exception as e:
        print(f"Error: {e}")
else:

    attachments = None

if send_email_with_attachment(subject, body, to_emails, attachments):
    print("Correo electrónico enviado con éxito desde el script de cron.")
else:
    print("Error al enviar el correo electrónico desde el script de cron.")

