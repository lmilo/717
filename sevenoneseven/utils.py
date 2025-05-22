import base64
import hashlib
import secrets

ALGORITHM = "pbkdf2_sha256"


def hash_password(password, salt=None, iterations=260000):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)

print(hash_password("123455"))


# -------------------------------------------------
# Función para comprimir archivos
import zipfile

def compress_file_to_zip(filepath, zip_filepath, compression=zipfile.ZIP_DEFLATED, compresslevel=9):
    """Compresses a file to a zip archive.

    Args:
        filepath: Path to the file to compress.
        zip_filepath: Path to the output zip file.
        compression: Compression method (e.g., zipfile.ZIP_DEFLATED).
        compresslevel: Compression level (0-9, only for DEFLATED).
    """
    with zipfile.ZipFile(zip_filepath, 'w', compression=compression, compresslevel=compresslevel) as zipf:
        zipf.write(filepath)



#--------------------------------------------------
# Funcion para comprimir carpetas

def compress_folder_to_zip(folder_path, zip_filepath, compression=zipfile.ZIP_DEFLATED, compresslevel=9):
    """Comprime una carpeta completa (con subcarpetas y archivos) en un archivo ZIP.

    Args:
        folder_path (str): Ruta de la carpeta a comprimir.
        zip_filepath (str): Ruta del archivo ZIP de salida.
        compression: Método de compresión (por defecto ZIP_DEFLATED).
        compresslevel: Nivel de compresión (0-9), solo aplica para ZIP_DEFLATED.
    """
    with zipfile.ZipFile(zip_filepath, 'w', compression=compression, compresslevel=compresslevel) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, folder_path)
                zipf.write(abs_path, arcname=rel_path)

# -------------------------------------------------
# Función para Enviar Correos con Archivos Adjuntos

from django.core.mail import EmailMessage
from . import email_settings  # Importa la configuración de correo

def send_email_with_attachment(subject, body, to_emails, folder_to_compress=None, zip_output_path=None, attachments=None, from_email=None):
    """
    Envía un correo electrónico con archivos adjuntos o una carpeta comprimida.

    Args:
        subject (str): Asunto del correo.
        body (str): Cuerpo del mensaje.
        to_emails (list): Lista de destinatarios.
        folder_to_compress (str, optional): Ruta de la carpeta a comprimir y enviar.
        zip_output_path (str, optional): Ruta donde guardar el ZIP antes de adjuntarlo.
        attachments (list, optional): Lista de tuplas (filename, content, mimetype).
        from_email (str, optional): Dirección del remitente.
    """
    if from_email is None:
        from_email = email_settings.DEFAULT_FROM_EMAIL

    email = EmailMessage(subject, body, from_email, to_emails)

    # Adjuntar carpeta comprimida si se proporciona
    if folder_to_compress and zip_output_path:
        compress_folder_to_zip(folder_to_compress, zip_output_path)
        with open(zip_output_path, 'rb') as f:
            email.attach(os.path.basename(zip_output_path), f.read(), 'application/zip')

    # Adjuntar otros archivos si se proporcionan
    if attachments:
        for filename, content, mimetype in attachments:
            email.attach(filename, content, mimetype)

    try:
        email.send()
        return True
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
        return False