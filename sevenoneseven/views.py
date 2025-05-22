from django.conf import settings
from io import BytesIO
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import random
from django.db.utils import IntegrityError
from .models import *
import datetime
from django.core.mail import send_mail, EmailMultiAlternatives, EmailMessage
from .utils import *
import re
from PIL import Image 
from fpdf import FPDF
import os
from django.contrib.sessions.models import Session
from io import BytesIO
import uuid
from django.utils.timezone import now
from django.db import transaction
from django.template.loader import render_to_string

# Vista de inicio
def inicio(request):

    p = list(Producto.objects.all())
    destacados = random.sample(p, min(len(p), 3))
    contexto = {
        "data": destacados
    }
    return render(request, "index.html", contexto)


# Vista de contacto

def contacto(request):
    if request.method == "POST":
        auth = request.session.get("auth")

        if auth: 
            nombre = f"{auth['nombre']} {auth['apellido']}"
            email = auth["correo"]
        else:
            nombre = request.POST.get("txtNombre", "").strip()
            email = request.POST.get("txtEmail", "").strip()

        contenido = request.POST.get("txtMensaje", "").strip()

        if not nombre or not email or not contenido:
            messages.error(request,"Todos los campos son obligatorios.")
            return render(request, "contacto.html")

        if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', nombre):
            messages.error(request, "El nombre solo puede contener letras y espacios.")
            return render(request, "contacto.html")

        else:

            try:
                validate_email(email)
            except ValidationError:
                messages.error(request, "El correo electrónico no tiene un formato válido.")
                return render(request, "contacto0.html")    

            asunto = f"Mensaje de contacto de {nombre}"
            cuerpo = f"{contenido}\n\nEmail de contacto: {email}"

            email_desde = settings.EMAIL_HOST_USER
            email_para = ["717days@gmail.com"]

            correo = EmailMessage(
                subject=asunto,
                body=cuerpo,
                from_email=email_desde,
                to=email_para,
            )

            try:
                correo.send()
                messages.success(request, "Mensaje enviado con éxito. Nos pondremos en contacto contigo pronto.")
            except Exception as e:
                messages.error(request, f"Error al enviar el mensaje: {str(e)}")

    return render(request, "contacto.html") 

#Vista de legal
def legal(request):
    return render(request, 'legal.html')


def detalles(request, producto_id):
    producto = get_object_or_404(Producto, id=producto_id)

    if request.method == 'POST':
        talla = request.POST.get('talla')  

        
        if talla:
            carrito = request.session.get('carrito', [])

            item_en_carrito = next((item for item in carrito if item['id'] == producto.id and item['talla'] == talla), None)

            if item_en_carrito:
                item_en_carrito['cantidad'] += 1
            else:
                carrito.append({
                    'id': producto.id,
                    'nombre': producto.nombre,
                    'precio': producto.precio,
                    'talla': talla,
                    'cantidad': 1,
                    'foto': producto.foto.url,
                })

            request.session['carrito'] = carrito

            return redirect('ver_carrito')
        else:
            return render(request, 'detalles.html', {'producto': producto, 'error': 'Por favor, selecciona una talla.'})

    return render(request, 'detalles.html', {'producto': producto})


def validar_telefono(telefono):
    return re.match(r'^\d{7,15}$', telefono) is not None
#CRUD de perfil

# Vista de reigstro

def register(request):
    verificar = request.session.get("auth", False)
    if verificar:
        return redirect("inicio")
    else:
        
        if request.method == "POST":
            request.session["datos"] = request.POST
            nombre = request.POST.get("nombre")
            apellido = request.POST.get("apellido")
            correo = request.POST.get("correo")
            password = request.POST.get("password")
            confirm_password = request.POST.get("confirm_password")
            telefono = request.POST.get("telefono")
            direccion = request.POST.get("direccion")
            fecha_nac = request.POST.get("fecha_nac")
            genero = request.POST.get("genero")
            cedula = request.POST.get("cedula")
            
            try:
                validate_email(correo)
            except ValidationError:
                messages.error(request, "El correo electrónico no tiene un formato válido.")
                return render(request, "register.html")

            if Usuario.objects.filter(correo=correo).exists():
                messages.error(request, "El correo electrónico ya está registrado.")
                return render(request, "register.html")
            else:
                try:
                    fecha_nac = datetime.datetime.strptime(fecha_nac, "%Y-%m-%d").date()
                    if fecha_nac >= datetime.date.today():
                        messages.error(request, "La fecha de nacimiento debe ser anterior a hoy.")
                        return render(request, "register.html")                  
                    if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', nombre):
                        messages.error(request, "El nombre solo puede contener letras y espacios.")
                        return render(request, "register.html")
                    if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', apellido):
                        messages.error(request, "El apellido solo puede contener letras y espacios.")
                        return render(request, "register.html")
                    if not validar_telefono(telefono):
                        messages.error(request, "El teléfono debe contener entre 7 y 15 dígitos numéricos.")
                        return render(request, "register.html")
                    if not cedula.isdigit():
                        messages.error(request, "La cédula solo debe contener números.")
                        return render(request, "register.html")
                    if password != confirm_password:
                        messages.error(request, "Las contraseñas no coinciden.")
                        return render(request, "register.html")
                    
                    q = Usuario(
                        cedula=cedula,
                        nombre=nombre,
                        apellido=apellido,
                        telefono=telefono,
                        direccion=direccion,
                        correo=correo,
                        password=hash_password(password),
                        fecha_nac=fecha_nac,
                        genero=genero,
                        rol=3
                    )
                    q.save()
                    request.session["datos"]= None
                    messages.success(request, "Registro exitoso. Ahora puedes iniciar sesión.")
                    return redirect('login')

                except ValueError:
                    messages.error(request, "Formato de fecha inválido. Use YYYY-MM-DD.")
                    return render(request, "register.html")


        return render(request, "register.html", {})

# Vista de login
def login(request):  
    verificar = request.session.get("auth", False)
    if verificar:
        return redirect("inicio")
    else:
        if request.method == "POST":
            correo = request.POST.get("correo")
            password = request.POST.get("password")
            try:
                q = Usuario.objects.get(correo=correo)
                if verify_password(password, q.password):
                    # Crear variable de sesión ========
                    request.session["auth"] = {
                        "id": q.id,
                    "nombre": q.nombre,
                    "apellido": q.apellido,
                    "correo": q.correo,
                    "telefono": q.telefono,
                    "direccion": q.direccion,
                    "rol": q.rol,
                    "nombre_rol": q.get_rol_display(),
                    }
                    return redirect("inicio")
                else:
                    raise Usuario.DoesNotExist()

            except Usuario.DoesNotExist:
                messages.warning(request, "Usuario o contraseña no válidos..")
                request.session["auth"] = None
            except Exception as e:
                messages.error(request, f"Error: {e}")
                request.session["auth"] = None
            return redirect("login")
        else:
            verificar = request.session.get("auth", False)

            if verificar:
                return redirect("inicio")
            else:
                return render(request, "login.html")

    
    

# Vista de cerrar sesion

def logout(request):
    verificar = request.session.get("auth", False)
    
    if verificar:
        try:
            del request.session["auth"]
            return redirect("inicio")
        except Exception as e:
            messages.error(request, "No se pudo cerrar sesión, intente de nuevo")
            return redirect("perfil")

def editar_perfil(request):
    verificar = request.session.get("auth", False)
    if verificar:
        pass
    else:
        messages.info(request, "Usted no tiene permisos para éste módulo...")
        return redirect("inicio")
    if request.method == "POST":
        try:
            user_id = request.session.get("auth", {}).get("id")
            
            usuario = Usuario.objects.get(pk=user_id)
            
            nombre = request.POST.get("nombre").strip()
            apellido = request.POST.get("apellido").strip()
            telefono = request.POST.get("telefono").strip()
            direccion = request.POST.get("direccion").strip()
            correo = request.POST.get("correo").strip()
            
            if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', nombre):
                messages.error(request, "El nombre solo puede contener letras y espacios.")
                return redirect("editar_perfil")
            
            if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', apellido):
                messages.error(request, "El apellido solo puede contener letras y espacios.")
                return redirect("editar_perfil")
            
            if not validar_telefono(telefono):
                messages.error(request, "El teléfono debe contener entre 7 y 15 dígitos numéricos.")
                return redirect("editar_perfil")
            
            if not re.match(r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ ,.]+$', direccion):
                messages.error(request, "La dirección contiene caracteres no permitidos.")
                return redirect("editar_perfil")
            
            if Usuario.objects.exclude(pk=user_id).filter(correo=correo).exists():
                messages.error(request, "Este correo ya está en uso por otro usuario.")
                return redirect("editar_perfil")
            
            usuario.nombre = nombre
            usuario.apellido = apellido
            usuario.telefono = telefono
            usuario.direccion = direccion
            usuario.correo = correo
            usuario.save()
            request.session["auth"] = {
                        "id": usuario.id,
                    "nombre": usuario.nombre,
                    "apellido": usuario.apellido,
                    "correo": usuario.correo,
                    "telefono": usuario.telefono,
                    "direccion": usuario.direccion,
                    "rol": usuario.rol,
                    "nombre_rol": usuario.get_rol_display(),
                    }
            
            messages.success(request, "Perfil actualizado correctamente.")
            return redirect("perfil")
        except Exception as e:
            messages.error(request, f"Error: {e}")
            return redirect("editar_perfil")
    else:
        return render(request, "editar-perfil.html")
def cambiar_password(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if request.method == "POST":
            clave_actual = request.POST.get("clave_actual")
            nueva = request.POST.get("nueva")   
            repite_nueva = request.POST.get("repite_nueva")
            logueado = request.session.get("auth", False)
            q = Usuario.objects.get(pk=logueado["id"])
            if  verify_password(clave_actual, q.password):
                if nueva == repite_nueva:
                    q.password = hash_password(nueva)
                    q.save()
                    messages.success(request, "Contraseña actualizada con exito")
                    return redirect("perfil")

                else:
                    messages.error(request, "Contraseñas nuevas no coinciden")
            else:
                messages.error(request, "La contraseña no concuerda")
                
                
            return redirect("cambiar_clave")
            
        else:
            return render(request, "usuarios/cambiar_clave.html")
    else:
        pass
        
    


# Vista de perfil
def perfil(request):
    verificar = request.session.get("auth", False)
    if verificar:
        pass
    else:
        messages.info(request, "Usted no tiene permisos para éste módulo...")
        return redirect("inicio")
    
    return render(request, 'perfil.html')

# Vista de pedidos 
def pedidos(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] != 3:
            return redirect("inicio")
        else:
            correo_usuario = verificar["correo"]
            
            pedidos_usuario = Factura.objects.filter(cliente__correo=correo_usuario)
            
            return render(request, 'pedidos.html', {'pedidos': pedidos_usuario})
    else:
        return redirect("inicio")


def detalles_pedido(request, factura_id):
    verificar = request.session.get("auth", False)
    if not verificar or verificar["rol"] != 3:
        return redirect("inicio")

    try:
        pedido = Factura.objects.get(id=factura_id, cliente__correo=verificar["correo"])
        productos = pedido.detalles.all()
        total = pedido.total
    except Factura.DoesNotExist:
        return redirect("pedidos")

    return render(request, 'usuarios/detalles_compra.html', {
        "pedido": pedido,
        "productos": productos,
        "total": total
    })

# Función para eliminar producto del carrito
def eliminar_del_carrito(request, producto_id, talla):
    carrito = request.session.get('carrito', {})
    clave_producto = f"{producto_id}-{talla}"

    if clave_producto in carrito:
        del carrito[clave_producto]
        request.session['carrito'] = carrito
        messages.success(request, "Producto eliminado del carrito con éxito.")
    else:
        messages.error(request, "El producto no está en el carrito.")

    return redirect('cart')



# Función para agregar al carrito
def agregar_al_carrito(request, producto_id):
    producto = get_object_or_404(Producto, id=producto_id)
    talla = request.POST.get('talla', '').strip()
    if request.method == "POST":
        try:
            cantidad = int(request.POST.get('cantidad', 1))
            if cantidad < 1:
                raise ValueError
        except ValueError:
            messages.error(request, "La cantidad debe ser un número entero positivo.")
            return redirect(request.META.get('HTTP_REFERER', 'inicio'))

        if not talla:
            messages.error(request, "Debe seleccionar una talla antes de agregar al carrito.")
            return redirect(request.META.get('HTTP_REFERER', 'inicio'))

        carrito = request.session.get('carrito', {})
        clave_producto = f"{producto_id}-{talla}"

        # Calcular cuántas unidades ya hay en el carrito para este producto (sin importar talla)
        total_en_carrito = sum(
            item['cantidad'] for key, item in carrito.items()
            if key.startswith(f"{producto_id}-")
        )

        if total_en_carrito + cantidad > producto.cantidad:
            disponible = producto.cantidad - total_en_carrito
            messages.error(request, f"Solo hay {disponible} unidades disponibles para este producto.")
            return redirect(request.META.get('HTTP_REFERER', 'inicio'))

        if clave_producto in carrito:
            carrito[clave_producto]['cantidad'] += cantidad
        else:
            carrito[clave_producto] = {
                'nombre': producto.nombre,
                'precio': producto.precio,
                'foto': producto.foto.url if producto.foto else '',
                'cantidad': cantidad,
                'talla': talla
            }

        request.session['carrito'] = carrito
        messages.success(request, "Producto agregado al carrito con éxito.")
        return redirect(request.META.get('HTTP_REFERER', 'inicio'))
    else:
        return redirect("productos")




#Actualizar Cantidad

def actualizar_cantidad(request, producto_id, talla, accion):
    carrito = request.session.get('carrito', {})
    clave_producto = f"{producto_id}-{talla}"

    if clave_producto in carrito:
        producto = get_object_or_404(Producto, id=producto_id)
        cantidad_actual = carrito[clave_producto]['cantidad']

        # Sumar todas las cantidades de este producto en el carrito
        total_en_carrito = sum(
            item['cantidad'] for key, item in carrito.items()
            if key.startswith(f"{producto_id}-")
        )

        if accion == "incrementar":
            if total_en_carrito < producto.cantidad:
                carrito[clave_producto]['cantidad'] += 1
            else:
                messages.error(request, "No puedes agregar más unidades de las disponibles en stock.")
        elif accion == "decrementar":
            if cantidad_actual > 1:
                carrito[clave_producto]['cantidad'] -= 1
            else:
                del carrito[clave_producto]

    request.session['carrito'] = carrito
    return redirect('cart')



#Vaciar carrito

def vaciar_carrito(request):
    request.session['carrito'] = {}  
    request.session.modified = True  
    return redirect('cart')



#Funcion del carrito despues de iniciar secion
def fusionar_carrito(request):
    verificar = request.session.get("auth", False)

    if verificar:
        carrito_sesion = request.session.get('carrito', {})
        carrito_usuario = request.user.carrito.all()

        for producto_id, tallas in carrito_sesion.items():
            for talla, cantidad in tallas.items():
                producto = Producto.objects.get(id=producto_id)

                if not carrito_usuario.filter(producto=producto, talla=talla).exists():
                    request.user.carrito.create(producto=producto, talla=talla, cantidad=cantidad)

        del request.session['carrito']

#Funcion para eliminar productos que se queden sin stock
def verificar_stock(request):
    verificar = request.session.get("auth", False)

    carrito = request.session.get('carrito', {})

    for producto_id, tallas in list(carrito.items()):
        producto = Producto.objects.get(id=producto_id)
        if producto.cantidad == 0:
            del carrito[producto_id]
    
    request.session['carrito'] = carrito
    messages.info(request, "Se eliminaron productos sin stock del carrito.")

    return redirect('ver_carrito')


# Función para ver el carrito
def cart(request):
    carrito = request.session.get('carrito', {})
    carrito_items = []
    total = 0

    print("Contenido del carrito en la sesión:", carrito)  # Depuración

    if isinstance(carrito, dict):
        for clave_producto, item in carrito.items():
            print("Procesando item:", item)  # Depuración

            nombre = item.get('nombre', 'Producto sin nombre')
            precio = item.get('precio', 0)
            foto = item.get('foto', '')
            cantidad = item.get('cantidad', 1)
            talla = item.get('talla', 'N/A')

            subtotal = precio * cantidad
            total += subtotal

            carrito_items.append({
                'id': clave_producto.split('-')[0],
                'nombre': nombre,
                'precio': precio,
                'foto': foto,
                'cantidad': cantidad,
                'talla': talla,
                'subtotal': subtotal
            })
    else:
        print("⚠️ El carrito no es un diccionario. Valor:", carrito)


    return render(request, 'cart.html', {'carrito_items': carrito_items, 'total': total})


#CRUD para Usuarios //////////////////////////////////////////////////////////////////////////////////////////////////////////

# Vista para ver usuarios
def listar_usuarios(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] != 3 :
            u = Usuario.objects.all()
            contexto = {
                "data": u
                }
            return render(request, "usuarios/listar_usuarios.html", contexto)
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
        return redirect("inicio")
    else:
        return redirect("inicio")
    
    
# Vista para editar perfil
def editar_usuario(request, id_usuario):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] == 1 :
            if request.method == "POST":
                try:
                    u = Usuario.objects.get(pk=id_usuario)
                    u.cedula = request.POST.get("cedula")
                    if not u.cedula.isdigit():
                        messages.error(request, "La cédula solo debe contener números.")
                        return redirect("editar_usuario", id_usuario=id_usuario)
                    
                    u.nombre = request.POST.get("nombre").strip()
                    if not u.nombre:
                        messages.error(request, "El nombre no puede estar vacío.")
                        return redirect("editar_usuario", id_usuario=id_usuario)

                    if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', u.nombre):
                        messages.error(request, "El nombre solo puede contener letras y espacios.")
                        return redirect("editar_usuario", id_usuario=id_usuario)
                    
                    u.apellido = request.POST.get("apellido").strip()
                    if not u.apellido:
                        messages.error(request, "El apellido no puede estar vacío.")
                        return redirect("editar_usuario", id_usuario=id_usuario)

                    if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$', u.apellido):
                        messages.error(request, "El apellido solo puede contener letras y espacios.")
                        return redirect("editar_usuario", id_usuario=id_usuario)
                    
                    u.telefono = request.POST.get("telefono")
                    if not validar_telefono(u.telefono):
                        messages.error(request, "El teléfono debe contener entre 7 y 15 dígitos numéricos.")
                        return redirect("editar_usuario", id_usuario=id_usuario)
                    
                    u.direccion = request.POST.get("direccion")
                    if not re.match(r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ ,.]+$', u.direccion):
                        messages.error(request, "La dirección contiene caracteres no permitidos.")
                        return redirect("editar_usuario", id_usuario=id_usuario)
                                        
                    u.direccion = request.POST.get("direccion").strip()
                    if not u.direccion:
                        messages.error(request, "La dirección no puede estar vacía.")
                        return redirect("editar_usuario", id_usuario=id_usuario)

                    # Expresión actualizada con más símbolos permitidos
                    if not re.match(r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ ,.#-/]+$', u.direccion):
                        messages.error(request, "La dirección contiene caracteres no permitidos.")
                        return redirect("editar_usuario", id_usuario=id_usuario)
                        
                    if Usuario.objects.exclude(pk=id_usuario).filter(correo=u.correo).exists():
                        messages.error(request, "Este correo ya está en uso por otro usuario.")
                        return redirect("editar_perfil", id_usuario=id_usuario)
                    
                    u.genero = request.POST.get("genero")
                    u.rol = request.POST.get("rol")
                    u.save()
                    
                    messages.success(request, "Usuario actualizado correctamente!")
                    return redirect("listar_usuarios")
                except Exception as e:  
                    messages.error(request, f"Error: {e}")
                    return redirect("editar_usuario", id_usuario=id_usuario)
            else:
                u = Usuario.objects.get(pk=id_usuario)
                contexto = {"data": u}
                return render(request, 'register.html', contexto)
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
            return redirect("inicio")
    else:
        return redirect("inicio")
    
    
# Eliminar usuario
def eliminar_usuario(request, id_usuario):

# Obtener la instancia
        try:
            usuario_a_eliminar = Usuario.objects.get(pk=id_usuario)

            # Verificar si el usuario tiene sesiones activas
            sesiones_activas = Session.objects.filter(session_data__contains=f'"_auth_user_id":{usuario_a_eliminar.id}')

            if sesiones_activas.exists():
                messages.error(request, "No puedes eliminar a un usuario que tiene la sesión iniciada.")
            else:
                # Eliminar las sesiones del usuario antes de eliminarlo
                sesiones_activas.delete()

                # Eliminar al usuario
                usuario_a_eliminar.delete()
                messages.success(request, "Usuario eliminado correctamente!")

        except Usuario.DoesNotExist:
            messages.error(request, "El usuario no existe.")
        except IntegrityError:
            messages.warning(request, "Error: No puede eliminar el usuario, está en uso.")
        except Exception as e:
            messages.error(request, f"Error: {e}")

        return redirect("listar_usuarios")

# final del CRUD para Usuarios ///////////////////////////////////////////////////////////////////////////////////////////////////

def ventas(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] != 3 :
            v = Factura.objects.all()
            contexto = {
                "data": v
                }
            return render(request, "ventas/ventas.html", contexto)
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
        return redirect("inicio")
    else:
        return redirect("inicio")
    
def detalles_venta(request, id_venta):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] != 3 :
            detalles = DetalleCompras.objects.filter(factura__id=id_venta)
            facturas = Factura.objects.filter(id=id_venta)
            total = sum(d.subtotal for d in detalles) 

            return render(request, "ventas/detalles_venta.html", {
                "venta": detalles,
                "factura": facturas,
                "total": total
            })
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
            return redirect("inicio")
    else:
        return redirect("inicio")
# Vista de productos

def productos(request):
    
    p = Producto.objects.all()
    color = request.GET.get('color')
    tipo = request.GET.get('tipo')
    precio_orden = request.GET.get('precio_orden')
     # Aplicar filtros
    if color:
        p = p.filter(color=color)

    if tipo:
        p = p.filter(tipo=tipo)

    if precio_orden == 'menor':
        p = p.order_by('precio')  # Menor precio primero
    elif precio_orden == 'mayor':
        p = p.order_by('-precio')
    contexto = {
        "data": p,
    }
    return render(request, "productos.html", contexto)

#CRUD para Productos /////////////////////////////////////////////////////////////////////////////////////////////////////////////

# Listar productos
def listar_productos(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] != 3:
            p = Producto.objects.all()
            color = request.GET.get('color')
            tipo = request.GET.get('tipo')
            precio_orden = request.GET.get('precio_orden')

            # Aplicar filtros
            if color:
                p = p.filter(color=color)

            if tipo:
                p = p.filter(tipo=tipo)

            if precio_orden == 'menor':
                p = p.order_by('precio')  # Menor precio primero
            elif precio_orden == 'mayor':
                p = p.order_by('-precio')
            contexto = {
                "data": p,
            }
            return render(request, "productos/listar_productos.html", contexto)
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
        return redirect("inicio")
    else:
        return redirect("inicio")


# Verificacion de tipo de imagen

def validate_image_file(value):
    try:
        img = Image.open(value)
        img.verify()  # Verifica si es una imagen válida
        if img.format not in ['PNG', 'JPEG']:
            raise ValidationError('Solo se permiten archivos .png y .jpg')
    except Exception:
        raise ValidationError('Archivo de imagen no válido')
    
    # Agregar producto
def agregar_producto(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] !=3 :
            if request.method == "POST":
                
                try:
                    request.session["datos"] = request.POST
        
                    nombre = request.POST.get("nombre")
                    if not re.match(r'^[a-zA-Z0-9 ]+$', nombre):
                        messages.error(request, "El nombre solo debe contener letras y números.")
                        return redirect("agregar_producto")
                    
                    medida = request.POST.get("medida")
                    if not re.match(r'^[a-zA-Z0-9 ]+$', medida):
                        messages.error(request, "La medida solo debe contener letras y números.")
                        return redirect("agregar_producto")
                    
                    color = request.POST.get("color")
                    color = color.upper()
                    if not re.match(r'^[a-zA-Z ]+$', color):
                        messages.error(request, "El color solo debe contener letras y espacios.")
                        return redirect("agregar_producto")

                    precio = request.POST.get("precio")
                    if not validar_precio(precio):
                        messages.error(request, "El precio debe ser un número válido con hasta tres decimales.")
                        return redirect("agregar_producto")
                    precio = float(precio)
                    
                    descripcion = request.POST.get("descripcion")
                    
                    cantidad = request.POST.get("cantidad")
                    if not cantidad.isdigit() or int(cantidad) < 0:
                        messages.error(request, "La cantidad debe ser un número positivo.")
                        return redirect("agregar_producto")
                    cantidad = int(cantidad)
                    
                    peso = request.POST.get("peso")
                    if not re.match(r'^[a-zA-Z0-9 ]+$', peso):
                        messages.error(request, "El peso solo debe contener letras y números.")
                        return redirect("agregar_producto")
                    
                    foto = request.FILES.get("foto")
                    if foto:
                        try:
                            validate_image_file(foto)
                        except ValidationError as e:
                            messages.error(request, str(e))
                            return redirect("agregar_producto")
                    else:
                        messages.error(request, "Debes subir una foto del producto.")
                        return redirect("agregar_producto")

                    tipo = request.POST.get("tipo")
                    gen = int(request.POST.get("gen"))
                    
                    p = Producto(
                        nombre=nombre,
                        medida=medida,
                        color=color,
                        precio=precio,
                        descripcion=descripcion,
                        cantidad=cantidad,
                        peso=peso,
                        foto=foto,
                        tipo=tipo,
                        gen=gen
                    )
                    p.save()
                    request.session["datos"] = None
                    messages.success(request, "Producto agregado correctamente!")
                    return redirect("listar_productos")
                except Exception as e:
                    messages.error(request, f"Error: {e}")
                    return redirect("agregar_producto")
            else:
                return render(request, 'productos/formulario_productos.html')
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
            return redirect("inicio")
    else:
        return redirect("inicio")

def validar_precio(valor):
    return re.match(r'^\d+(\.\d{2,3})?$', valor) is not None

#Editar Producto    
def editar_producto(request, producto_id):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] !=3 :
            if request.method == "POST":
                try:
                    p = Producto.objects.get(pk=producto_id)
                    p.nombre = request.POST.get("nombre")
                    
                    if not re.match(r'^[a-zA-Z0-9 ]+$', p.nombre):
                        messages.error(request, "El nombre solo debe contener letras y números.")
                        return redirect("editar_producto", producto_id=producto_id)
                    
                    p.medida = request.POST.get("medida")
                    if not re.match(r'^[a-zA-Z0-9 ]+$', p.medida):
                        messages.error(request, "La medida solo debe contener letras y números.")
                        return redirect("editar_producto", producto_id=producto_id)

                    
                    p.color = request.POST.get("color")
                    if not re.match(r'^[a-zA-Z ]+$', p.color):
                        messages.error(request, "El color solo debe contener letras y espacios.")
                        return redirect("editar_producto", producto_id=producto_id)
                    
                    precio = request.POST.get("precio")
                    if not validar_precio(precio):
                        messages.error(request, "El precio debe ser un número válido con hasta tres decimales.")
                        return redirect("editar_producto", producto_id=producto_id)
                    p.precio = float(precio)
                    
                    p.descripcion = request.POST.get("descripcion")
                    
                    cantidad = request.POST.get("cantidad")
                    if not cantidad.isdigit() or int(cantidad) < 0:
                        messages.error(request, "La cantidad debe ser un número positivo y sin caracteres especiales.")
                        return redirect("editar_producto", producto_id=producto_id)
                    p.cantidad = int(cantidad)
                    
                    peso = request.POST.get("peso")
                    if not re.match(r'^[a-zA-Z0-9 ]+$', peso):
                        messages.error(request, "El peso solo debe contener letras y números.")
                        return redirect("editar_producto", producto_id=producto_id)
                    p.peso = peso
                    
                    p.foto = request.FILES.get("foto", p.foto)
                    if p.foto:
                        try:
                            validate_image_file(p.foto)
                        except ValidationError as e:
                            messages.error(request, str(e))
                            return redirect("editar_producto", producto_id=producto_id)
                    else:
                        messages.error(request, "Debes subir una foto del producto.")
                        return redirect("editar_producto")
                    
                    p.tipo = request.POST.get("tipo")
                    p.gen = request.POST.get("gen")
                    p.save()
                    
                    messages.success(request, "Producto actualizado correctamente!")
                    return redirect("listar_productos")
                except Exception as e:
                    messages.error(request, f"Error: {e}")
                    return redirect("editar_producto", producto_id=producto_id)
            else:
                p = Producto.objects.get(pk=producto_id)
                contexto = {"data": p}
                return render(request, 'productos/formulario_productos.html', contexto)
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
            return redirect("inicio")
    else:
        return redirect("inicio")
        

#Eliminar Producto
def eliminar_producto(request, producto_id):
    try:
        p = Producto.objects.get(pk = producto_id)
        p.delete()
        messages.success(request, "¡Producto eliminado correctamente!")
    except IntegrityError:
        messages.warning(request, "Error: No puede eliminar el producto, está en uso.")
    except Exception as e:
        messages.error(request, f"Error: {e}")

    return redirect("listar_productos")

#Final del CRUD para Productos //////////////////////////////////////////////////////////////////////////////////////////////////      
    

#favoritos //////////////////////////////////////////////////////////////////////////////////////////////////
def agregar_a_favoritos(request, producto_id):
    verificar = request.session.get("auth", False)
    if verificar:
        favoritos = request.session.get('favoritos', [])

        if producto_id not in favoritos:
            favoritos.append(producto_id)
            request.session['favoritos'] = favoritos
            return JsonResponse({'status': 'added'})
        else:
            return JsonResponse({'status': 'exists'})
    else:
        messages.info(request, "Debes iniciar sesión para agregar productos a favoritos.")
        return redirect("inicio")

def eliminar_de_favoritos(request, producto_id):
    try:
        p = Producto.objects.get(pk = producto_id)
        p.delete()
        messages.success(request, "producto eliminado correctamente!")
    except IntegrityError:
        messages.warning(request, "Error: No puede eliminar el producto, está en uso.")
    except Exception as e:
        messages.error(request, f"Error: {e}")

    return redirect("favoritos.html")

  
def favoritos(request):
    verificar = request.session.get("auth", False)
    if verificar:
        if verificar["rol"] == 3:
            favoritos_ids = request.session.get('favoritos', [])
            productos_favoritos = Producto.objects.filter(id__in=favoritos_ids)
            
            return render(request, 'favoritos.html', {'productos': productos_favoritos}) 
        else:
            messages.info(request, "Usted no tiene permisos para éste módulo...")
            return redirect("inicio")
    else:
        return redirect("inicio")
    
def checkout(request):
    carrito = request.session.get('carrito', {})
    carrito_items = []
    total = 0

    for clave_producto, item in carrito.items():
        nombre = item.get('nombre', 'Producto sin nombre')
        precio = item.get('precio', 0)
        foto = item.get('foto', '')
        cantidad = item.get('cantidad', 1)
        talla = item.get('talla', 'N/A')

        subtotal = precio * cantidad
        total += subtotal

        carrito_items.append({
            'id': clave_producto.split('-')[0], 
            'nombre': nombre,
            'precio': precio,
            'foto': foto,
            'cantidad': cantidad,
            'talla': talla,
            'subtotal': subtotal
        })

    return render(request, 'checkout.html', {'carrito_items': carrito_items, 'total': total})

@transaction.atomic
def procesar_pago(request):
    if not request.session.get("auth"):
        return redirect("login")
    
    usuario_id = request.session["auth"]["id"]
    usuario = Usuario.objects.get(id=usuario_id)

    if not usuario.verificado:
        
        return redirect("enviar_token_verificacion")

    if request.method == "POST":
        medio_pago = request.POST.get("medio_pago")

        carrito = request.session.get("carrito", {})

        if not carrito:
            return redirect("checkout")

        total = sum(item["precio"] * item["cantidad"] for item in carrito.values())

        factura = Factura.objects.create(
            cliente=usuario,
            precio=total,
            total=total,
            fecha=now(),
            medioPago=int(medio_pago)
        )

        productos_serializados = []

        for clave, item in carrito.items():
            producto_id = clave.split("-")[0]
            producto = Producto.objects.get(id=producto_id)
            cantidad = item["cantidad"]
            subtotal = item["precio"] * cantidad
            talla = item.get("talla", "N/A")

            DetalleCompras.objects.create(
                factura=factura,
                precioProducto=producto,
                cantidad=cantidad,
                subtotal=subtotal,
                talla=talla
            )

            producto.cantidad -= cantidad
            if producto.cantidad < 0:
                producto.cantidad = 0
            producto.save()

            productos_serializados.append({
                "nombre": producto.nombre,
                "precio": producto.precio,
                "cantidad": cantidad,
                "talla": talla,
                "subtotal": subtotal
            })

        request.session["confirmacion_pago"] = {
            "nombre": usuario.nombre,
            "apellido": usuario.apellido,
            "direccion": usuario.direccion,
            "email": usuario.correo,
            "medio_pago": dict(Factura.MEDIOPAGO).get(int(medio_pago), "Desconocido"),
            "total": total,
            "productos": productos_serializados
        }

        request.session["carrito_factura"] = carrito

        request.session["carrito"] = {}

        messages.success(request, "Pago procesado con éxito. Gracias por tu compra.")
        return redirect("confirmacion_pago")

    return redirect("checkout")

def confirmacion_pago(request):
    datos_pago = request.session.get("confirmacion_pago", {})

    if not datos_pago:
        return redirect("checkout")  

    return render(request, "confirmacion_pago.html", {"datos_pago": datos_pago})



    
class PDF(FPDF):
    def header(self):
        # Logo
        if os.path.exists(self.logo_path):
            self.image(self.logo_path, x=160, y=10, w=30)
        self.set_font('Helvetica', 'B', 16)
        self.set_y(20)
        self.cell(0, 10, 'Factura - 717', ln=True, align='L')

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', align='C')

def descargar_factura_pdf(request):
    datos_pago = request.session.get("confirmacion_pago", {})
    carrito = request.session.get("carrito_factura", {})
    numero_factura = f"FAC-{uuid.uuid4().hex[:6].upper()}"
    fecha_actual = datetime.date.today().strftime("%d/%m/%Y")

    if not datos_pago or not carrito:
        return redirect("checkout")

    pdf = PDF()
    pdf.logo_path = os.path.join(settings.BASE_DIR, 'sevenoneseven', 'static', 'img', '717logo.png')
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Datos tienda
    pdf.set_font('Helvetica', '', 10)
    pdf.set_y(30)
    pdf.cell(0, 5, "DE", ln=True)
    pdf.cell(0, 5, "Tienda 717", ln=True)
    pdf.cell(0, 5, "Calle Principal 123", ln=True)
    pdf.cell(0, 5, "Medellin, Colombia", ln=True)

    # Datos factura
    pdf.set_xy(120, 39)
    pdf.cell(40, 5, "N° DE FACTURA:")
    pdf.cell(40, 5, numero_factura, ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "FECHA:")
    pdf.cell(40, 5, fecha_actual, ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "N° DE PEDIDO:")
    pdf.cell(40, 5, "0001", ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "FECHA VENCIMIENTO:")
    pdf.cell(40, 5, fecha_actual, ln=True)

    # Direcciones
    pdf.set_y(70)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(90, 6, "ENVIAR A", ln=True)

    pdf.set_font('Helvetica', '', 10)

    # Primera fila: Nombre y Apellido
    pdf.cell(13, 6, datos_pago['nombre'])
    pdf.cell(13, 6, datos_pago['apellido'], ln=True)

    # Segunda fila: Correo (en toda la fila)
    pdf.cell(180, 6, datos_pago['email'], ln=True)

    # Tercera fila: Dirección (en toda la fila)
    pdf.cell(180, 6, datos_pago['direccion'])

    # Tabla encabezado
    pdf.set_y(100)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(20, 8, "CANT.")
    pdf.cell(80, 8, "DESCRIPCIÓN")
    pdf.cell(40, 8, "PRECIO UNITARIO", align='R')
    pdf.cell(40, 8, "IMPORTE", align='R', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())

    # Tabla productos
    total = 0
    pdf.set_font('Helvetica', '', 10)
    for _, item in carrito.items():
        cantidad = item['cantidad']
        nombre = item['nombre'][:40]
        precio = float(item['precio'])
        subtotal = cantidad * precio
        total += subtotal

        pdf.cell(20, 8, str(cantidad))
        pdf.cell(80, 8, nombre)
        pdf.cell(40, 8, f"{precio:.2f}", align='R')
        pdf.cell(40, 8, f"{subtotal:.2f}", align='R', ln=True)

    # Subtotal con cargo adicional
    total += 10000
    pdf.cell(140, 8, "Subtotal:", align='R')
    pdf.cell(40, 8, f"{total:.2f}", align='R', ln=True)

    # Total destacado
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_y(pdf.get_y() + 10)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(140, 10, "TOTAL", border=1)
    pdf.cell(40, 10, f"{total:.2f} $", border=1, ln=True, align='R')

    # Información bancaria
    pdf.set_y(pdf.get_y() + 20)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, "CONDICIONES Y FORMA DE PAGO", ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, datos_pago['medio_pago'], ln=True)
    pdf.cell(0, 6, "IBAN: ES12 3456 7891", ln=True)
    pdf.cell(0, 6, "SWIFT/BIC: ABCDESM1XXX", ln=True)

    # Generar respuesta HTTP
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Facutura_717.pdf"'
    pdf_output = BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    pdf_output.write(pdf_bytes)
    response.write(pdf_output.getvalue())
    return response

def enviar_factura_por_correo(request):
    datos_pago = request.session.get("confirmacion_pago", {})
    carrito = request.session.get("carrito_factura", {})
    numero_factura = f"FAC-{uuid.uuid4().hex[:6].upper()}"
    fecha_actual = datetime.date.today().strftime("%d/%m/%Y")

    if not datos_pago or not carrito:
        return redirect("checkout")

    pdf = PDF()
    pdf.logo_path = os.path.join(settings.BASE_DIR, 'sevenoneseven', 'static', 'img', '717logo.png')
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Datos tienda
    pdf.set_font('Helvetica', '', 10)
    pdf.set_y(30)
    pdf.cell(0, 5, "DE", ln=True)
    pdf.cell(0, 5, "Tienda 717", ln=True)
    pdf.cell(0, 5, "Calle Principal 123", ln=True)
    pdf.cell(0, 5, "Medellin, Colombia", ln=True)

    # Datos factura
    pdf.set_xy(120, 39)
    pdf.cell(40, 5, "N° DE FACTURA:")
    pdf.cell(40, 5, numero_factura, ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "FECHA:")
    pdf.cell(40, 5, fecha_actual, ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "N° DE PEDIDO:")
    pdf.cell(40, 5, "0001", ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "FECHA VENCIMIENTO:")
    pdf.cell(40, 5, fecha_actual, ln=True)

    # Direcciones
    pdf.set_y(70)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(90, 6, "ENVIAR A", ln=True)

    pdf.set_font('Helvetica', '', 10)

    # Primera fila: Nombre y Apellido
    pdf.cell(13, 6, datos_pago['nombre'])
    pdf.cell(13, 6, datos_pago['apellido'], ln=True)

    # Segunda fila: Correo (en toda la fila)
    pdf.cell(180, 6, datos_pago['email'], ln=True)

    # Tercera fila: Dirección (en toda la fila)
    pdf.cell(180, 6, datos_pago['direccion'])

    # Tabla encabezado
    pdf.set_y(100)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(20, 8, "CANT.")
    pdf.cell(80, 8, "DESCRIPCIÓN")
    pdf.cell(40, 8, "PRECIO UNITARIO", align='R')
    pdf.cell(40, 8, "IMPORTE", align='R', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())

    # Tabla productos
    total = 0
    pdf.set_font('Helvetica', '', 10)
    for _, item in carrito.items():
        cantidad = item['cantidad']
        nombre = item['nombre'][:40]
        precio = float(item['precio'])
        subtotal = cantidad * precio
        total += subtotal

        pdf.cell(20, 8, str(cantidad))
        pdf.cell(80, 8, nombre)
        pdf.cell(40, 8, f"{precio:.2f}", align='R')
        pdf.cell(40, 8, f"{subtotal:.2f}", align='R', ln=True)

    # Subtotal con cargo adicional
    total += 10000
    pdf.cell(140, 8, "Subtotal:", align='R')
    pdf.cell(40, 8, f"{total:.2f}", align='R', ln=True)

    # Total destacado
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_y(pdf.get_y() + 10)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(140, 10, "TOTAL", border=1)
    pdf.cell(40, 10, f"{total:.2f} $", border=1, ln=True, align='R')

    # Información bancaria
    pdf.set_y(pdf.get_y() + 20)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, "CONDICIONES Y FORMA DE PAGO", ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, "Banco Santander", ln=True)
    pdf.cell(0, 6, "IBAN: ES12 3456 7891", ln=True)
    pdf.cell(0, 6, "SWIFT/BIC: ABCDESM1XXX", ln=True)

    pdf_output = BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    pdf_output.write(pdf_bytes)
    pdf_output.seek(0)

    email = EmailMessage(
        subject='Factura de tu compra en 717 Tienda',
        body='Adjunto encontrarás la factura de tu compra. ¡Gracias por confiar en nosotros!',
        from_email='717days@gmail.com',
        to=[datos_pago['email']],
    )
    email.attach('Factura_717.pdf', pdf_output.getvalue(), 'application/pdf')
    email.send()

    messages.success(request, "Factura enviada al correo correctamente.")
    request.session["confirmacion_pago"] = datos_pago
    return redirect("confirmacion_pago")


def enviar_token_verificacion(request):
    if not request.session.get("auth"):
        return redirect("login")

    usuario = Usuario.objects.get(id=request.session["auth"]["id"])
    token = uuid.uuid4().hex[:6].upper()
    usuario.token_verificacion = token
    usuario.save()  

    send_mail(
        subject="Tu código de verificación",
        message=f"Tu código de verificación es: {token}",
        from_email="717days@gmail.com",
        recipient_list=[usuario.correo]
    )

    return render(request, "verificar_token.html")

def verificar_token(request):
    if request.method == 'POST':
        token = request.POST.get('token', '').strip().upper()
        usuario_id = request.session['auth']['id']
        usuario = Usuario.objects.get(id=usuario_id)

        if token == usuario.token_verificacion:
            usuario.verificado = True
            usuario.token_verificacion = None
            usuario.save()
            messages.success(request, "Verificación exitosa. Ya puedes completar tu compra.")
            return redirect('checkout')
        else:
            messages.error(request, "El código ingresado no es válido.")
            return redirect('verificar_token')  
    return render(request, 'verificar_token.html')

def solicitar_recuperacion(request):
    if request.method == "POST":
        correo = request.POST.get("correo")
        try:
            usuario = Usuario.objects.get(correo=correo)
            token = uuid.uuid4().hex[:6].upper()
            usuario.TokenClave = token
            usuario.save()

            message_plain = f"Tu código de recuperación es: {token}"

            message_html = render_to_string("usuarios/recuperacion_password.html", {
                'token': token,
            })

            subject = "Recuperación de contraseña"
            from_email = settings.DEFAULT_FROM_EMAIL  
            to_email = [correo]

            email = EmailMultiAlternatives(
                subject,  
                message_plain,  
                from_email, 
                to_email,  
            )

            email.attach_alternative(message_html, "text/html")

            email.send()

            return redirect("verificar_token")
        except Usuario.DoesNotExist:
            messages.error(request, "Correo no registrado.")
    return render(request, "usuarios/recuperar_clave.html")

def verificar_token_clave(request):
    if request.method == "POST":
        correo = request.POST.get("correo")
        token = request.POST.get("token")

        try:
            usuario = Usuario.objects.get(correo=correo)
            if usuario.TokenClave == token:
                request.session["recuperar_correo"] = correo
                return redirect("actualizar_password")
            else:
                messages.error(request, "El token ingresado es incorrecto.")
        except Usuario.DoesNotExist:
            messages.error(request, "Correo no encontrado.")
    return render(request, "usuarios/verificar_token_clave.html")

def actualizar_password(request):
    correo = request.session.get("recuperar_correo", None)

    if not correo:
        messages.error(request, "Sesión expirada o no válida.")
        return redirect("solicitar_recuperacion")

    if request.method == "POST":
        nueva_password = request.POST.get("password")
        confirmar = request.POST.get("confirmar")

        if nueva_password != confirmar:
            messages.error(request, "Las contraseñas no coinciden.")
        else:
            try:
                usuario = Usuario.objects.get(correo=correo)
                usuario.password = hash_password(nueva_password)
                usuario.TokenClave = None
                usuario.save()

                del request.session["recuperar_correo"]
                messages.success(request, "Contraseña actualizada correctamente.")
                return redirect("login")
            except Usuario.DoesNotExist:
                messages.error(request, "Usuario no encontrado.")
                return redirect("solicitar_recuperacion")

    return render(request, "usuarios/actualizar_clave.html")


class PDF(FPDF):
    def header(self):
        if os.path.exists(self.logo_path):
            self.image(self.logo_path, x=160, y=10, w=30)
        self.set_font('Helvetica', 'B', 16)
        self.set_y(20)
        self.cell(0, 10, f'Factura - #{self.factura_id}', ln=True, align='L')

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', align='C')

def generar_pdf(factura):
    pdf = PDF()
    pdf.factura_id = factura.id
    pdf.logo_path = os.path.join(settings.BASE_DIR, 'sevenoneseven', 'static', 'img', '717logo.png')
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    cliente = factura.cliente
    productos = factura.detalles.all()

    pdf.set_font('Helvetica', '', 10)
    pdf.set_y(30)
    pdf.cell(0, 5, "DE", ln=True)
    pdf.cell(0, 5, "Tienda 717", ln=True)
    pdf.cell(0, 5, "Calle Principal 123", ln=True)
    pdf.cell(0, 5, "Medellin, Colombia", ln=True)

    pdf.set_xy(120, 39)
    pdf.cell(40, 5, "N° DE FACTURA:")
    pdf.cell(40, 5, f"FAC-{uuid.uuid4().hex[:6].upper()}", ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "FECHA:")
    pdf.cell(40, 5, factura.fecha.strftime("%d/%m/%Y"), ln=True)
    pdf.set_x(120)
    pdf.cell(40, 5, "CLIENTE ID:")
    pdf.cell(40, 5, str(cliente.id), ln=True)

    pdf.set_y(70)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(90, 6, "ENVIAR A", ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(180, 6, f"{cliente.nombre}", ln=True)
    pdf.cell(180, 6, cliente.correo, ln=True)

    pdf.set_y(100)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(20, 8, "CANT.")
    pdf.cell(80, 8, "DESCRIPCIÓN")
    pdf.cell(40, 8, "PRECIO UNITARIO", align='R')
    pdf.cell(40, 8, "IMPORTE", align='R', ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())

    total = 0
    pdf.set_font('Helvetica', '', 10)
    for item in productos:
        nombre = item.precioProducto.nombre[:40]
        precio = float(item.precioProducto.precio)
        cantidad = item.cantidad
        subtotal = item.subtotal
        total += subtotal

        pdf.cell(20, 8, str(cantidad))
        pdf.cell(80, 8, nombre)
        pdf.cell(40, 8, f"{precio:.2f}", align='R')
        pdf.cell(40, 8, f"{subtotal:.2f}", align='R', ln=True)

    pdf.cell(140, 8, "Subtotal:", align='R')
    pdf.cell(40, 8, f"{total:.2f}", align='R', ln=True)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_y(pdf.get_y() + 10)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(140, 10, "TOTAL", border=1)
    pdf.cell(40, 10, f"{total:.2f} $", border=1, ln=True, align='R')

    output = BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    output.write(pdf_bytes)
    output.seek(0)
    return output

def descargar_factura_pdf(request, factura_id):
    factura = get_object_or_404(Factura, id=factura_id)
    pdf_output = generar_pdf(factura)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Factura_717_{factura.id}.pdf"'
    response.write(pdf_output.getvalue())
    return response

def enviar_factura_pdf(request, factura_id):
    factura = get_object_or_404(Factura, id=factura_id)
    pdf_output = generar_pdf(factura)

    email = EmailMessage(
        subject=f'Factura #{factura.id} - Tienda 717',
        body='Adjunto encontrarás la factura de tu compra. ¡Gracias por tu pedido!',
        from_email='717days@gmail.com',
        to=[factura.cliente.correo],
    )
    email.attach(f'Factura_{factura.id}.pdf', pdf_output.getvalue(), 'application/pdf')
    email.send()
    pedido = Factura.objects.get(id=factura_id, cliente=factura.cliente)
    productos = pedido.detalles.all()
    total = pedido.total
    messages.success(request, "Factura enviada al correo correctamente.")        
    return render(request, 'usuarios/detalles_compra.html', {
        "pedido": pedido,
        "productos": productos,
        "total": total
    })


def backup(request):
    try:
        # 🔹 Rutas de elementos a incluir
        media_folder = '/home/manana/Descargas/717-main/media'
        static_folder = '/home/manana/Descargas/717-main/static_files_server'
        db_file = '/home/manana/Descargas/717-main/db.sqlite3'

        # 🔹 Rutas de ZIPs temporales
        media_zip = '/home/manana/Descargas/717-main/media.zip'
        static_zip = '/home/manana/Descargas/717-main/static_files_server.zip'

        # 🔹 Carpeta contenedora y ZIP final
        contenedor = '/home/manana/Descargas/717-main/agrupados'
        final_zip = '/home/manana/Descargas/717-main/para_enviar.zip'

        # 1. Comprimir carpetas individualmente
        compress_folder_to_zip(media_folder, media_zip)
        compress_folder_to_zip(static_folder, static_zip)

        # 2. Crear carpeta contenedora
        os.makedirs(contenedor, exist_ok=True)

        # 3. Mover archivos al contenedor
        shutil.move(media_zip, os.path.join(contenedor, 'media.zip'))
        shutil.move(static_zip, os.path.join(contenedor, 'static_files_server.zip'))
        shutil.copy(db_file, os.path.join(contenedor, 'db.sqlite3'))

        # 4. Comprimir carpeta contenedora completa
        compress_folder_to_zip(contenedor, final_zip)

        # 5. Limpiar archivos temporales
        shutil.rmtree(contenedor)

        print("...")
        time.sleep(2)
        print("Compresión correcta...!")
        print("...")

        # 6. Enviar por correo
        subject = "Spa SENA - Backup"
        body = "Copia de seguridad del proyecto Spa SENA (media, static_files_server y base de datos)"
        to_emails = ['717days@gmail.com']

        if os.path.exists(final_zip):
            with open(final_zip, 'rb') as f:
                file_content = f.read()
            attachments = [('para_enviar.zip', file_content, 'application/zip')]
        else:
            attachments = None

        if send_email_with_attachment(subject, body, to_emails, attachments):
            print("Correo electrónico enviado con éxito.")
            return HttpResponse("Backup creado y correo enviado con éxito.")
        else:
            print("Error al enviar el correo electrónico.")
            return HttpResponse("Error al enviar el correo electrónico.")

    except Exception as e:
        print(f"Error en el proceso de backup: {e}")
        return HttpResponse("Ocurrió un error al generar el backup.")