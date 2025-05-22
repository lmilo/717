from django.contrib import admin
from .models import *

# Register your models here.

@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ['nombre', 'apellido', 'telefono', 'direccion', 'correo', 'rol' ]
    search_fields = ['nombre', 'apellido', 'correo', 'rol']
    list_filter = ['rol',]
    list_editable = ['rol'] 


@admin.register(Producto)
class ProductoAdmin(admin.ModelAdmin):
    list_display = ['nombre', 'medida', 'color', 'precio', 'descripcion', 'cantidad', 'peso', 'tipo']
    search_fields = ['nombre', 'tipo', 'precio', 'medida']
    list_filter = ['nombre', 'precio', 'color']
    list_editable = ['tipo']

@admin.register(Factura)
class FacturaAdmin(admin.ModelAdmin):
    list_display = ['cliente', 'precio', 'total', 'fecha', 'medioPago']
    search_fields = ['cliente']
    list_filter = ['precio', 'medioPago']
    list_editable = ['medioPago']

@admin.register(DetalleCompras)
class DetalleComprasAdmin(admin.ModelAdmin):
    list_display =['precioProducto', 'cantidad', 'subtotal']
    search_fields = ['precioProducto', 'cantidad']
    list_filter = ['precioProducto', 'cantidad']
    list_editable = ['cantidad']
    