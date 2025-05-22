from django.urls import path
from. import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("", views.inicio, name="inicio"),
    path("productos/", views.productos, name="productos"),
    path("contacto/", views.contacto, name="contacto"),
    path("login/", views.login, name="login"),
    path("cart/", views.cart, name="cart"),
    path('checkout/', views.checkout, name='checkout'),
    path('procesar_pago/', views.procesar_pago, name='procesar_pago'),
    path("legal/", views.legal, name="legal"),
    path("register/", views.register, name="register"),
    path("perfil/", views.perfil, name="perfil"),
    path("pedidos/", views.pedidos, name="pedidos"),
    path("detalles_pedido/<int:factura_id>/", views.detalles_pedido, name="detalles_pedido"),
    path("favoritos/", views.favoritos, name="favoritos"),
    path("detalles/<int:producto_id>/", views.detalles, name="detalles"),
    path("editar-perfil/", views.editar_perfil, name= "editar_perfil"),

    #CRUD carrito
    path('agregar_al_carrito/<int:producto_id>/', views.agregar_al_carrito, name='agregar_al_carrito'),
    path('carrito/eliminar/<int:producto_id>/<str:talla>/', views.eliminar_del_carrito, name='eliminar_del_carrito'),
    path('vaciar-carrito/', views.vaciar_carrito, name='vaciar_carrito'),
    path('carrito/actualizar/<int:producto_id>/<str:talla>/<str:accion>/', views.actualizar_cantidad, name='actualizar_cantidad'),

    
    # CRUD Usuarios
    path("listar_usuarios/", views.listar_usuarios, name="listar_usuarios"),
    path("eliminar_usuario/<int:id_usuario>/", views.eliminar_usuario, name="eliminar_usuario"),
    path("editar_usuario/<int:id_usuario>/", views.editar_usuario, name="editar_usuario"),
    path('logout/', views.logout, name='logout'),
    
    # CRUD Productos
    path("listar_productos/", views.listar_productos, name="listar_productos"),
    path("agregar_producto/", views.agregar_producto, name="agregar_producto"),
    path("editar_producto/<int:producto_id>/", views.editar_producto, name="editar_producto"),
    path("eliminar_producto/<int:producto_id>/", views.eliminar_producto, name="eliminar_producto"),


    #Cambiar clave

    path("cambiar_clave/", views.cambiar_password, name="cambiar_clave"),

    #favoritos
    path('favoritos/', views.favoritos, name='favoritos'),
    path('agregar_a_favoritos/<int:producto_id>/', views.agregar_a_favoritos, name='agregar_a_favoritos'),
    path('eliminar_de_favoritos/<int:producto_id>/', views.eliminar_de_favoritos, name='eliminar_de_favoritos'),

    
    path('confirmacion-pago/', views.confirmacion_pago, name='confirmacion_pago'),
    path('factura-pdf/', views.descargar_factura_pdf, name='factura_pdf'),
    path('enviar-factura/', views.enviar_factura_por_correo, name='enviar_factura'),
    path('ventas/', views.ventas, name='ventas'),
    path('detalles_venta/<int:id_venta>/', views.detalles_venta, name='detalles_venta'),


    path('verificar-correo/', views.enviar_token_verificacion, name='enviar_token_verificacion'),
    path('verificar-token/', views.verificar_token, name='verificar_token'),
    path("reenviar-token/", views.enviar_token_verificacion, name="reenviar_token"),

    path('recuperar/', views.solicitar_recuperacion, name='recuperar'),
    path('verificar-token-clave/', views.verificar_token_clave, name='verificar_token_clave'),
    path('actualizar-password/', views.actualizar_password, name='actualizar_password'),

    path('pedido/<int:factura_id>/descargar/', views.descargar_factura_pdf, name='descargar_factura_pdf'),
    path('pedido/<int:factura_id>/enviar/', views.enviar_factura_pdf, name='enviar_factura_pdf'),

    path('backup/', views.backup, name="backup")
    
] 
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT
                        )

