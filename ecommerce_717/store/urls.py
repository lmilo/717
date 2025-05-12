from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('productos/', views.product_list, name='product_list'),
    path('detalles/<int:product_id>/', views.product_detail, name='product_detail'),
    path('add-to-cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('remove-from-cart/<int:product_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('cart/', views.cart, name='cart'),
    path('toggle-favorite/<int:product_id>/', views.toggle_favorite, name='toggle_favorite'),
    path('favoritos/', views.favorites, name='favorites'),
    path('contacto/', views.contact, name='contact'),
    path('legal/', views.legal, name='legal'),
    path('checkout/', views.checkout, name='checkout'),
    path('order-confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
    path('profile/', views.profile, name='profile'),
    path('orders/', views.orders, name='orders'),
    path('edit-profile/', views.edit_profile, name='edit_profile'),
]

