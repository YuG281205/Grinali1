from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout


def index(request):
    return render(request , 'index.html')

def order(request):
    return render(request , 'order.html')

def bigpizza(request):
    return render(request , 'bigpizza.html')

def cheeseburst(request):
    return render(request , 'cheeseburst.html')

def double_brust(request):
    return render(request , 'double_brust.html')

def garlic_bread(request):
    return render(request , 'garlic_bread.html')

def mania(request):
    return render(request , 'mania.html')

def spicy(request):
    return render(request , 'spicy.html')

def regular(request):
    return render(request , 'regular.html')

def value_combo(request):
    return render(request , 'value_combo.html')

def vegpizza(request):
    return render(request , 'vegpizza.html')

def volcano(request):
    return render(request , 'volcano.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('dashboard') 
        else:
            messages.error(request, 'Invalid username or password.')
            return redirect('login')

    return render(request, 'user_login.html')

from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        
       
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('register')  
        
       
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already in use')
            return redirect('register')

       
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()
        messages.success(request, 'Account created successfully')
        return redirect('login')

    return render(request, 'register.html')



@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

def user_logout(request):
    logout(request)
    return redirect('login')

def payment(request):
    return render(request , 'payment.html')






