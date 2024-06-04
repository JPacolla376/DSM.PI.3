from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from .forms import RegisterForm, LoginForm
from .settings import collection
import bcrypt

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            email = form.cleaned_data['email']
            phone = form.cleaned_data['phone']

            existing_user = collection.find_one({'username': username})
            if existing_user is None:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                collection.insert_one({
                    'username': username,
                    'password': hashed_password,
                    'email': email,
                    'phone': phone
                })
                messages.success(request, 'User registered successfully.')
                return redirect('login')
            else:
                messages.error(request, 'Username already exists.')
    else:
        form = RegisterForm()

    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = collection.find_one({'username': username})
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                request.session['username'] = username
                messages.success(request, 'Logged in successfully.')
                return redirect('home')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('login')

def home(request):
    if 'username' in request.session:
        return render(request, 'home.html', {'username': request.session['username']})
    return redirect('login')
