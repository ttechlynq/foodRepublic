from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import PermissionDenied
from django.contrib import messages, auth
from django.utils.http import urlsafe_base64_decode
from django.http import HttpResponse
from .forms import UserForm
from .utils import detectUser, send_verification_email
from vendor.forms import VendorForm
from .models import User, UserProfile


# Create your views here.
def check_vendor_role(user):
    if user.role == 1:
        return True
    else:
        PermissionDenied

def check_customer_role(user):
    if user.role == 2:
        return True
    else:
        PermissionDenied

def registerUser(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already looged in!')
        return redirect('myAccount')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            # user = form.save(commit=False)
            # user.role = User.CUSTOMER
            # user.save()
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            user.role = User.CUSTOMER
            user.save()
            mail_subject = 'Please activate your account.'
            email_template = 'accounts/emails/account_verification_email.html'
            send_verification_email(request, user, mail_subject, email_template)
            messages.success(request, 'Acount successfully created.')
            return redirect('registerUser')
        else:
            print('Invalid information provided.')
            print('form.errors')
    else:
        form = UserForm()
    context = {
        'form':form,
    }
    return render(request, 'accounts/registerUser.html', context)


def registerVendor(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already looged in!')
        return redirect('myAccount')
    elif request.method == 'POST':
        u_form = UserForm(request.POST)
        v_form = VendorForm(request.POST, request.FILES)
        if u_form.is_valid() and v_form.is_valid:
            first_name = u_form.cleaned_data['first_name']
            last_name = u_form.cleaned_data['last_name']
            username = u_form.cleaned_data['username']
            email = u_form.cleaned_data['email']
            password = u_form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            user.role = User.VENDOR
            user.save()
            vendor = v_form.save(commit=False)
            vendor.user = user
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()

            mail_subject = 'Please activate your account.'
            email_template = 'accounts/emails/account_verification_email.html'
            send_verification_email(request, user, mail_subject, email_template)
            messages.success(request, 'Your account has been created. Please wait for an admin to approve it.')
            return redirect('registerVendor')
        else:
            print('Invalid form')
            print('u_form.errors')
    else:
        u_form = UserForm()
        v_form = VendorForm()
    context = {
        'u_form': u_form,
        'v_form': v_form
    }
    return render(request, 'accounts/registerVendor.html', context)

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user =None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account has been activated.')
        return redirect('myAccount')
    else:
        messages.error(request, 'Invalid activation link')
    return redirect('myAccount')


def login(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already looged in!')
        return redirect('myAccount')
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            return redirect('myAccount')
        else:
            messages.error(request, 'Invalid login credentials.')
            return redirect('login')
    return render(request, 'accounts/login.html')
    
def logout(request):
    auth.logout(request)
    messages.info(request, 'You are logged out')
    return redirect('home')

@login_required(login_url='login')
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)

@login_required(login_url='login')
@user_passes_test(check_customer_role)
def customerDashboard(request):
    return render(request, 'accounts/customerDashboard.html')

@login_required(login_url='login')
@user_passes_test(check_vendor_role)    
def vendorDashboard(request):
    return render(request, 'accounts/vendorDashboard.html')
    
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)

            mail_subject = 'Reset your password'
            email_template = 'accounts/emails/reset_password_email.html'
            send_verification_email(request, user, mail_subject, email_template)
            messages.success(request, 'Password reset link has been emailed to you')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist.')
            return redirect('login')
    return render(request, 'accounts/forgot_password.html')

def reset_password_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user =None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.info(request, 'Please reset your password.')
        return redirect('reset_password')
    else:
        messages.error(request, 'This link has expired.')
        return redirect('myAccount')


def reset_password(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            pk = request.session.get('uid')
            user = User.objects.get(pk=pk)
            user.set_password(password)
            user.is_active = True
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Provided passwords did not match')
            return redirect('reset_password')
    return render(request, 'accounts/reset_password.html')

    