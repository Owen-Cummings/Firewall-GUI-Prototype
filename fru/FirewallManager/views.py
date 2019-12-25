import re
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.db import models
from django.db.models import Q
from .models import Rule
from .models import Profile
from .models import User
from .backend import ufwFunctions
import sqlite3


def dashboard(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        rules = Rule.objects.all()
        context = {'rules': rules}
        return render(request, 'Firewalls-R-Us/dashboard.html', context)


def search_rules(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        searchQuery = request.POST.get("Search")
        # Filter all fields for requested information
        rules = Rule.objects.filter(Q(protocol__icontains=searchQuery) | Q(from_ip__icontains=searchQuery) |
                                    Q(to_ip__icontains=searchQuery) | Q(port_number__icontains=searchQuery) |
                                    Q(permission__icontains=searchQuery))
        # Saves the rules in context
        context = {'rules': rules}
        # Returns the render
        return render(request, 'Firewalls-R-Us/viewrules.html', context)


@login_required(login_url="user-login")
def create_rule(request):

    # To call the initial web page with forms
    if request.method == 'GET':
        return render(request, 'Firewalls-R-Us/firewall_rule_creation_editing.html', )
    else:
        permission = request.POST.get("permission")
        protocol = request.POST.get("protocol")
        from_ip = request.POST.get("from_ip")
        to_ip = request.POST.get("to_ip")
        port_number = request.POST.get("port_number")

        if permission and protocol and from_ip and to_ip and port_number:

            permission = permission.lower()
            protocol = protocol.lower()

            re_dict = {
                "permission": "(allow|deny)",
                "protocol": "(tcp|udp)",
                "from_ip": ["(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                            "\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                            "\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                            "\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                            "any"],
                "to_ip": ["(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                          "\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                          "\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                          "\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                          "(/([1-9]|[1-2][0-9]|3[1-2]))?",
                          "any"],
                "port_number": "[0-9]{1,5}"
            }

            invalid_input = 0
            match = 0

            if not re.fullmatch(re_dict["permission"], permission):
                messages.add_message(request, messages.WARNING, "Invalid Permission Field.")
                invalid_input = 1

            if not re.fullmatch(re_dict["protocol"], protocol):
                messages.add_message(request, messages.WARNING, "Invalid Protocol Field.")
                invalid_input = 1

            for r in re_dict["from_ip"]:
                if re.fullmatch(r, from_ip):
                    match = 1
                    break

            if not match:
                invalid_input = 1
                messages.add_message(request, messages.WARNING, "Invalid Source IP Address.")

            match = 0

            for r in re_dict["to_ip"]:
                if re.fullmatch(r, to_ip):
                    match = 1
                    break

            if not match:
                invalid_input = 1
                messages.add_message(request, messages.WARNING, "Invalid Destination IP Address.")

            if not re.fullmatch(re_dict["port_number"], port_number):
                messages.add_message(request, messages.WARNING, "Invalid Port Number.")
                invalid_input = 1
            else:
                if 65535 < int(port_number) < 1:
                    messages.add_message(request, messages.WARNING, "Invalid Port Number.")
                    invalid_input = 1

            if invalid_input:
                return render(request, 'Firewalls-R-Us/firewall_rule_creation_editing.html', )

            # If firewall is enabled
            if ufwFunctions.enableFirewall() == 0:
                # Creation possible
                if ufwFunctions.createRule(permission, protocol, from_ip, to_ip, port_number) == 0:
                    messages.add_message(request, messages.SUCCESS, "Firewall Rule Successfully Created.")

                    rule = Rule(permission=permission, protocol=protocol, from_ip=from_ip, to_ip=to_ip,
                                port_number=port_number)
                    rule.save()
                    # Queries all the objects in order to post to page
                    rules = Rule.objects.all()
                    # Saves the rules in context
                    context = {'rules': rules}
                    # returns the render
                    return render(request, 'Firewalls-R-Us/firewall_rule_creation_editing.html')
                # Rule unable to be created
                else:
                    messages.add_message(request, messages.ERROR, "Failed To Create Firewall Rule")
                    return render(request, 'Firewalls-R-Us/firewall_rule_creation_editing.html')
            # Firewall is not enabled
            else:
                messages.add_message(request, messages.WARNING, "Firewall is not enabled.")
                return render(request, 'Firewalls-R-Us/firewall_rule_creation_editing.html', )
        else:
            messages.add_message(request, messages.WARNING, "Missing Input.")
            return render(request, 'Firewalls-R-Us/firewall_rule_creation_editing.html', )


def delete_rule(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        # command to delete rule to UFW
        id = request.GET.get("id")
        permission = request.GET.get("permission")
        protocol = request.GET.get("protocol")
        from_ip = request.GET.get("from_ip")
        to_ip = request.GET.get("to_ip")
        port_number = request.GET.get("port_number")
        permission = permission.lower()
        protocol = protocol.lower()

        ret = ufwFunctions.deleteRule(permission, protocol, to_ip, from_ip, port_number)

        if ret == 0:
            rule = Rule.objects.get(pk=id).delete()  # , port_number='port_number'
            print("if rule deleted = " + str(rule))
            rules = Rule.objects.all()
            context = {'rules': rules}
            return render(request, 'Firewalls-R-Us/viewrules.html', context)
        else:
            print("else")
            rules = Rule.objects.all()
            context = {'rules': rules}
            return render(request, 'Firewalls-R-Us/viewrules.html', context)


def edit_rule(request):
    return redirect(to='user-login')


def disable_rule(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


# Thinking of adding a if stmt on if firewall is enabled or not.
def view_rules(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        # print ( "View Rule" )
        rules = Rule.objects.all()
        context = {'rules': rules}
        return render(request, 'Firewalls-R-Us/viewrules.html', context)


def import_rules(request):
    return redirect(to='user-login')


def export_rules(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


def view_users(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        users = Profile.objects.all()
        context = {'profiles': users}
        return render(request, 'Firewalls-R-Us/user_management.html', context)


def search_users(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


def register_user(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


def create_user(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    
    if request.method == 'GET':
        return render(request, 'Firewalls-R-Us/user_creation_editing.html', )
    
    else:
        invalid_input = 0
        
        if (request.POST.get("Active") == 'on'):
            active_bool = True
        else:
            active_bool = False
        
        is_active = active_bool
        username = request.POST.get("User_ID") 
        if username == None or username == "":
            messages.add_message(request, messages.WARNING, "Username Field can not be empty." )
            invalid_input = 1
            return render(request, 'Firewalls-R-Us/user_creation_editing.html', )               

        email = request.POST.get("Email")
        password = request.POST.get("Password")            
        if password == None or password == "":
            messages.add_message(request, messages.WARNING, "Password field can not be empty.")
            invalid_input = 1
            return render(request, 'Firewalls-R-Us/user_creation_editing.html', )            

        phone_num = request.POST.get("Phone")        
        if invalid_input != 1:
            phone_num = "+" + phone_num
            newUsername = request.POST.get("User_ID")
            newProfileUser = User.objects.get(username=newUsername)
            newProfile = Profile.objects.get(user=newProfileUser)
            newProfile.phone_number = phone_num
            newProfile.save()
            profiles = Profile.objects.all()
            # print(profile.user.username)
            context = {'profiles': profiles}
            return render(request, 'Firewalls-R-Us/user_management.html', context )		        

def delete_user(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


def edit_user(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


def disable_user(request):
    return redirect(to='user-login')


def docs(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        return redirect(to='user-login')


def index(request):
    return redirect(to='user-login')


def login_firewall(request):
    if request.method == 'POST':
        username = request.POST['Username']
        password = request.POST['Password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect(to='firewall-dashboard')
        else:
            return render(request, 'Firewalls-R-Us/login.html')
    else:
        return render(request, 'Firewalls-R-Us/login.html')


def logout_firewall(request):
    if not request.user.is_authenticated:
        return redirect(to='user-login')
    else:
        logout(request)
        return redirect(to='user-login')


def recover_password(request):
    return redirect(to='user-login')
