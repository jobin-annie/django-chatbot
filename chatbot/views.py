from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib import auth
from django.contrib.auth.models import User
import openai
from .models import Chat
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

openai_api_key = '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'
openai.api_key = openai_api_key

def get_gpt_response(message):
    response = openai.ChatCompletion.create(
        model = "gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an helpful assistant."},
            {"role": "user", "content": message},
        ]
    )
    answer =response.choices[0].message.content.strip()
    print(answer)
    return answer


def chatbot(request):
    if request.user.is_authenticated:
        chats = Chat.objects.filter(user=request.user)
    else:
        chats = None

    if request.method == 'POST':
        message = request.POST.get('message')
        response = get_gpt_response(message)
        chat = Chat(user=request.user, message=message, response=response, created_at=timezone.now())
        chat.save()
        return JsonResponse({'message':message, 'response':response})
    return render(request, 'chatbot.html', {'chats': chats, 'user': request.user})


def login(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        print("Entered Username:", username)
        print("Entered Password:", password)

        # Attempt to get the user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user is not None and check_password(password, user.password):
            auth.login(request, user)
            print("User Authenticated:", user.username)
            return redirect('chatbot')
        else:
            error_message = "Invalid username or password"
            return render(request, 'login.html', {'error_message': error_message})
    else:
        return render(request, 'login.html')


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        confirmPassword = request.POST.get('confirmPassword', '').strip()

        if password != confirmPassword:
            error_message = "Passwords don't match"
            return render(request, 'register.html', {'error_message': error_message})

        if username != '' and email != '':
            try:
                hashed_password = make_password(password)
                user = User.objects.create_user(username, email, hashed_password)
                user.save()
                auth.login(request, user)
                print("User Created Successfully:", user.username)
                return redirect('chatbot')
            except Exception as e:
                error_message = f'Error in creating account: {str(e)}'
                return render(request, 'register.html', {'error_message': error_message})
        else:
            error_message = "Invalid form data. Please make sure all fields are filled correctly."
            return render(request, 'register.html', {'error_message': error_message})
    return render(request, 'register.html')



def logout(request):
    auth.logout(request)
    return redirect('login')