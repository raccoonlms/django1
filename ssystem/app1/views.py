from django.shortcuts import render, redirect
from .models import User, Event, Contestant, Score, NowLogin
from .forms import LoginForm, EventForm, ContestantForm, RegisteForm
from django.http import HttpResponse
from random import randint, choice
from PIL import Image, ImageDraw, ImageFont
from django.http import FileResponse
from django.http import HttpRequest
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.utils import timezone
from .models import NowLogin, User
from .forms import LoginForm


def record_login(user_ip, user_id, success=True):
    """记录登录信息，确保每个 IP 地址只能对应一个 login，并记录时间和登录状态"""
    # 使用 update_or_create 来确保 IP 地址对应的记录只有一个
    NowLogin.objects.update_or_create(
        ip=user_ip,
        defaults={
            'login': user_id,
            'login_time': timezone.now(),
            'success': success
        }
    )


def login(request: HttpRequest):
    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():
            # 获取表单提交的数据
            user_id = form.cleaned_data['user_id']
            password = form.cleaned_data['password']
            captcha = form.cleaned_data['captcha']  # 获取用户输入的验证码

            # 验证验证码是否正确
            if captcha != request.session.get('randomcode', ''):
                return render(request, 'login.html', {'form': form, 'error': '验证码错误'})

            # 获取用户的IP地址
            user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]

            # 首先检查是否为管理员账户
            if user_id == 'admin' and password == 'admin':
                # 记录登录信息（包括IP、登录时间和登录状态）
                record_login(user_ip, 'admin', success=True)
                return redirect('admin_dashboard')
            # 检查是否为普通用户
            try:
                user = User.objects.get(user_id=user_id, password=password)
                # 用户验证成功，登录后重定向到用户仪表板
                request.session['user_id'] = user.user_id
                request.session['password'] = user.password
                record_login(user_ip, user.user_id, success=True)
                return redirect('user_dashboard')
            except User.DoesNotExist:
                # 如果用户验证失败，记录失败的登录信息
                record_login(user_ip, '未登录成功', success=False)
                return render(request, 'login.html', {'form': form, 'error': '用户名或密码错误'})
    else:
        form = LoginForm()

    # 渲染登录页面
    return render(request, 'login.html', {'form': form})


# 验证码随机字符
def getRandomChar():
    num = str(randint(0, 9))
    lower = chr(randint(97, 122))
    upper = chr(randint(65, 90))
    char = choice([num, lower, upper])
    return char


# 创建验证码图片
def createImg(request):
    img = Image.new(mode="RGB", size=(150, 20), color=(30, 144, 255))
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    code = ''
    for i in range(5):
        c = getRandomChar()
        draw.text((10 + 30 * i, 2), text=c, fill=(0, 0, 0), font=font)
        code += c
    request.session['randomcode'] = code
    f = open("test.png", 'wb')
    img.save(f, format="png")
    f.close()
    return FileResponse(open("test.png", 'rb'))


# 注册界面
def register(request):
    if request.method == 'POST':
        form = RegisteForm(request.POST)
        if form.is_valid():
            # 获取表单数据
            user_id = form.cleaned_data['user_id']
            password = form.cleaned_data['password']
            name = form.cleaned_data['name']

            # 创建新用户并保存到数据库
            if User.objects.filter(user_id=user_id).exists():
                # 如果用户名重复，则显示错误信息
                return render(request, 'register.html', {'form': form, 'error': '注册失败用户名重复'})
            else:
                new_user = User(user_id=user_id, password=password, name=name)
                new_user.save()
            # 注册成功后重定向到登录页面或其他页面
            return render(request, 'register.html', {'form': form, 'error': '注册成功'})
    else:
        form = RegisteForm()

    # 渲染注册页面
    return render(request, 'register.html', {'form': form, 'error': None})


# 密码修改
from django.contrib.auth.hashers import check_password, make_password
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User, NowLogin


def change_password(request):
    response = checkloginuser(request)
    if response:
        return response

    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # 获取登录用户的IP地址
        user_ip = request.META.get('REMOTE_ADDR')

        login_record = NowLogin.objects.get(ip=user_ip)
        user_id = login_record.login
        user = User.objects.get(user_id=user_id)
        # 验证旧密码是否正确
        if old_password == User.objects.get(user_id=user_id, password=old_password):  # 使用 check_password 进行比较
            messages.error(request, "旧密码不正确。")
            return redirect('change_password')

        # 检查新密码和确认密码是否匹配
        if new_password != confirm_password:
            messages.error(request, "新密码与确认密码不匹配。")
            return redirect('change_password')

        # 验证新密码的有效性（例如：最小长度检查）
        if len(new_password) < 8:
            messages.error(request, "密码长度必须至少为8个字符。")
            return redirect('change_password')

        # 如果所有检查通过，更新密码
        user.password = new_password  # 使用 make_password 安全地加密新密码
        user.save()
        messages.success(request, "密码修改成功。")
        return redirect('login')  # 重定向到登录页面

    return render(request, 'change_password.html')  # 渲染修改密码的页面


from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpRequest
from .models import NowLogin


def logout(request: HttpRequest):
    # 获取用户的IP地址
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]

    # 记录退出登录的信息，设置success为False
    user_id = request.session.get('user_id', '')
    if user_id:
        # 记录退出登录信息
        record_login(user_ip, user_id, success=False)

    # 清除会话信息，退出登录
    request.session.flush()  # 清除所有会话数据

    # 提示用户成功退出
    messages.success(request, "您已成功退出登录。")

    # 重定向到登录页面
    return redirect('login')


# 登录检查管理员
def checklogin(request):
    # 获取当前用户的IP地址
    ip_address = request.META.get('REMOTE_ADDR')

    # 检查当前IP是否已登录admin
    admin_logged_in = NowLogin.objects.filter(ip=ip_address, login='admin', success=True).exists()

    if not admin_logged_in:
        # 如果未登录admin，则返回登录界面
        return redirect('login')
    return None


# 管理界面
def admin_dashboard(request):
    response = checklogin(request)
    if response:
        return response
    return render(request, 'admin_dashboard.html')


from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import Event, NowLogin


# 查询比赛项目

def query_competition(request):
    # 获取查询条件，如果为空则不进行过滤
    event_id = request.GET.get('event_id', '')
    event_name = request.GET.get('event_name', '')

    # 默认查询所有数据
    events = Event.objects.all()

    # 如果有查询条件，过滤数据
    if event_id:
        events = events.filter(event_id=event_id)
    if event_name:
        events = events.filter(event_name__icontains=event_name)

    # 设置分页
    paginator = Paginator(events, 10)  # 每页显示 10 条记录
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number)  # 获取当前页的分页对象

    # 传递分页对象和其他数据到模板
    return render(request, 'add_competition.html', {
        'page_obj': page_obj,
        'event_id': event_id,
        'event_name': event_name
    })


# 增加比赛项目

def add_competition(request):
    response = checklogin(request)
    if response:
        return response

    if request.method == "POST":
        form = EventForm(request.POST)
        if form.is_valid():
            event_id = form.cleaned_data['event_id']
            # 创建新用户并保存到数据库
            if Event.objects.filter(event_id=event_id).exists():
                # 如果用户名重复，则显示错误信息
                return render(request, 'add_competition.html', {'form': form, 'error': '注册失败项目编号重复'})
            else:
                form.save()
            return redirect('query_competition')  # 增加成功后跳转到查询页面
        else:
            return render(request, 'add_competition.html', {'form': form, 'error': "请确保输入项有效且唯一"})
    else:
        form = EventForm()

    # 直接查询所有比赛项目
    events = Event.objects.all()
    paginator = Paginator(events, 10)  # 每页显示 10 条记录
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number)  # 获取当前页的分页对象

    return render(request, 'add_competition.html', {'form': form, 'events': page_obj})


# 删除比赛项目
def delete_competition(request):
    if request.method == "POST":
        event_id = request.POST.get('event_id')
        event_name = request.POST.get('event_name')

        # 根据项目编号或描述删除项目
        if event_id:
            Event.objects.filter(event_id=event_id).delete()
        elif event_name:
            Event.objects.filter(event_name=event_name).delete()

        return redirect('query_competition')  # 删除后跳转到查询页面


from django.shortcuts import redirect
from .models import Event


# 批量删除比赛项目
def delete_selected_competitions(request):
    if request.method == "POST":
        # 获取选中的事件 ID 列表
        selected_events = request.POST.getlist('selected_events')

        # 删除选中的比赛项目
        if selected_events:
            Event.objects.filter(id__in=selected_events).delete()

    # 删除后重定向到当前页面
    return redirect('query_competition')


'''------------------------------------------------'''

from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from .models import Contestant, User, Event
from .forms import ContestantForm


# 查询参赛信息
def query_participation(request):
    # 获取查询条件，如果为空则不进行过滤
    user_id = request.GET.get('user_id', '')
    event_id = request.GET.get('event_id', '')

    # 默认查询所有参赛信息
    contestants = Contestant.objects.all()

    # 如果有查询条件，过滤数据
    if user_id:
        contestants = contestants.filter(user__user_id=user_id)
    if event_id:
        contestants = contestants.filter(event__event_id=event_id)

    # 获取所有用户和比赛项目
    users = User.objects.all()
    events = Event.objects.all()

    # 设置分页
    paginator = Paginator(contestants, 10)  # 每页显示 10 条记录
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number)  # 获取当前页的分页对象

    # 传递分页对象、用户、项目和其他数据到模板
    return render(request, 'add_participation.html', {
        'page_obj': page_obj,
        'user_id': user_id,
        'event_id': event_id,
        'users': users,  # 传递用户数据
        'events': events  # 传递项目数据
    })


# 增加参赛信息
def add_participation(request):
    response = checklogin(request)
    if response:
        return response

    if request.method == "POST":
        user_id = request.POST.get('user_id')
        event_id = request.POST.get('event_id')
        group = request.POST.get('group')

        # 检查学号是否存在
        try:
            user = User.objects.get(user_id=user_id)
        except User.DoesNotExist:

            return render(request, 'add_participation.html', {'error': '学号不存在'})

        # 检查项目编号是否存在
        try:
            event = Event.objects.get(event_id=event_id)
        except Event.DoesNotExist:
            return render(request, 'add_participation.html', {'error': '项目编号不存在'})

        # 检查是否已有相同的参赛记录（即相同的学号和项目编号）
        if Contestant.objects.filter(user=user, event=event).exists():
            return render(request, 'add_participation.html', {'error': '该学号已经参加了此项目的比赛'})

        # 如果没有重复，创建新的参赛信息
        Contestant.objects.create(user=user, event=event, group=group)

        return redirect('query_participation')  # 成功后跳转到查询页面

    # 获取所有用户和比赛项目
    users = User.objects.all()
    events = Event.objects.all()

    return render(request, 'add_participation.html', {'users': users, 'events': events})


# 删除参赛信息
def delete_participation(request):
    if request.method == "POST":
        contestant_id = request.POST.get('contestant_id')
        if contestant_id:
            Contestant.objects.filter(id=contestant_id).delete()

        return redirect('query_participation')  # 删除后跳转到查询页面


# 批量删除参赛信息
def delete_selected_participations(request):
    if request.method == "POST":
        # 获取选中的参赛信息 ID 列表
        selected_participations = request.POST.getlist('selected_participations')

        # 删除选中的参赛信息
        if selected_participations:
            Contestant.objects.filter(id__in=selected_participations).delete()

    # 删除后重定向到当前页面
    return redirect('query_participation')


# ------------------------------------------------------------------------
from django.shortcuts import render, redirect
from .models import Contestant, Score, Event
from django.core.paginator import Paginator
from django.http import Http404


# 查询成绩的视图
def query_scores(request):
    response = checklogin(request)
    if response:
        return response

    event_id = request.GET.get('event_id', '')
    events = Event.objects.all()  # 获取所有项目

    # 默认查询所有参赛者成绩
    contestants = Contestant.objects.all()

    # 如果有选择项目，则按项目过滤
    if event_id:
        contestants = contestants.filter(event__event_id=event_id)

    # 预加载与 Contestant 相关联的 Score 数据
    contestants = contestants.prefetch_related('score_set')

    # 分页
    paginator = Paginator(contestants, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'add_score.html', {
        'page_obj': page_obj,
        'event_id': event_id,
        'events': events,
    })


# 填写成绩
def update_score(request, contestant_id):
    try:
        contestant = Contestant.objects.get(id=contestant_id)
        # 获取或创建成绩对象
        score, created = Score.objects.get_or_create(contestant=contestant)
    except Contestant.DoesNotExist:
        raise Http404("参赛信息未找到")

    if request.method == 'POST':
        score_value = request.POST.get('score')
        rank_value = request.POST.get('rank')

        # 更新成绩和排名
        if score_value:
            score.score = float(score_value)
        if rank_value:
            score.rank = int(rank_value)

        score.save()
        return redirect('query_scores')  # 成功后跳转到查询页面

    return render(request, 'add_score.html', {'contestant': contestant, 'score': score})


'''--------------------------------------------------------'''


# 登录检查用户
def checkloginuser(request):
    # 获取当前用户的IP地址
    ip_address = request.META.get('REMOTE_ADDR')
    user_logged = NowLogin.objects.filter(ip=ip_address).exists()
    # 检查当前IP是否已登录
    user_logged_in = NowLogin.objects.filter(ip=ip_address, success=False).exists()
    if not user_logged:
        return redirect('login')
    if user_logged_in:
        # 如果未登录或登录FOALSE，则返回登录界面
        return redirect('login')
    return None


# 用户界面
from django.shortcuts import render
from .models import NowLogin, User


def user_dashboard(request):
    # 获取当前请求的IP地址
    response = checkloginuser(request)
    if response:
        return response

    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]

    try:
        # 查找与当前IP地址匹配的登录记录
        login_record = NowLogin.objects.get(ip=user_ip)
        user_id = login_record.login  # 获取登录名，即user_id

        # 根据user_id查找对应的用户信息
        user = User.objects.get(user_id=user_id)
        user_name = user.name  # 获取用户名

        # 获取该用户的参赛信息
        contestants = Contestant.objects.filter(user=user)
        event_details = []

        # 获取参赛项目及成绩
        for contestant in contestants:
            event = contestant.event
            score = Score.objects.filter(contestant=contestant).first()  # 获取该参赛者的成绩

            # 如果有成绩，则提取成绩和排名
            event_details.append({
                'event_name': event.event_name,
                'event_id': event.event_id,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'group': contestant.group,
                'score': score.score if score else '未评分',
                'rank': score.rank if score else '未排名'
            })

    except NowLogin.DoesNotExist:
        user_name = None  # 如果没有找到对应的登录记录
        event_details = []
    except User.DoesNotExist:
        user_name = None  # 如果没有找到对应的用户
        event_details = []

    # 将用户名和参赛信息传递到模板
    return render(request, 'user_dashboard.html', {
        'user_name': user_name, 'user': user,
        'event_details': event_details
    })


# 查询比赛项目用户
def user_competition(request):
    response = checkloginuser(request)
    if response:
        return response
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]

    try:
        # 查找与当前IP地址匹配的登录记录
        login_record = NowLogin.objects.get(ip=user_ip)
        user_id = login_record.login  # 获取登录名，即user_id

        # 根据user_id查找对应的用户信息
        user = User.objects.get(user_id=user_id)
        user_name = user.name  # 获取用户名
    except NowLogin.DoesNotExist:
        user_name = None  # 如果没有找到对应的登录记录
    except User.DoesNotExist:
        user_name = None  # 如果没有找到对应的用户
    # 获取查询条件，如果为空则不进行过滤
    event_id = request.GET.get('event_id', '')
    event_name = request.GET.get('event_name', '')

    # 默认查询所有数据
    events = Event.objects.all()

    # 如果有查询条件，过滤数据
    if event_id:
        events = events.filter(event_id=event_id)
    if event_name:
        events = events.filter(event_name__icontains=event_name)

    # 设置分页
    paginator = Paginator(events, 10)  # 每页显示 10 条记录
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number)  # 获取当前页的分页对象

    # 传递分页对象和其他数据到模板
    return render(request, 'user_competition.html', {
        'page_obj': page_obj,
        'event_id': event_id,
        'user':user,
        'user_name': user_name,
        'event_name': event_name
    })


# 查询参赛信息用户
def user_participation(request):
    response = checkloginuser(request)
    if response:
        return response
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]

    try:
        # 查找与当前IP地址匹配的登录记录
        login_record = NowLogin.objects.get(ip=user_ip)
        user_id = login_record.login  # 获取登录名，即user_id

        # 根据user_id查找对应的用户信息
        user = User.objects.get(user_id=user_id)
        user_name = user.name  # 获取用户名
    except NowLogin.DoesNotExist:
        user_name = None  # 如果没有找到对应的登录记录
    except User.DoesNotExist:
        user_name = None  # 如果没有找到对应的用户
    # 获取查询条件，如果为空则不进行过滤
    user_id = request.GET.get('user_id', '')
    event_id = request.GET.get('event_id', '')

    # 默认查询所有参赛信息
    contestants = Contestant.objects.all()

    # 如果有查询条件，过滤数据
    if user_id:
        contestants = contestants.filter(user__user_id=user_id)
    if event_id:
        contestants = contestants.filter(event__event_id=event_id)

    # 获取所有用户和比赛项目
    users = User.objects.all()
    events = Event.objects.all()

    # 设置分页
    paginator = Paginator(contestants, 10)  # 每页显示 10 条记录
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number)  # 获取当前页的分页对象

    # 传递分页对象、用户、项目和其他数据到模板
    return render(request, 'user_participation.html', {
        'page_obj': page_obj,
        'user_id': user_id,
        'event_id': event_id,
        'user_name': user_name,
        'users': users,  # 传递用户数据
        'events': events  # 传递项目数据
    })


# 查询成绩的视图用户
def user_scores(request):
    response = checkloginuser(request)
    if response:
        return response
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]

    try:
        # 查找与当前IP地址匹配的登录记录
        login_record = NowLogin.objects.get(ip=user_ip)
        user_id = login_record.login  # 获取登录名，即user_id

        # 根据user_id查找对应的用户信息
        user = User.objects.get(user_id=user_id)
        user_name = user.name  # 获取用户名
    except NowLogin.DoesNotExist:
        user_name = None  # 如果没有找到对应的登录记录
    except User.DoesNotExist:
        user_name = None  # 如果没有找到对应的用户
    event_id = request.GET.get('event_id', '')
    events = Event.objects.all()  # 获取所有项目

    # 默认查询所有参赛者成绩
    contestants = Contestant.objects.all()

    # 如果有选择项目，则按项目过滤
    if event_id:
        contestants = contestants.filter(event__event_id=event_id)

    # 预加载与 Contestant 相关联的 Score 数据
    contestants = contestants.prefetch_related('score_set')

    # 分页
    paginator = Paginator(contestants, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'user_score.html', {
        'page_obj': page_obj,
        'user_name': user_name,
        'event_id': event_id,
        'events': events,
    })