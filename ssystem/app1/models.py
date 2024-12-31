from django.db import models
from django.utils import timezone

# 用户角色
class User(models.Model):

    user_id = models.CharField(max_length=20, unique=True)
    password = models.CharField(max_length=100)
    # 用户姓名
    name = models.CharField(max_length=100,default=False)
    # 用户加入时间，默认为当前时间
    date_joined = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.user_id

# 比赛项目
class Event(models.Model):
    event_id = models.CharField(max_length=100)
    event_name = models.TextField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def __str__(self):
        return self.event_id

# 参赛者信息
class Contestant(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    group = models.CharField(max_length=50)
    registration_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.user_id} - {self.event.event_id}"

# 成绩表
class Score(models.Model):
    contestant = models.ForeignKey(Contestant, on_delete=models.CASCADE)
    score = models.FloatField(null=True, blank=True)
    rank = models.IntegerField(null=True, blank=True) 

    def __str__(self):
        return f"{self.contestant.user.user_id} - Score"
#登录表
from django.db import models
from django.utils import timezone

class NowLogin(models.Model):
    login = models.CharField(max_length=20, default='0')  # 存储用户登录的 user_id
    ip = models.GenericIPAddressField(default='0')  # 存储用户的IP地址
    login_time = models.DateTimeField(default=timezone.now)  # 手动设置默认时间
    success = models.BooleanField(default=True)  # 是否成功登录

    def __str__(self):
        return f'{self.login} ({self.ip})'

