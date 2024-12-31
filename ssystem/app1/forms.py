from django import forms
from .models import Event, Contestant, Score, User,NowLogin

class LoginForm(forms.Form):
    user_id = forms.CharField(max_length=20, label='用户名或学号')
    password = forms.CharField(widget=forms.PasswordInput, label='密 码')
    captcha = forms.CharField(max_length=5, label='验证码')  # 添加验证码字段


class RegisteForm(forms.Form):
    user_id = forms.CharField(max_length=20, label='学号')
    password = forms.CharField(widget=forms.PasswordInput, label='密 码')
    name=forms.CharField(max_length=20, label='姓名')


class EventForm(forms.ModelForm):
    class Meta:
        model = Event
        fields = ['event_id', 'event_name', 'start_time', 'end_time']

    def clean_name(self):
        event_id = self.cleaned_data.get('event_id')
        if Event.objects.filter(event_id=event_id).exists():
            raise forms.ValidationError("项目编号已存在。")
        return event_id

class ContestantForm(forms.ModelForm):
    class Meta:
        model = Contestant
        fields = ['user', 'event', 'group']

        


