import os
from datetime import datetime
from flask import Flask,render_template,redirect,url_for,request,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from forms import LoginForm,RegisterForm
from flask_login import login_user,logout_user,login_required
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask('user',__name__)

# 配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////' + os.path.join(app.root_path,'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # 关闭对模型修改的监控

db = SQLAlchemy(app)

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from flask_wtf.file import FileField, FileAllowed, FileRequired
from app.models import User
from app.extensions import photos


# 用户注册表单
class RegisterForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message='用户名不能为空'), Length(6, 12, message='用户名只能在6~12个字符之间')])
    password = PasswordField('密码', validators=[DataRequired(message='密码不能为空'), Length(6, 20, message='密码只能在6~20个字符之间')])
    confirm = PasswordField('确认密码', validators=[EqualTo('password', message='两次密码不一致')])
    email = StringField('邮箱', validators=[Email(message='无效的邮箱格式')])
    submit = SubmitField('立即注册')

    # 自定义用户名验证器
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已注册，请选用其它名称')

    # 自定义邮箱验证器
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise  ValidationError('该邮箱已注册使用，请选用其它邮箱')


class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(message='no empty')])
    password = PasswordField('password', validators=[DataRequired(message='no empty')])
    remember = BooleanField('remember me')
    submit = SubmitField('login')


# 首页
@app.route('/')
def index():
    return render_template('index.html')


# 用户注册
@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # 根据表单数据创建用户对象
        u = User(username=form.username.data,
                 password=form.password.data,
                 email=form.email.data)
        # 将用户对象保存到数据库
        db.session.add(u)
        # 下面生成token需要用户id，此时还没有id，需要手动提交
        db.session.commit()

        # 提示用户下一步操作
        flash('注册成功')
        # 跳转到指定位置
        return redirect(url_for('main.index'))
    return render_template('user/register.html', form=form)


# 用户登录
@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # 根据用户名查找用户
        u = User.query.filter_by(username=form.username.data).first()
        if not u:
            flash('用户不存在')
        elif u.verify_password(form.password.data):
            # 用户登录，顺便可以完成'记住我'的功能
            login_user(u, remember=form.remember.data)
            flash('登录成功')
            return redirect(request.args.get('next') or url_for('main.index'))
        else:
            flash('无效的密码')
    return render_template('user/login.html', form=form)
































# # 创建数据库模型类
# class User(db.Model,UserMixin):
#     id = db.Column(db.Integer,primary_key=True) # 主键
#     name = db.Column(db.String(20)) 
#     username = db.Column(db.String(20))  # 用户名
#     password_hash = db.Column(db.String(128))  # 密码散列值

#     def set_password(self,password):
#         self.password_hash = generate_password_hash(password)
#     def validate_password(self,password):
#         return check_password_hash(self.password_hash,password)
    
# class Works(db.Model):    # 作品
#     id = db.Column(db.Integer,primary_key=True) # 主键
#     title = db.Column(db.String(60))    # 名称
#     describe = db.Column(db.String(4))     # 描述

# class Photo(db.Model):
# 	__tablename__ = 'photo'
# 	id = db.Column(db.Integer, primary_key=True)
# 	origname = db.Column(db.String(255), unique=False, nullable=False) #原图文件名
# 	showname = db.Column(db.String(255), unique=False, nullable=False) #展示图文件名
# 	thumbname = db.Column(db.String(255), unique=False, nullable=False) #缩略图文件名
# 	album_id = db.Column(db.Integer,db.ForeignKey('album.id'))
# 	addtime = db.Column(db.DATETIME, index=True, default=datetime.now)
 
# 	def __repr__(self):
# 		return '<Photo %r>' % self.id




# # 登录
# @app.route('/login')
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user_name = request.form.get('username', None)
#         password = request.form.get('password', None)
#         user = User(user_name, password)
#         if user.verify_password(password):
#             login_user(user)
#             return redirect(request.args.get('next') or url_for('main'))
#     return render_template('login.html', title="Sign In", form=form)

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))