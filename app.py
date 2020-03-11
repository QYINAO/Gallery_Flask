import os
from datetime import datetime
from flask import Flask,render_template,redirect,url_for,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from forms import LoginForm
from flask_login import login_user,logout_user,login_required
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)

# 配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////' + os.path.join(app.root_path,'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # 关闭对模型修改的监控

db = SQLAlchemy(app)

# 创建数据库模型类
class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True) # 主键
    name = db.Column(db.String(20)) 
    username = db.Column(db.String(20))  # 用户名
    password_hash = db.Column(db.String(128))  # 密码散列值

    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
    def validate_password(self,password):
        return check_password_hash(self.password_hash,password)
    
class Works(db.Model):    # 作品
    id = db.Column(db.Integer,primary_key=True) # 主键
    title = db.Column(db.String(60))    # 名称
    describe = db.Column(db.String(4))     # 描述

class Photo(db.Model):
	__tablename__ = 'photo'
	id = db.Column(db.Integer, primary_key=True)
	origname = db.Column(db.String(255), unique=False, nullable=False) #原图文件名
	showname = db.Column(db.String(255), unique=False, nullable=False) #展示图文件名
	thumbname = db.Column(db.String(255), unique=False, nullable=False) #缩略图文件名
	album_id = db.Column(db.Integer,db.ForeignKey('album.id'))
	addtime = db.Column(db.DATETIME, index=True, default=datetime.now)
 
	def __repr__(self):
		return '<Photo %r>' % self.id


# 首页
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_name = request.form.get('username', None)
        password = request.form.get('password', None)
        user = User(user_name, password)
        if user.verify_password(password):
            login_user(user)
            return redirect(request.args.get('next') or url_for('main'))
    return render_template('login.html', title="Sign In", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))