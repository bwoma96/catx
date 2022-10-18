from flask import Flask,render_template,flash,redirect,url_for,request
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,PasswordField,BooleanField,ValidationError
from wtforms.validators import DataRequired,EqualTo,Length
from flask_wtf.file import FileField,FileRequired,FileAllowed
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from wtforms.widgets import TextArea
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import date
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_uploads import UploadSet,IMAGES,configure_uploads
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage


app = Flask(__name__)

#users database
app.config['SQLALCHEMY_DATABASE_URI']='c3820655035feb16f0d667dce51cefe565c38472ef47cff25468ea68bc117489@ec2-44-209-24-62.compute-1.amazonaws.com:5432/dc6p0v55kg5ckf
'
app.config['SECRET_KEY']="superscretkey"
db=SQLAlchemy(app)
migrate=Migrate(app,db)


app.config['UPLOADED_PHOTOS_DEST']='uploads'
photos=UploadSet('photos',IMAGES)
configure_uploads(app, photos)

class UploadForm(FlaskForm):
	photos=FileField(
		validators=[
			FileAllowed(photos,'only images are allowed'),
			FileAllowed('File field should not be empty')
		]


	)
	submit=SubmitField('Upload')

@app.route('/uploads/<filename>')
def get_file(filename):
	return send_from_directory(app.config['UPLOADED_PHOTOS_DEST'],filename)

@app.route('/uploadfiles',methods=['GET','POST'])
def upload_images():
	form=UploadForm()
	if form.validate_on_submit():
		filename=photos.save(form.photos.data)
		file_url=url_for('get_file',filename=filename)
	else:
		file_url=None
	return render_template('uploadfiles.html',file_url=file_url,form=form)


#login stuff
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
	return users.query.get(int(user_id))

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
	logout_user()
	return redirect('login')



class Posts(db.Model):
	id= db.Column(db.Integer,primary_key=True)
	title=db.Column(db.String(255))
	content=db.Column(db.Text)
	#author=db.Column(db.String(255))
	date_posted=db.Column(db.DateTime,default=datetime.utcnow)
	slug=db.Column(db.String(255))
	category=db.Column(db.String(255))



	poster_id=db.Column(db.Integer,db.ForeignKey('users.id'))
	comments=db.relationship('comments',backref='post.id')

		

#create a model
class users(db.Model, UserMixin):
	id=db.Column(db.Integer,primary_key=True)
	name=db.Column(db.String(200),nullable=False)
	username=db.Column(db.String(200),nullable=False,unique=True)
	email=db.Column(db.String(120),nullable=False,unique=True)
	date_added=db.Column(db.DateTime,default=datetime.utcnow)
	password_hash=db.Column(db.String(128))
	posts=db.relationship('Posts',backref='poster')
	comments=db.relationship('comments',backref='users.id')

#comment model
class comments(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	text=db.Column(db.String(200),nullable=False)
	date_added=db.Column(db.DateTime,default=datetime.utcnow)
	username=db.Column(db.Integer,db.ForeignKey('users.id'))
	post_id=db.Column(db.Integer,db.ForeignKey('posts.id'))


	

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')
	@password.setter
	def password(self,password):
		self.password_hash=generate_password_hash(password)

	def verify_password(self,password):
		return check_password_hash(self.password_hash,password)	
	#create a string
	def __repr__(self):
		return 'Name %r>' % self.name




class PostForm(FlaskForm):
	title=StringField("Title",validators=[DataRequired()])
	content=StringField("Content",validators=[DataRequired()],widget=TextArea())	
	#author= StringField("Author",validators=[DataRequired()])
	slug= StringField("slug",validators=[DataRequired()])
	category=StringField("category",validators=[DataRequired()])
	submit=SubmitField("Submit")

	


class LoginForm(FlaskForm):
	username=StringField("Whats your username?",validators=[DataRequired()])
	password=PasswordField("Whats your password",validators=[DataRequired()])
	submit=SubmitField("Submit")
		

class UserForm(FlaskForm):
	name=StringField("name",validators=[DataRequired()])
	username=StringField("username",validators=[DataRequired()])
	email=StringField("email",validators=[DataRequired()])
	password_hash=PasswordField('Password',validators=[DataRequired(),EqualTo('password_hash2',message='Passwords must match')])
	password_hash2=PasswordField('Confirm Password',validators=[DataRequired()])
	submit=SubmitField("Submit")



@app.route("/delete_comment/<int:id>")
def delete_comment(id):
	comment=comments.query.get_or_404(id)
	db.session.delete(comment)
	db.session.commit()
	return redirect(url_for("blog"))


@app.route("/create-comment/<post_id>", methods=['POST'])
def create_comment(post_id):
	text=request.form.get('text')

	if not text:
		flash('comment cannot be empty')
	else:
		post=Posts.query.filter_by(id=post_id)
		if post:
			comment=comments(text=text,username=current_user.username,post_id=post_id)
			db.session.add(comment)
			db.session.commit()

		else:
			flash('post does not exist')	


	return redirect(url_for('blog'))


@app.route('/addpost',methods=['GET','POST'])
def addpost():
	form=PostForm()
	if form.validate_on_submit():
		poster=current_user.id
		post=Posts(title=form.title.data,content=form.content.data,poster_id=poster,slug=form.slug.data,category=form.category.data)
		form.title.data=''
		form.content.data=''
		#form.author.data=''
		form.slug.data=''
		form.category.data=''
		db.session.add(post)
		db.session.commit()
		flash("Post submitted succesfully" )	
	return render_template("addpost.html",form=form)		



@app.route("/register",methods=['GET','POST'])
def register():
	name=None
	form=UserForm()
	if form.validate_on_submit():
		user=users.query.filter_by(email=form.email.data).first()
		if user is None:
			#hash password
			hashed_pw=generate_password_hash(form.password_hash.data,"sha256")
			user=users(name=form.name.data,username=form.username.data,email=form.email.data,password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()
		name=form.name.data
		form.name.data=''
		form.email.data=''
		form.username.data=''
		form.password_hash.data=''
		flash("user added successfully")



	our_users=users.query.order_by(users.date_added)
	return render_template("register.html",form=form,name=name,our_users=our_users)

@app.route("/")
def index():
	return render_template("index.html")
@app.route('/blog/<int:id>')
def single(id):
	post=Posts.query.get_or_404(id)
	return render_template("single.html",post=post)



@app.route('/blog/edit/<int:id>',methods=['GET','POST'])
def editpost(id):
	post=Posts.query.get_or_404(id)
	form=PostForm()
	if form.validate_on_submit():
		post.title=form.title.data
		#kpost.author=form.author.data
		post.content=form.content.data
		post.slug=form.slug.data
		post.category=form.category.data
		db.session.add(post)
		db.session.commit()
		return redirect(url_for('blog'))
	form.title.data=post.title
	#form.author.data=post.author
	form.content.data=post.content
	form.slug.data=post.slug
	form.category.data=post.category
	return render_template('editpost.html',form=form)

@app.route('/blog/delete/<int:id>')
def deletepost(id):
	posttodelete=Posts.query.get_or_404(id)
	try:
		db.session.delete(posttodelete)
		db.session.commit()
		posts=Post.query.order_by(Posts.date_posted)
		return redirect("blog.html")
	except:
		posts=Posts.query.order_by(Posts.date_posted)
		return render_template('blog.html',posts=posts)
@app.route('/update/edit/<int:id>',methods=['POST','GET'])
def update(id):
	nametoupdate=users.query.get_or_404(id)
	form=UserForm()
	
	if form.validate_on_submit():
		nametoupdate.name=form.name.data
		nametoupdate.username=form.username.data
		nametoupdate.email=form.email.data
		db.session.add(nametoupdate)
		db.session.commit()
		return render_template('update.html',nametoupdate=nametoupdate,form=form)
	form.name.data=nametoupdate.name
	form.email.data=nametoupdate.email
	form.username.data=nametoupdate.username
	return render_template('update.html',nametoupdate=nametoupdate,form=form)	
		

@app.route('/delete/<int:id>')
def delete(id):
	user_to_delete=users.query.get_or_404(id)
	name=None
	form=UserForm()
	try:
		db.session.delete(user_to_delete)
		db.session.commit()
		
		our_users=users.query.order_by(users.date_added)
		return redirect (url_for('register'))
	except:
	
		our_users=users.query.order_by(users.date_added)
		return redirect (url_for('register'))


@app.route("/about")
def about():
	return render_template("about.html")

@app.route("/contact")
def contact():
	return render_template("contact.html")

@app.route("/blog")
def blog():
	posts=Posts.query.order_by(Posts.date_posted)
	return render_template("blog.html",posts=posts)

@app.route("/dash")
def dash():
	return render_template('dash.html')	

@app.route("/admin")
def admin():
		return redirect(url_for('dash'))		


@app.route('/login',methods=['GET','POST'])
def login():
	form=LoginForm()
	if form.validate_on_submit():
		user=users.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password_hash,form.password.data):
				login_user(user)
				return redirect(url_for('dash'))
			else:
				flash("wrong password")
		else:
			flash("that user doesnt exist..")			
				
	return render_template('login.html',form=form)	


if __name__ == "__main__":
	app.run(debug=True)

	
