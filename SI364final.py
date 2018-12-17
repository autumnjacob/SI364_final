import os
import datetime
import re

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


## NASA API

from nasa import apod

api_key = 'rQwnb1AthQTnrLbK21h5QcguSkOHLV62ZT5TD6xR'
os.environ['NASA_API_KEY'] = api_key


## App Config Values

app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hard to guess string from si364'

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/finaljacobau"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)


## LoginManager Configuration

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## Models

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    galleries = db.relationship('PhotosGallery', backref='User')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class PhotosGallery(db.Model):
    __tablename__ = 'galleries'
    id = db.Column(db.Integer, primary_key=True)
    gallery_name = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    photos = db.relationship('Apod', secondary='saved_apods')

class Apod(db.Model):
    __tablename__ = 'apods'
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String())
    title = db.Column(db.String())
    description = db.Column(db.String())
    date = db.Column(db.String())
    galleries = db.relationship('PhotosGallery', secondary='saved_apods')

class SavedApod(db.Model):
    __tablename__ = 'saved_apods'
    id = db.Column(db.Integer, primary_key=True)
    apod_id = db.Column(db.Integer, db.ForeignKey('apods.id'))
    gallery_id = db.Column(db.Integer, db.ForeignKey('galleries.id'))

class ApodComment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(1000))
    apod_id = db.Column(db.Integer, db.ForeignKey('apods.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
## Forms

def validate_date(form, field):
    try:
        datetime.datetime.strptime(field.data, '%Y-%m-%d')
    except ValueError:
        raise ValidationError('Incorrect data format, should be YYYY-MM-DD.')

def validate_name(form, field):
    if not re.match('^[a-zA-Z0-9_]*$', field.data):
        raise ValidationError('Name must not contain special characters.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Registered email.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username has been already taken')

class SearchForm(FlaskForm):
    apod_date = StringField("Please enter the date: ", validators=[Required(), validate_date])
    submit = SubmitField('Search')

class SavePhotoForm(FlaskForm):
    gallery_name = StringField('Please enter the name of the gallery the photo will be associated with: ', validators=[Required(), validate_name])
    comment_text = StringField('You can leave a comment if you want here: ')
    save_photo_submit = SubmitField('Save Photo')

class RemoveGalleriesForm(FlaskForm):
    remove_galleries_submit = SubmitField('Remove all galleries')

## View Functions

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('home'))
        flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('home'))

@app.route('/register', methods=["GET", "POST"])
def register():
  form = RegistrationForm()
  if form.validate_on_submit():
      user = User(email=form.email.data, username=form.username.data, password=form.password.data)
      db.session.add(user)
      db.session.commit()
      flash('You are logged in! Enjoy!')
      login_user(user)
      return redirect(url_for('home'))
  return render_template('register.html', form=form)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/search', methods = ['GET', 'POST'])
def search():
    search_form = SearchForm()
    if search_form.validate_on_submit():
        apod_date = search_form.apod_date.data
        return redirect(url_for('_apod', apod_date=apod_date))
    return render_template('search.html', form=search_form)

@app.route('/apod/<apod_date>', methods = ['GET', 'POST'])
def _apod(apod_date):
    save_form = None
    apod = apod_search(apod_date)
    if apod is None:
        flash('Please enter a valid date so APOD can be found.')
    else:
        save_form = SavePhotoForm()
        if save_form.validate_on_submit():
            gallery_name = save_form.gallery_name.data
            gallery = get_or_create_gallery(gallery_name, photos=[apod])
            comment_text = save_form.comment_text.data
            if comment_text is not None:
                comment = ApodComment(comment=comment_text, apod_id=apod.id, user_id=current_user.id)
                db.session.add(comment)
                db.session.commit()
            flash('Gallery was successfully created!')
    return render_template('pictures.html', pictures=[apod], form=save_form, is_apod=True)

@app.route('/navigate', methods = ['GET', 'POST'])
@login_required
def navigate():
    form = RemoveGalleriesForm()
    if form.validate_on_submit():
        for gallery in current_user.galleries:
            current_user.galleries.remove(gallery)
            db.session.commit()
    galleries = db.session.query(PhotosGallery).filter_by(user_id=current_user.id)
    return render_template('navigate.html', galleries=galleries, form=form)

@app.route('/navigate/<gallery_id>')
@login_required
def explore_gallery(gallery_id):
    for user_gallery in current_user.galleries:
        if user_gallery.id == int(gallery_id):
            return render_template('pictures.html', pictures=user_gallery.photos, is_apod=False)
    else:
        abort(404)

@app.route('/last_comments')
@login_required
def last_comments():
    apod_comments = db.session.query(ApodComment).all()
    comments_chunk_size = 10
    if len(apod_comments) > comments_chunk_size:
        apod_comments = apod_comments[:comments_chunk_size]
    comments = []
    for apod_comment in apod_comments:
        apod = db.session.query(Apod).filter_by(id=apod_comment.apod_id).first()
        user = db.session.query(User).filter_by(id=apod_comment.user_id).first()
        comments.append((apod_comment.comment, apod.title, user.username))
    return render_template("comments.html", comments=comments)


## Helper Functions

def apod_search(apod_date):
    try:
        picture = apod.apod(apod_date)
    except ValueError:
        return None
    else:
        return Apod(image_url=picture.url, title=picture.title, description=picture.explanation,
                    date=apod_date)

def get_or_create_gallery(gallery_name, photos=[]):
    for user_gallery in current_user.galleries:
        if user_gallery.gallery_name == gallery_name:
            user_gallery.photos.extend(photos)
            db.session.commit()
            return user_gallery
    else:
        gallery = PhotosGallery(gallery_name=gallery_name, user_id=current_user.id, photos=photos)
        db.session.add(gallery)
        current_user.galleries.append(gallery)
        db.session.commit()
        print("CREATED")
        return gallery

if __name__ == "__main__":
    db.create_all()
    manager.run()
