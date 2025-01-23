from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Mnopk13579@localhost:5432/course-project'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

users = []


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Successful login
            return redirect(url_for('index'))

        # If login fails, redirect back to the login page
        return redirect(url_for('login'))

    return render_template('login.html', form=form)


# Render different pages
@app.route('/')
def index():
    return render_template('index.html')


class Article(db.Model):
    __tablename__ = 'reviews'  # Specify the table name
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)


# Route to display reviews
@app.route('/news', methods=['GET', 'POST'])
def display_news():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        if search_query:
            found_article = Article.query.filter(Article.title.ilike(f"%{search_query}%")).first()
            if found_article:
                return redirect(found_article.url)
            else:
                return "No matching article found"
    articles = Article.query.all()
    return render_template('news.html', reviews=articles)


class NewsArticle(db.Model):
    __tablename__ = 'news'  # Specify the table name
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)


@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    if request.method == 'POST':
        search_query = request.form['search_query']
        reviews = NewsArticle.query.filter(NewsArticle.title.ilike(f'%{search_query}%')).all()
    else:
        reviews = NewsArticle.query.all()

    return render_template('reviews.html', reviews=reviews)


@app.route('/about')
def about():
    return render_template('aboutus.html')


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)



    def __repr__(self):
        return f'<Comment {self.id}>'


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']




        user_id = 1

        # Create a new Comment object and add it to the database
        new_comment = Comment(user_id=user_id, comment=message)
        db.session.add(new_comment)
        db.session.commit()

        return render_template('contact_success.html')  # Redirect to a success page or display a success message

    return render_template('contactus.html')  # Render the contact form


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)