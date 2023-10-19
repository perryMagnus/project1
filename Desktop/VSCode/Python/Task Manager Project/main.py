from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, EmailField, SubmitField, DateField, BooleanField, DateTimeLocalField, HiddenField
from wtforms.validators import DataRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import login_user, logout_user, login_required, UserMixin, LoginManager, current_user
from datetime import datetime, timedelta
import sqlalchemy.exc


# APP
app = Flask(__name__)



# SESSION
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes = 5)



# CSRF
csrf = CSRFProtect(app)
app.config["SECRET_KEY"] = "grubasek1"



# DATABASE CLASS OBJECT AND APP.CONFIG MYSQL CONNECTION
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://perry:grubasek1@127.0.0.1:3306/schema"
db = SQLAlchemy(app)



# BCRYPT CLASS OBJECT
bcrypt = Bcrypt(app)


# LOGIN MANAGER CLASS OBJECT
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=365)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# FORM CLASSES
class LoginForm(FlaskForm):
    """LOGIN FORM CLASS - IS SERVING A PURPOSE OF CREATING HTML FORMS TO PROVIDE
    USER'S LOG IN INFORMATION TO THE SERVER"""

    username = StringField(render_kw={"placeholder":"username"}, validators=[DataRequired(), Length(min = 4, max = 30)])
    password = PasswordField(render_kw={"placeholder":"password"}, validators=[DataRequired(), Length(min = 8, max = 60)])

    remember_me = BooleanField("Zapamiętaj mnie")

    submit_login = SubmitField("Zaloguj się")
    submit_register = SubmitField("Zarejestruj się")



# REGISTER FORM CLASS
class RegisterForm(FlaskForm):
    """REGISTER FORM CLASS - IS SERVING A PURPOSE OF CREATING HTML FORMS TO PROVIDE
    POSSIBILITY OF REGISTERING ON A TaskManager WebApp FOR NEW USERS"""

    username = StringField(render_kw={"placeholder":"username"}, validators=[DataRequired(), Length(min = 4, max = 30)])
    password = PasswordField(render_kw={"placeholder":"password"}, validators=[DataRequired(), Length(min = 8, max = 60)])
    email = EmailField(render_kw={"placeholder":"e-mail"}, validators=[DataRequired(), Email()])
    date_of_birth = DateField("Date of birth", validators=[DataRequired()])

    submit = SubmitField("Zarejestruj się")

# ADD A TASK FORM CLASS
class Add_a_TaskForm(FlaskForm):
    title = StringField(render_kw={"placeholder":"title"}, validators=[DataRequired(), Length(max=100)])
    description = StringField(render_kw={"placeholder":"description"}, validators=[DataRequired(), Length(max=3000)])
    deadline = DateTimeLocalField("Deadline", format='%Y-%m-%dT%H:%M')

    submit = SubmitField("Zapisz")

# REDIRECT AUTOMATIC LOG OUT FORM CLASS
class RedirectForm(FlaskForm):
    redirect = SubmitField("Przenieś mnie")
    add_a_task = SubmitField("Dodaj zadanie")

# DATABASE TABLE "USERS"
class User(UserMixin, db.Model):
    """DATABASE USED TO STORE USER'S INFORMATION ON THE SERVER"""

    __tablename__ = "users"

    # COLUMNS IN THE DATABASE
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)

    username = db.Column(db.String(30), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False)
    email = db.Column(db.String, unique = True, nullable = False)
    date_of_birth = db.Column(db.Date, nullable = False)
    active = db.Column(db.Boolean, default = False)

    tasks = db.relationship("Task", back_populates = "user")

    def is_anonymous(self):
        return True if self.id is None else False
    
    def is_authenticated(self):
        return True if self.id is not None else False
    
    def is_active(self):
        return self.active

    def get(id):
        return str(id)
    
    def create_task(self, title, description, deadline):
        if self.session_expired():
            return redirect(url_for('automatic_log_out_page'))
        
        new_task = Task(user_id = current_user.id,
                        title = title,
                        description = description,
                        deadline = deadline)
        
        try:
            db.session.add(new_task)
            db.session.commit()

            print("Task added succesfully.")
            
        except sqlalchemy.exc.SQLAlchemyError as e:
            print(f"Error type: {e}.")
            flash("Error met! Please try again.")
    
    def session_expired(self):
        last_activity_time = session.get('last_activity_time')
        if last_activity_time is not None:
            expiration_time = last_activity_time + timedelta(minutes=5)
            current_time = datetime.now()
            if current_time > expiration_time:
                return True
        return False

# DATABASE TABLE "TASKS"
class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key = True, autoincrement = True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    title = db.Column(db.String(100), nullable = False)
    description = db.Column(db.String(3000), nullable = False)
    deadline = db.Column(db.DateTime)

    user = db.relationship("User", back_populates = "tasks")



# "/", "/login" ROUTE
@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login_page() -> str:
    """LOG IN PAGE - PROVIDES: POSSIBILITY OF LOG IN, VERIFYING THE INFORMATION IN DB, RETURNS AN OUTPUT INFORMATION"""

    form = LoginForm()

    if form.validate_on_submit():
        if form.submit_login.data:
            user = User.query.filter_by(username = form.username.data).first()

            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember = form.remember_me.data)
                user.active = True
                db.session.commit()
                return redirect("/wall") 
                
        elif form.submit_register.data:
            return redirect("/register")
        
    elif current_user.is_authenticated:
        return redirect(url_for("wall_page"))

    return render_template("login.html",
                           title = "Zaloguj się do TaskManager",
                           form = form)
    

# REGISTER ROUTE
@app.route("/register", methods=["GET", "POST"])
def register_page() -> str:
    """REGISTER PAGE - PROVIDES POSSIBILITY OF REGISTERING AND SAVES THE DATA IN DATABASE, REDIRECTS TO /MAIN"""

    form = RegisterForm()

    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data)

            new_user = User(username = form.username.data,
                          password = hashed_password,
                          email = form.email.data,
                          date_of_birth = form.date_of_birth.data)
            
            db.session.add(new_user)
            db.session.commit()

            print(f'Success! Data of user: "{form.username.data}" saved in the database.')

            return redirect("/login")

        except sqlalchemy.exc.SQLAlchemyError as e:
            print(f"Something gone wrong! Error: {e}")
            db.session.rollback()

    return render_template("register.html",
                           title = "Zarejestruj się do TaskManager",
                           form = form)

# MAIN WALL PAGE ROUTE
@login_required
@app.route("/wall", methods=["GET", "POST"])
def wall_page() -> str:
    """MAIN WALL OF THE WEBAPP. ALLOWS USERS TO SEE AND INTERACT WITH THE TASKS
    THEY SAVED ON OUR WEB APPLICATION."""
    form = RedirectForm()


    if form.validate_on_submit():
        return redirect(url_for("add_a_task_page"))

    task = Task.query.filter_by(user_id = current_user.id).all()

    return render_template("wall.html",
                            title = "Strona Główna TaskManager WebApp",
                            form = form,
                            task = task)

@login_required
@app.route("/add_a_task", methods=["GET", "POST"])
def add_a_task_page() -> str:
    form = Add_a_TaskForm()

    if form.validate_on_submit():
        user = User()
        user.create_task(title = form.title.data,
                         description = form.description.data,
                         deadline = form.deadline.data)
        
        return redirect(url_for("wall_page"))
    


    return render_template("add_a_task.html",
                           title = "Dodaj zadanie.",
                           form = form)

# DELETE TASK PAGE
@app.route("/delete_task/<int:task_id>", methods=["POST"])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task:
        db.session.delete(task)
        db.session.commit()
    return redirect('/')

# EDIT TASK PAGE
@app.route("/edit_task/<int:task_id>", methods=["POST"])
def edit_task(task_id):
    form = Add_a_TaskForm()
    task = Task.query.get(task_id)

    if task: 

        print("Task found.")

        if form.submit.data:
            print("Data submitted.")

            task.title = form.title.data
            task.description = form.description.data
            task.deadline = form.deadline.data
        
            db.session.commit() 

            print(f"Task: {task_id} updated in the database!")

            return redirect("/wall")

    return render_template("edit_task.html",
                           form = form,
                           t = task)
        

# AUTOMATIC LOG OUT PAGE
@app.route("/automatic_log_out", methods=["GET", "POST"])
def automatic_log_out_page() -> str:
    form = RedirectForm()

    if form.validate_on_submit():
        return redirect(url_for("login_page"))

    return render_template("automatic_log_out.html",
                           title = "Wylogowano Cię z powodu braku aktywności.",
                           form = form)


# AUTOMATIC LOG OUT AFTER 900 (15 min) SECONDS OF NO ACTIVITIES
@app.before_request
def check_session_expiry():
    if current_user.is_authenticated:
        if current_user.session_expired():
            logout_user()
            return redirect(url_for('automatic_log_out_page'))





if __name__ == "__main__":
    app.run()


