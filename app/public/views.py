# -*- coding: utf-8 -*-
"""Public section, including homepage and signup."""
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    
)
import os 
from flask_login import login_required, login_user, logout_user

from app.extensions import login_manager
from app.public.forms import LoginForm
from app.user.forms import RegisterForm
from app.user.models import User
from app.utils import flash_errors
from .forms import EventForm
from .forms import SeminarForm
from .forms import ProfileForm
blueprint = Blueprint("public", __name__, static_folder="../static")


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    return User.get_by_id(int(user_id))


@blueprint.route("/", methods=["GET", "POST"])
def home():
    """Home page."""
    form = LoginForm(request.form)
    current_app.logger.info("Hello from the home page!")
    # Handle logging in
    if request.method == "POST":
        if form.validate_on_submit():
            login_user(form.user)
            flash("You are logged in.", "success")
            redirect_url = request.args.get("next") or url_for("user.members")
            return redirect(redirect_url)
        else:
            flash_errors(form)
    return render_template("public/home.html", form=form)


@blueprint.route("/logout/")
@login_required
def logout():
    """Logout."""
    logout_user()
    flash("You are logged out.", "info")
    return redirect(url_for("public.home"))


@blueprint.route("/register/", methods=["GET", "POST"])
def register():
    """Register new user."""
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        User.create(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            active=True,
        )
        flash("Thank you for registering. You can now log in.", "success")
        return redirect(url_for("public.home"))
    else:
        flash_errors(form)
    return render_template("public/register.html", form=form)


@blueprint.route("/about/")
def about():
    """About page."""
    form = LoginForm(request.form)
    return render_template("public/about.html", form=form)


@blueprint.route("/event/create")
def create_event():
    """event create."""
    form = LoginForm(request.form)
    event_form = EventForm(request.form)

    return render_template("public/event_create.html", form=form, event_form = event_form)

@blueprint.route("/seminar/")
def create_seminar():
    """  seminar information."""
    form = LoginForm(request.form)
    seminar_form = SeminarForm(request.form)

    return render_template("public/seminar.html", form=form, event_form = seminar_form)

@blueprint.route("/profile/")
def create_profile():
    """  profile."""
    form = LoginForm(request.form)
    profile_form = ProfileForm(request.form)

    return render_template("public/profile.html", form=form, event_form =profile_form)


