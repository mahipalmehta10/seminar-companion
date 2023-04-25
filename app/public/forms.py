# -*- coding: utf-8 -*-
"""Public forms."""
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField,FileField,DateField,IntegerField
from wtforms.validators import DataRequired,InputRequired

from app.user.models import User


class LoginForm(FlaskForm):
    """Login form."""

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    event_name = StringField('Event Name', validators=[InputRequired()])
    organization = StringField('Organization', validators=[InputRequired()])
    event_banner = FileField('Event Banner', validators=[InputRequired()])
    event_date = DateField('Event Date', format='%Y-%m-%d', validators=[InputRequired()])
    event_location = StringField('Event Location', validators=[InputRequired()])
    event_duration = IntegerField('Event Duration (in days)', validators=[InputRequired()]) 
    seminar_name=StringField("Seminar Name", validators=[DataRequired()])
    seminar_topic=StringField("Seminar Topic", validators=[DataRequired()])
    seminar_speaker=StringField("Speaker Info", validators=[DataRequired()])
    seminar_notes=FileField("notes", validators=[DataRequired()])
    seminar_description=StringField("description",validators=[InputRequired()])


    def __init__(self, *args, **kwargs):
        """Create instance."""
        super(LoginForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self):
        """Validate the form."""
        initial_validation = super(LoginForm, self).validate()
        if not initial_validation:
            return False

        self.user = User.query.filter_by(username=self.username.data).first()
        if not self.user:
            self.username.errors.append("Unknown username")
            return False

        if not self.user.check_password(self.password.data):
            self.password.errors.append("Invalid password")
            return False

        if not self.user.active:
            self.username.errors.append("User not activated")
            return False
        return True


from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, IntegerField, FileField
from wtforms.validators import InputRequired, ValidationError

class EventForm(FlaskForm):
     event_banner = FileField('Event Banner', validators=[InputRequired()])
    
class SeminarForm(FlaskForm):
    ()
