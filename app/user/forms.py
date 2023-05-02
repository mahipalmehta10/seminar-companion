# -*- coding: utf-8 -*-
"""User forms."""
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField,DateField,FileField,IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired

from .models import User


class RegisterForm(FlaskForm):
    """Register form."""

    username = StringField( "Username", validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(min=6, max=40)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=40)])
    confirm = PasswordField("Verify password",[DataRequired(), EqualTo("password", message="Passwords must match")],)
    event_name = StringField("Eventname", validators=[InputRequired(), Length(min=3, max=25)])
    organization_name = StringField("organization name", validators=[InputRequired(), Length(min=3, max=25)] )
    event_banner = FileField( "eventbanner", validators=[InputRequired(), Length(min=3, max=25)] )
    event_date = DateField("eventdate", validators=[InputRequired(), Length(min=3, max=10)])    
    event_location = StringField("eventdate", validators=[InputRequired(), Length(min=3, max=30)])    
    event_duration = IntegerField("eventdate", validators=[InputRequired(), Length(min=1, max=6)])   
    seminar_name=StringField( "seminar name", validators=[DataRequired(), Length(min=3, max=25)])
    seminar_topic=StringField( "topic ", validators=[DataRequired(), Length(min=3, max=25)])
    seminar_speaker=StringField( "speaker ", validators=[DataRequired(), Length(min=3, max=25)])
    seminar_description=StringField( "description ", validators=[DataRequired(), Length(min=3, max=25)])
    seminar_notes=FileField( "notes ", validators=[DataRequired(), Length(min=3, max=25)])
    profile_image=FileField( "eventbanner", validators=[InputRequired(), Length(min=3, max=25)] )


    def __init__(self, *args, **kwargs):
        """Create instance."""
        super(RegisterForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self):
        """Validate the form."""
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered")
            return False
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            self.email.errors.append("Email already registered")
            return False
        return

