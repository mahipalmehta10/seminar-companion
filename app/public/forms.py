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
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

class EventForm(FlaskForm):
    # event_banner = FileField('Event Banner', validators=[InputRequired()])
    # event_date = DateField('Event Date', format='%Y-%m-%d', validators=[InputRequired()])
    # event_location = StringField('Event Location', validators=[InputRequired()])
    # event_duration = IntegerField('Event Duration (in days)', validators=[InputRequired()])

    def validate_event_banner(self, field):
        if not field.data or not field.data.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            raise ValidationError('Only PNG, JPG, and JPEG files are allowed.')

@app.route('/', methods=['GET', 'POST'])
def event_form():
    form = EventForm()
    if form.validate_on_submit():
        # Save the uploaded event banner file to a folder named 'uploads'
        file_path = os.path.join('uploads', form.event_banner.data.filename)
        form.event_banner.data.save(file_path)
        
        # Get the form data and create an event object
        organization = form.organization.data
        event_name = form.event_name.data
        event_banner = file_path
        event_date = form.event_date.data
        event_location = form.event_location.data
        event_duration = form.event_duration.data

        # Process the event object (e.g., save to database, send email, etc.)
        # ...

        # Redirect to a success page
        return redirect(url_for('success'))

    return render_template('event_form.html', form=form)

@app.route('/success')
def success():
    return 'Event registration successful!'

if __name__ == '__main__':
    app.run(debug=True)
