from flask_wtf import FlaskForm
from wtforms import FileField, PasswordField, SelectField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Optional

class UploadForm(FlaskForm):
    file = FileField('Choisissez un fichier', validators=[DataRequired()])
    password = PasswordField('Mot de passe (optionnel)', validators=[Optional()])
    expiry = SelectField('Durée de validité', choices=[('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois')], validators=[DataRequired()])
    max_downloads = IntegerField('Nombre maximal de téléchargements', validators=[NumberRange(min=1), Optional()])
    submit = SubmitField('Téléverser')
