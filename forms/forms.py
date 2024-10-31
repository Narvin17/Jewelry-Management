from flask_wtf import FlaskForm
from wtforms import HiddenField, StringField, SelectField, IntegerField, FloatField, FileField, PasswordField, DecimalField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Length
from flask_wtf.file import FileRequired, FileAllowed

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddProductForm(FlaskForm):
    product_name = StringField('Product Name', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Ring', 'Ring'),
        ('Earring', 'Earring'),
        ('Necklace', 'Necklace'),
        ('Pendant', 'Pendant'),
        ('Bracelet', 'Bracelet')
    ], validators=[DataRequired()])
    initial_quantity = IntegerField('Initial Quantity', validators=[DataRequired()])  # Initial stock quantity
    karat = SelectField('Karat', choices=[
        ('18K', '18K'),
        ('21K', '21K'),
    ], validators=[DataRequired()])
    gold_type = SelectField('Gold Type', choices=[
        ('Chinese Gold', 'Chinese Gold'),
        ('Saudi Gold', 'Saudi Gold'),
    ], validators=[DataRequired()])
    weight = FloatField('Weight (Ex: 5.2g)', validators=[DataRequired()])
    size = StringField('Size (Ex: 10 inches/ 10")', validators=[DataRequired()])
    photo = FileField('Product Photo', validators=[
        FileRequired(message='Product photo is required.'),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Only image files are allowed!')
    ])
    submit = SubmitField('Add Product')


class EditProductForm(FlaskForm):
    product_name = StringField('Product Name', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Ring', 'Ring'),
        ('Earring', 'Earring'),
        ('Necklace', 'Necklace'),
        ('Pendant', 'Pendant'),
        ('Bracelet', 'Bracelet')
    ], validators=[DataRequired()])
    initial_quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    price_per_unit = FloatField('Price per Unit', validators=[DataRequired(), NumberRange(min=0)])  # Added field
    karat = SelectField('Karat', choices=[
        ('18K', '18K'),
        ('21K', '21K')
    ], validators=[DataRequired()])
    gold_type = SelectField('Gold Type', choices=[
        ('Chinese Gold', 'Chinese Gold'),
        ('Saudi Gold', 'Saudi Gold')
    ], validators=[DataRequired()])
    weight = FloatField('Weight (grams)', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Update Product')
        
class AddExpenseForm(FlaskForm):
    supplier = StringField('Supplier', validators=[DataRequired()])
    price_per_gram = FloatField('Price per Gram', validators=[DataRequired()])
    total_weight = FloatField('Total Weight', validators=[DataRequired()])
    time_bought = StringField('Time Bought', validators=[DataRequired()])
    submit = SubmitField('Add Expense')

class GoldPricesForm(FlaskForm):
    chinese_18k = DecimalField('Chinese 18K Price per Gram (₱)', validators=[
        DataRequired(message="This field is required."),
        NumberRange(min=0, message="Price must be a positive number.")
    ])
    chinese_21k = DecimalField('Chinese 21K Price per Gram (₱)', validators=[
        DataRequired(message="This field is required."),
        NumberRange(min=0, message="Price must be a positive number.")
    ])
    saudi_18k = DecimalField('Saudi 18K Price per Gram (₱)', validators=[
        DataRequired(message="This field is required."),
        NumberRange(min=0, message="Price must be a positive number.")
    ])
    saudi_21k = DecimalField('Saudi 21K Price per Gram (₱)', validators=[
        DataRequired(message="This field is required."),
        NumberRange(min=0, message="Price must be a positive number.")
    ])
    submit = SubmitField('Update Prices')

class MarkAsSoldForm(FlaskForm):
    product_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Mark as Sold')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('staff', 'Staff'), ('guest', 'Guest')], validators=[DataRequired()])
    submit = SubmitField('Create User')

class GoldPricesForm(FlaskForm):
    chinese_18k = DecimalField('Chinese 18K Price per Gram', validators=[DataRequired()])
    chinese_21k = DecimalField('Chinese 21K Price per Gram', validators=[DataRequired()])
    saudi_18k = DecimalField('Saudi 18K Price per Gram', validators=[DataRequired()])
    saudi_21k = DecimalField('Saudi 21K Price per Gram', validators=[DataRequired()])
    submit = SubmitField('Update Prices')


class MarkAsSoldForm(FlaskForm):
    product_id = HiddenField('Product ID', validators=[DataRequired()])
    customer_name = StringField('Customer Name', validators=[DataRequired(), Length(max=100)])
    sold_by = StringField('Sold By', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Mark as Sold')
    
class CheckoutForm(FlaskForm):
    customer_name = StringField('Customer Name', validators=[DataRequired()])
    sold_by = StringField('Sold By', validators=[DataRequired()])

