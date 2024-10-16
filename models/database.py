from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, FloatField, SelectField
from wtforms.validators import DataRequired, NumberRange
from datetime import datetime
from flask_login import UserMixin
from flask import session


db = SQLAlchemy()

# User table with roles and login integration
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    role = db.Column(db.String(20), nullable=False)  # Can be 'admin', 'staff', or 'guest'

    def __repr__(self):
        return f'<User {self.username}>'

# Inventory table for tracking jewelry items
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_per_unit = db.Column(db.Float, nullable=False)
    price_per_gram = db.Column(db.Float, nullable=True)
    karat = db.Column(db.String(20), nullable=False)
    gold_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)  # Weight of the item in grams
    size = db.Column(db.String(20), nullable=False)
    barcode = db.Column(db.String(50), unique=True, nullable=False)
    image_url = db.Column(db.String(200))  # URL for product image

    def calculate_price_per_unit(self):
        """Calculate price per unit based on weight and price per gram."""
        gold_prices = session.get('gold_prices', {})
        if self.gold_type == 'Chinese Gold' and self.karat == '18K':
            return gold_prices.get('chinese_18k', 0) * self.weight
        elif self.gold_type == 'Chinese Gold' and self.karat == '21K':
            return gold_prices.get('chinese_21k', 0) * self.weight
        elif self.gold_type == 'Saudi Gold' and self.karat == '18K':
            return gold_prices.get('saudi_18k', 0) * self.weight
        elif self.gold_type == 'Saudi Gold' and self.karat == '21K':
            return gold_prices.get('saudi_21k', 0) * self.weight
        else:
            return 0

    def __repr__(self):
        return f"<Inventory {self.product_name}>"


# SoldProduct table for tracking sold items
class SoldProduct(db.Model):
    __tablename__ = 'sold_product'

    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    quantity_sold = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    date_sold = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    karat = db.Column(db.String(20), nullable=False)
    gold_type = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)  # Add this line
    size = db.Column(db.String(20), nullable=True, default='N/A')
    barcode = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<SoldProduct {self.product_name}>"  # Set nullable=True and provide default value

    def __repr__(self):
        return f"<SoldProduct {self.product_name}>"

# Expense table for tracking business expenses
class Expense(db.Model):
    __tablename__ = 'expense'

    id = db.Column(db.Integer, primary_key=True)
    supplier = db.Column(db.String(100), nullable=False)
    price_per_gram = db.Column(db.Float, nullable=False)
    total_weight = db.Column(db.Float, nullable=False)
    time_bought = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_price = db.Column(db.Float, nullable=False)  # Store calculated total price

    def __repr__(self):
        return f"<Expense {self.supplier}>"
