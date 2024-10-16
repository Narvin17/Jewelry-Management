from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask import session
from sqlalchemy import Column, Integer, String

db = SQLAlchemy()

class BaseProduct(db.Model):
    __abstract__ = True  # This ensures the class is not created as a separate table
    id = db.Column(db.Integer, primary_key=True)  # Add a primary key here
    product_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    karat = db.Column(db.String(20), nullable=False)
    gold_type = db.Column(db.String(50), nullable=False)
    size = db.Column(db.String(20), nullable=True, default='N/A')
    barcode = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<Product {self.product_name}>"

class Inventory(BaseProduct):
    __tablename__ = 'inventory'

    quantity = db.Column(db.Integer, nullable=False)
    price_per_unit = db.Column(db.Float, nullable=False)
    price_per_gram = db.Column(db.Float, nullable=True)
    image_url = db.Column(db.String(200))  # URL for product image
    printed = db.Column(db.Boolean, default=False)  # New column to track if printed


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

class SoldProduct(BaseProduct):
    __tablename__ = 'sold_product'

    quantity_sold = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    date_sold = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<SoldProduct {self.product_name}>"

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

# User model for authentication
class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    role = db.Column(db.String(20), nullable=False)  # Can be 'admin', 'staff', or 'guest'

    def __repr__(self):
        return f'<User {self.username}>'
    
