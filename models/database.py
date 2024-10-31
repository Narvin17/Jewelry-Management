from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy()

class BaseProduct(db.Model):
    __abstract__ = True  # This ensures the class is not created as a separate table
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    karat = db.Column(db.String(20), nullable=False)
    gold_type = db.Column(db.String(50), nullable=False)
    size = db.Column(db.String(20), nullable=True, default='N/A')

    def __repr__(self):
        return f"<Product id={self.id}, name='{self.product_name}'>"

class Inventory(BaseProduct):
    __tablename__ = 'inventory'

    barcode = db.Column(db.String(50), unique=True, nullable=False)
    initial_quantity = db.Column(db.Integer, nullable=False)  # Original stock when added
    current_stock = db.Column(db.Integer, nullable=False)     # Tracks available stock
    price_per_unit = db.Column(db.Float, nullable=False)
    frozen_price_per_gram = db.Column(db.Float, nullable=False)  # Store price at creation
    image_url = db.Column(db.String(200), nullable=True)  # Single image URL
    printed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    status = db.Column(db.String(20), nullable=False, default='Available')  # New column to track sold status
    existence = db.Column(db.String(10), default="Exists")  # Renamed field for soft delete
    batch_number = db.Column(db.Integer, nullable=False)
    # Relationship to sold products
    sold_products = db.relationship('SoldProduct', backref='product', lazy=True)

    def calculate_price_per_unit(self, gold_prices):
        """Calculate price per unit based on weight and gold prices."""
        karat_key = self.karat.lower()
        if self.gold_type == 'Chinese Gold':
            price_per_gram = gold_prices.get(f'chinese_{karat_key}', 0)
        elif self.gold_type == 'Saudi Gold':
            price_per_gram = gold_prices.get(f'saudi_{karat_key}', 0)
        else:
            price_per_gram = 0
        return price_per_gram * self.weight
    
    def __repr__(self):
        return f"<Inventory id={self.id}, name='{self.product_name}', current_stock={self.current_stock}>"


class SoldProduct(BaseProduct):
    __tablename__ = 'sold_product'

    product_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)  # Foreign Key to Inventory
    barcode = db.Column(db.String(50), nullable=False)
    current_stock_sold = db.Column(db.Integer, nullable=False, default=1)
    total_price = db.Column(db.Float, nullable=False)
    price_per_gram = db.Column(db.Float, nullable=False)
    date_sold = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    customer_name = db.Column(db.String(100), nullable=False)
    sold_by = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Inventory id={self.id}, name='{self.product_name}', current_stock={self.current_stock}>"


class Expense(db.Model):
    __tablename__ = 'expense'

    id = db.Column(db.Integer, primary_key=True)
    supplier = db.Column(db.String(100), nullable=False)
    price_per_gram = db.Column(db.Float, nullable=False)
    total_weight = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)  # Store calculated total price
    time_bought = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Expense id={self.id}, supplier='{self.supplier}', total_price={self.total_price}>"

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    role = db.Column(db.String(20), nullable=False)  # Can be 'admin', 'staff', or 'guest'

    def __repr__(self):
        return f'<User id={self.id}, username="{self.username}", role="{self.role}">'

class UserLogin(db.Model):
    __tablename__ = 'user_login'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('logins', lazy=True))

    def __repr__(self):
        return f"<UserLogin user_id={self.user_id}, login_time={self.login_time}>"

class GoldPrice(db.Model):
    __tablename__ = 'gold_price'

    id = db.Column(db.Integer, primary_key=True)
    karat = db.Column(db.String(10), nullable=False)
    gold_type = db.Column(db.String(20), nullable=False)
    price_per_gram = db.Column(db.Float, nullable=False)  # Keep this as the main price field
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('karat', 'gold_type', name='_karat_gold_type_uc'),
    )

    def __repr__(self):
        return f"<GoldPrice id={self.id}, karat='{self.karat}', price_per_gram={self.price_per_gram}>"

