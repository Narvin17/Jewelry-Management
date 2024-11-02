from flask import abort, Flask, jsonify, render_template, request, redirect, url_for, flash, session, send_file
from models.database import db, Inventory, SoldProduct, Expense, UserLogin, User, GoldPrice
from forms.forms import AddProductForm, EditProductForm, AddExpenseForm, LoginForm, GoldPricesForm, CreateUserForm, MarkAsSoldForm, CheckoutForm
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime
from barcode.writer import ImageWriter
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import and_, func
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_talisman import Talisman
from dotenv import load_dotenv
from urllib.parse import urlencode

import os
import random
import string
import barcode
import logging

from datetime import datetime, timedelta

# Define the offset for Philippine Standard Time (GMT+8)
philippine_offset = timedelta(hours=8)
# Sample timestamp without timezone (UTC)
utc_timestamp = datetime.strptime("2024-10-31 07:48:53.800508", "%Y-%m-%d %H:%M:%S.%f")
# Convert UTC timestamp to Philippine time
philippine_time = utc_timestamp + philippine_offset
# Format the datetime to display in the desired format
philippine_time_formatted = philippine_time.strftime("%Y-%m-%d %H:%M:%S")
print("Philippine Time:", philippine_time_formatted)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql+pg8000://postgres:password@localhost/jewelry_management')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

app.config['SESSION_COOKIE_SECURE'] = False  # Set to False if not using HTTPS (development only)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # This setting is usually fine for IP access
app.config['SESSION_COOKIE_DOMAIN'] = None  # Ensure it's None so that IP addresses work properly

csrf = CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Talisman for security headers
if os.getenv('FLASK_ENV') == 'production':
    csp = {
        'default-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net'],
        'script-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net'],
        'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdnjs.cloudflare.com', 'https://cdn.jsdelivr.net'],
        'img-src': ['\'self\'', 'data:'],
    }
    talisman = Talisman(app, content_security_policy=csp, force_https=True)
else:
    talisman = Talisman(app, content_security_policy=None, force_https=False)


@app.template_filter('to_philippine_time')
def to_philippine_time(value):
    if isinstance(value, datetime):
        philippine_offset = timedelta(hours=8)
        philippine_time = value + philippine_offset
        return philippine_time.strftime("%Y-%m-%d %H:%M:%S")
    return value

# CSRF Error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The form you submitted is invalid or has expired. Please try again.', 'error')
    return redirect(request.referrer or url_for('inventory')), 400

@app.template_filter('float')
def float_filter(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0  # or return None, depending on your logic

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Updated for SQLAlchemy 2.x

@app.route('/user_profiles', methods=['GET'])
@login_required
def user_profiles():
    if current_user.role != 'admin':
        flash('Access denied. Only admins can view user profiles.', 'error')
        return redirect(url_for('dashboard'))

    users = User.query.all()  # Fetch all users from the database
    form = CreateUserForm()  # Create an instance of the form

    return render_template('user_profiles.html', users=users, form=form)

@app.route('/')
def home():
    print(request.args)  # Log query parameters to console
    return render_template('dashboard.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Only admins can edit users.', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form.get('username').strip()
        role = request.form.get('role').strip().lower()

        if not username or not role:
            flash('All fields are required.', 'error')
            return redirect(url_for('edit_user', user_id=user.id))

        user.username = username
        user.role = role
        db.session.commit()
        flash(f'User {username} updated successfully!', 'success')
        return redirect(url_for('user_profiles'))

    return render_template('edit_user.html', user=user)

@app.route('/remove_user/<int:user_id>', methods=['POST'])
@login_required
def remove_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied. Only admins can remove users.', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)  # Get the user by ID
    db.session.delete(user)  # Delete the user from the database

    try:
        db.session.commit()  # Commit the changes to the database
        flash(f"User '{user.username}' removed successfully!", "success")
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        flash(f"Error removing user: {e}", "error")

    return redirect(url_for('user_profiles'))  # Redirect to user profiles page

@app.route('/barcode/<string:barcode_data>')
def generate_barcode_image(barcode_data):
    code = barcode.get('code128', barcode_data, writer=ImageWriter())
    filename = f"{barcode_data}.png"
    code.save(filename)

    # Serve the barcode image
    response = send_file(filename, mimetype='image/png')
    os.remove(filename)  # Clean up the file after serving
    return response

# Function to generate a unique barcode
def generate_barcode(category, karat, gold_type):
    category_prefixes = {
        'Ring': 'RNG',
        'Earring': 'ERG',
        'Necklace': 'NCK',
        'Bracelet': 'BRC',
        'Pendant': 'PND'
    }
    karat_prefixes = {
        '18K': '18',
        '21K': '21',
    }
    gold_type_prefixes = {
        'Chinese Gold': 'CHI',
        'Saudi Gold': 'SAU',
    }
    category_prefix = category_prefixes.get(category, 'OTH')
    karat_prefix = karat_prefixes.get(karat, 'UNK')
    gold_type_prefix = gold_type_prefixes.get(gold_type, 'OTH')
    random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    barcode = f"{category_prefix}-{karat_prefix}-{gold_type_prefix}-{random_suffix}"
    return barcode

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Retrieve and sanitize user input
        username = form.username.data.strip()
        password = form.password.data.strip()

        # Query for the user in the database
        user = User.query.filter_by(username=username).first()

        if user:
            # Check the password
            if check_password_hash(user.password, password):
                # Log the user in
                login_user(user)

                # Record the login time for the user
                new_login = UserLogin(user_id=user.id)
                try:
                    db.session.add(new_login)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    flash('An error occurred while logging the login time.', 'error')
                    return redirect(url_for('login'))

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')
        else:
            flash('Invalid username or password', 'error')

    # Render the login template with the form
    return render_template('login.html', form=form)

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    form = CreateUserForm()

    if form.validate_on_submit():  # Validate form on POST
        username = form.username.data.strip()
        password = form.password.data.strip()
        role = form.role.data.lower()

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f'Error: Username "{username}" already exists. Please choose a different username.', 'error')
        else:
            # Create the new user
            new_user = User(username=username, password=hashed_password, role=role)
            try:
                db.session.add(new_user)
                db.session.commit()
                flash(f'User {username} created successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating user: {e}', 'error')

    # Render the template with the form instance
    return render_template('create_user.html', form=form)

# Route for logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Admin dashboard route (restricted to admin)
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html')

# General dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch total sales, inventory value, products sold today, and low stock items
    total_sales = db.session.query(func.sum(SoldProduct.total_price)).scalar() or 0
    total_inventory_value = db.session.query(func.sum(Inventory.price_per_unit)).scalar() or 0
    products_sold_today = SoldProduct.query.filter(
        func.date(SoldProduct.date_sold) == datetime.today().date()
    ).count()
    low_stock_count = Inventory.query.filter(Inventory.current_stock < 5).count()

    # Generate notifications
    notifications = [
        {"message": "New product added to inventory", "date": "2024-10-01"},
        {"message": "Low stock alert: 10 items below threshold", "date": "2024-10-02"}
    ]

    # Sales Trend and Expenses vs. Sales Data for Charts
    sales_data = SoldProduct.query.with_entities(
        func.date_trunc('month', SoldProduct.date_sold).label('month'),
        func.sum(SoldProduct.total_price).label('total')
    ).group_by('month').order_by('month').all()

    # Use 'time_bought' if 'date' does not exist for expenses
    expense_data = Expense.query.with_entities(
        func.date_trunc('month', Expense.time_bought).label('month'),  # Update to the correct attribute name
        func.sum(Expense.total_price).label('total')
    ).group_by('month').order_by('month').all()

    # Convert query results into lists for Chart.js
    sales_months = [record.month.strftime('%Y-%m') for record in sales_data]
    sales_values = [float(record.total) for record in sales_data]
    expense_months = [record.month.strftime('%Y-%m') for record in expense_data]
    expense_values = [float(record.total) for record in expense_data]

    return render_template(
        'dashboard.html',
        total_sales=total_sales,
        total_inventory_value=total_inventory_value,
        products_sold_today=products_sold_today,
        low_stock_count=low_stock_count,
        notifications=notifications,
        sales_months=sales_months,
        sales_values=sales_values,
        expense_months=expense_months,
        expense_values=expense_values
    )


# Expense list route (restricted to admin only)
@app.route('/expenses')
@login_required
def expenses():
    if current_user.role == 'staff':
        flash('You are not authorized to view this page', 'error')
        return redirect(url_for('dashboard'))
    expenses_list = Expense.query.all()
    return render_template('expense_list.html', expenses=expenses_list)

@app.route('/update_gold_prices', methods=['GET', 'POST'])
@login_required
def update_gold_prices():
    if current_user.role != 'admin':
        flash('Access denied. Only admins can update gold prices.', 'error')
        return redirect(url_for('dashboard'))

    form = GoldPricesForm()

    if form.validate_on_submit():
        # Update gold prices in the database
        update_or_create_gold_price('18K', 'Chinese Gold', form.chinese_18k.data)
        update_or_create_gold_price('21K', 'Chinese Gold', form.chinese_21k.data)
        update_or_create_gold_price('18K', 'Saudi Gold', form.saudi_18k.data)
        update_or_create_gold_price('21K', 'Saudi Gold', form.saudi_21k.data)
        flash('Gold prices updated successfully!', 'success')
        return redirect(url_for('inventory'))
    else:
        # Populate the form with existing gold prices
        populate_gold_prices_form(form)

    return render_template('update_gold_prices.html', form=form)


def update_inventory_prices():
    inventory_items = Inventory.query.all()
    for item in inventory_items:
        current_gold_price = GoldPrice.query.filter_by(karat=item.karat, gold_type=item.gold_type).first()
        if current_gold_price:
            item.price_per_unit = item.weight * current_gold_price.price_per_gram
    db.session.commit()

def update_or_create_gold_price(karat, gold_type, price):
    gold_price = GoldPrice.query.filter_by(karat=karat, gold_type=gold_type).first()
    if gold_price:
        gold_price.price_per_gram = price
        gold_price.updated_at = datetime.utcnow()
    else:
        gold_price = GoldPrice(karat=karat, gold_type=gold_type, price_per_gram=price)
        db.session.add(gold_price)
    db.session.commit()

def populate_gold_prices_form(form):
    gold_prices = GoldPrice.query.all()
    for gp in gold_prices:
        if gp.karat == '18K' and gp.gold_type == 'Chinese Gold':
            form.chinese_18k.data = gp.price_per_gram
        elif gp.karat == '21K' and gp.gold_type == 'Chinese Gold':
            form.chinese_21k.data = gp.price_per_gram
        elif gp.karat == '18K' and gp.gold_type == 'Saudi Gold':
            form.saudi_18k.data = gp.price_per_gram
        elif gp.karat == '21K' and gp.gold_type == 'Saudi Gold':
            form.saudi_21k.data = gp.price_per_gram
            
    if form.validate_on_submit():
        # ... (update gold prices)
        update_inventory_prices()
        flash('Gold prices and inventory prices updated successfully!', 'success')
        return redirect(url_for('inventory'))


@app.route('/update_price', methods=['POST'])
@login_required
def update_price():
    product_id = request.form.get('productId')
    new_price = request.form.get('newPrice', type=float)

    product = Inventory.query.get(product_id)
    if product:
        product.price_per_gram = new_price
        db.session.commit()
        flash(f"Price per gram for {product.product_name} updated successfully!", "success")
    else:
        flash("Product not found!", "error")

    return redirect(url_for('inventory'))

@app.route('/inventory', methods=['GET'])
@login_required
def inventory():
    # Instantiate the GoldPricesForm
    gold_prices_form = GoldPricesForm()

    # Fetch pagination data from query parameters
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Limit to 50 items per page for the main table

    # Base query for inventory - exclude deleted and sold items
    query = Inventory.query.with_entities(
        Inventory.id,
        Inventory.product_name,
        Inventory.category,
        Inventory.karat,
        Inventory.gold_type,
        Inventory.size,
        Inventory.weight,
        Inventory.price_per_unit,
        Inventory.barcode,
        Inventory.batch_number,  # Include batch number
        Inventory.status,
        Inventory.existence,
        Inventory.printed  # Include printed status
    ).filter(
        (Inventory.existence == 'Exists') & 
        (~Inventory.status.in_(['Sold', 'Sold Out']))  # Exclude "Sold" and "Sold Out"
    ).order_by(Inventory.id.desc())  # Order by id in descending order

    # Paginate the main inventory items
    paginated_items = query.paginate(page=page, per_page=per_page, error_out=False)

    # Create an inventory tree grouped by Category -> Karat -> Gold Type
    inventory_tree = create_inventory_tree(paginated_items.items)

    # Directly pass the items to the template
    return render_template(
        'inventory.html',
        items=paginated_items.items,  # Pass the actual items from the query
        inventory_tree=inventory_tree,
        total_pages=paginated_items.pages,
        current_page=page,
        previous_page=paginated_items.prev_num,
        next_page=paginated_items.next_num,
        prices=fetch_gold_prices(),
        form=gold_prices_form
    )



@app.route('/inventory_tree')
@login_required
def inventory_tree():
    # Fetch all products from the inventory
    inventory_items = Inventory.query.all()

    # Create an inventory tree from all items
    inventory_tree = create_inventory_tree(inventory_items)

    return render_template('inventory_tree.html', inventory_tree=inventory_tree)

def create_inventory_tree(items):
    """Create a hierarchical inventory tree."""
    inventory_tree = {}

    for item in items:
        category = item.category
        karat = item.karat
        gold_type = item.gold_type

        # Initialize category if not already present
        if category not in inventory_tree:
            inventory_tree[category] = {'karat': {}, 'count': 0}

        # Initialize karat if not already present
        if karat not in inventory_tree[category]['karat']:
            inventory_tree[category]['karat'][karat] = {'gold_type': {}, 'count': 0}

        # Initialize gold type if not already present
        if gold_type not in inventory_tree[category]['karat'][karat]['gold_type']:
            inventory_tree[category]['karat'][karat]['gold_type'][gold_type] = {'items': [], 'count': 0}

        # Add item to the correct gold type group
        inventory_tree[category]['karat'][karat]['gold_type'][gold_type]['items'].append(item)

        # Increment counts at each level
        inventory_tree[category]['count'] += 1
        inventory_tree[category]['karat'][karat]['count'] += 1
        inventory_tree[category]['karat'][karat]['gold_type'][gold_type]['count'] += 1

    return inventory_tree

def fetch_gold_prices():
    """Retrieve gold prices from the database."""
    gold_prices_query = GoldPrice.query.all()
    gold_prices = {f"{gp.gold_type}_{gp.karat}": gp.price_per_gram for gp in gold_prices_query}
    return gold_prices

# Updated catalog route


@app.route('/catalog')
def catalog():
    # Initialize the base query with an outer join to include all inventory items
    query = Inventory.query.outerjoin(
        GoldPrice,
        and_(
            Inventory.gold_type == GoldPrice.gold_type,
            Inventory.karat == GoldPrice.karat
        )
    ).filter(
        Inventory.existence == 'Exists'  # Include only existing items
    )

    # Fetch all gold prices to use in calculations (if needed in templates)
    gold_prices = {f"{gp.gold_type}_{gp.karat}": gp.price_per_gram for gp in GoldPrice.query.all()}

    # Get filtering criteria from request arguments
    filters = {
        'category': request.args.get('category', 'all'),
        'price_min': request.args.get('price_min', 0.0, type=float),
        'price_max': request.args.get('price_max', float('inf'), type=float),
        'sort_by': request.args.get('sort_by', 'price_asc'),
        'karat': request.args.get('karat', 'all'),
        'gold_type': request.args.get('gold_type', 'all'),
        'search_query': request.args.get('search_query', '').strip(),
        'page': request.args.get('page', 1, type=int),
        'per_page': request.args.get('per_page', 50, type=int),
    }

    # Apply filters
    if filters['category'] != 'all':
        query = query.filter(Inventory.category == filters['category'])
    if filters['karat'] != 'all':
        query = query.filter(Inventory.karat == filters['karat'])
    if filters['gold_type'] != 'all':
        query = query.filter(Inventory.gold_type == filters['gold_type'])
    if filters['search_query']:
        query = query.filter(Inventory.product_name.ilike(f"%{filters['search_query']}%"))

    # Calculate total price expression for price range filtering and sorting
    total_price_expr = (GoldPrice.price_per_gram * Inventory.weight).label('total_price')

    # Apply price filtering, handling nulls gracefully
    query = query.filter(
        ((total_price_expr >= filters['price_min']) | (GoldPrice.price_per_gram.is_(None))),
        ((total_price_expr <= filters['price_max']) | (GoldPrice.price_per_gram.is_(None)))
    )

    # Apply sorting
    sorting_options = {
        'price_asc': total_price_expr.asc().nulls_last(),
        'price_desc': total_price_expr.desc().nulls_last(),
        'newest': Inventory.created_at.desc(),
    }
    query = query.order_by(sorting_options.get(filters['sort_by'], Inventory.created_at.desc()))

    # Paginate the query to handle a large number of products
    paginated_items = query.add_columns(total_price_expr).paginate(page=filters['page'], per_page=filters['per_page'], error_out=False)

    # Prepare data for rendering
    items = paginated_items.items  # List of tuples: (Inventory, total_price)
    total_pages = paginated_items.pages

    # Group products with appropriate handling for detailed product information
    products_grouped = group_products(items, gold_prices)

    # Prepare recently viewed items for display
    recently_viewed = get_recently_viewed_items()

    # Render the template with data
    return render_template(
        'catalog.html',
        products=products_grouped,
        recently_viewed=recently_viewed,
        categories=get_distinct_values(Inventory, 'category'),
        karats=get_distinct_values(Inventory, 'karat'),
        gold_types=get_distinct_values(Inventory, 'gold_type'),
        previous_page=paginated_items.prev_num,
        next_page=paginated_items.next_num,
        total_pages=total_pages,
        current_page=filters['page'],
        prices=gold_prices,  # Pass `gold_prices` to the template
        **filters
    )

def get_distinct_values(model, field):
    """Helper function to get distinct values of a given field."""
    return [value[0] for value in model.query.with_entities(getattr(model, field)).distinct().all()]

def group_products(items, gold_prices):
    """Helper function to group products hierarchically and include detailed product data."""
    products_grouped = {}
    for item, total_price in items:
        karat_key = item.karat
        gold_type_key = item.gold_type
        category_key = item.category
        product_name_key = item.product_name.replace(" ", "_")

        if karat_key not in products_grouped:
            products_grouped[karat_key] = {}
        if gold_type_key not in products_grouped[karat_key]:
            products_grouped[karat_key][gold_type_key] = {}
        if category_key not in products_grouped[karat_key][gold_type_key]:
            products_grouped[karat_key][gold_type_key][category_key] = {}

        if product_name_key not in products_grouped[karat_key][gold_type_key][category_key]:
            image_path = f"images/{product_name_key}.png"
            image_full_path = os.path.join(app.static_folder, image_path)
            image_url = image_path if os.path.exists(image_full_path) else 'images/default.png'
            products_grouped[karat_key][gold_type_key][category_key][product_name_key] = {
                'product': item,
                'variations': {},
                'total_stock': 0,
                'image_url': image_url,
            }

        product_entry = products_grouped[karat_key][gold_type_key][category_key][product_name_key]
        product_entry['total_stock'] += item.current_stock

        size_weight_key = (item.size, item.weight)
        if size_weight_key not in product_entry['variations']:
            calculated_price = item.calculate_price_per_unit(gold_prices)
            product_entry['variations'][size_weight_key] = {
                'size': item.size,
                'weight': item.weight,
                'stock': item.current_stock,
                'price': calculated_price if calculated_price else item.price_per_unit
            }
        else:
            product_entry['variations'][size_weight_key]['stock'] += item.current_stock

    return products_grouped

def get_recently_viewed_items():
    """Helper function to fetch recently viewed items."""
    recently_viewed_query = Inventory.query.filter(
        Inventory.existence == 'Exists'
    ).order_by(Inventory.id.desc()).limit(4)

    recently_viewed_items = recently_viewed_query.all()

    return recently_viewed_items

@app.template_filter('dict_to_urlencode')
def dict_to_urlencode(d):
    """Custom filter to URL-encode a dictionary."""
    return urlencode(d)

@app.route('/pos_view', methods=['GET'])
@login_required
def pos_view():
    """Render the Point of Sale view with filtering, sorting, and cart functionality."""
    form = CheckoutForm()
    
    # Fetch filtering parameters from the request
    category = request.args.get('category', 'all')
    karat = request.args.get('karat', 'all')
    gold_type = request.args.get('gold_type', 'all')
    price_min = request.args.get('price_min', 0, type=float)
    price_max = request.args.get('price_max', float('inf'), type=float)
    sort_by = request.args.get('sort_by', 'price_asc')
    search_query = request.args.get('search_query', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    # Fetch gold prices for dynamic pricing calculations
    gold_prices = {f"{gp.gold_type}_{gp.karat}": gp.price_per_gram for gp in GoldPrice.query.all()}

    # Prepare dropdown options for categories, karats, and gold types
    categories = [c[0] for c in Inventory.query.with_entities(Inventory.category).distinct().all()]
    karats = [k[0] for k in Inventory.query.with_entities(Inventory.karat).distinct().all()]
    gold_types = [g[0] for g in Inventory.query.with_entities(Inventory.gold_type).distinct().all()]

    # Base query for items where existence is 'Exists' and current stock is greater than zero
    query = Inventory.query.filter(
        Inventory.existence == 'Exists',
        Inventory.current_stock > 0
    )

    # Apply filtering criteria to the query
    if category != 'all':
        query = query.filter(Inventory.category == category)
    if karat != 'all':
        query = query.filter(Inventory.karat == karat)
    if gold_type != 'all':
        query = query.filter(Inventory.gold_type == gold_type)
    if search_query:
        query = query.filter(Inventory.product_name.ilike(f'%{search_query}%'))

    # Fetch and filter items by price range
    filtered_items = []
    for item in query.all():
        price_key = f"{item.gold_type}_{item.karat}"
        item_price_per_gram = gold_prices.get(price_key, 0)
        item_total_price = item_price_per_gram * item.weight
        item.total_price = item_total_price

        if price_min <= item_total_price <= price_max:
            filtered_items.append(item)

    # Sorting logic
    if sort_by == 'price_asc':
        filtered_items.sort(key=lambda x: x.total_price)
    elif sort_by == 'price_desc':
        filtered_items.sort(key=lambda x: x.total_price, reverse=True)
    elif sort_by == 'newest':
        filtered_items.sort(key=lambda x: x.created_at, reverse=True)

    # Pagination
    total_items = len(filtered_items)
    total_pages = (total_items + per_page - 1) // per_page
    paginated_items = filtered_items[(page - 1) * per_page:page * per_page]

    # Group products hierarchically by Karat > Gold Type > Category > Product Name
    products_grouped = {}
    for item in paginated_items:
        karat_key = item.karat
        gold_type_key = item.gold_type
        category_key = item.category
        product_name_key = item.product_name.replace(" ", "_")

        # Initialize the nested dictionary
        if karat_key not in products_grouped:
            products_grouped[karat_key] = {}
        if gold_type_key not in products_grouped[karat_key]:
            products_grouped[karat_key][gold_type_key] = {}
        if category_key not in products_grouped[karat_key][gold_type_key]:
            products_grouped[karat_key][gold_type_key][category_key] = {}

        # Store product details with image URL
        if product_name_key not in products_grouped[karat_key][gold_type_key][category_key]:
            image_path = os.path.join(app.static_folder, 'images', f"{product_name_key}.png")
            image_url = f"images/{product_name_key}.png" if os.path.exists(image_path) else 'images/default.png'
            products_grouped[karat_key][gold_type_key][category_key][product_name_key] = {
                'product': item,
                'variations': {},
                'total_stock': 0,
                'image_url': image_url,
            }

        # Aggregate stock for unique size-weight combinations, excluding deleted items
        product_entry = products_grouped[karat_key][gold_type_key][category_key][product_name_key]
        product_entry['total_stock'] += item.current_stock

        size_weight_key = (item.size, item.weight)  # Unique key for size and weight
        if size_weight_key not in product_entry['variations']:
            product_entry['variations'][size_weight_key] = {
                'id': item.id,
                'size': item.size,
                'weight': item.weight,
                'stock': item.current_stock,
                'price': item.total_price,
                'barcode': item.barcode
            }
        else:
            # Aggregate stock for duplicate size-weight combinations
            product_entry['variations'][size_weight_key]['stock'] += item.current_stock

    return render_template(
        'pos_view.html',
        products=products_grouped,
        categories=categories,
        karats=karats,
        gold_types=gold_types,
        category=category,
        karat=karat,
        gold_type=gold_type,
        price_min=price_min,
        price_max=price_max,
        sort_by=sort_by,
        search_query=search_query,
        prices=gold_prices,
        form=form,
        previous_page=page - 1 if page > 1 else None,
        next_page=page + 1 if page < total_pages else None,
        total_pages=total_pages,
        current_page=page,
        per_page=per_page
    )

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    """Process the checkout by recording sold products and updating inventory."""
    if current_user.role not in ['admin', 'staff']:
        return jsonify({'success': False, 'message': 'Access denied.'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid request data.'}), 400
    
    # Retrieve customer and sold by data
    customer_name = data.get('customer_name', '').strip()
    sold_by_user = data.get('sold_by', '').strip()
    
    if not customer_name or not sold_by_user:
        return jsonify({'success': False, 'message': 'Customer Name and Sold By are required.'}), 400
    
    # Retrieve cart from session
    cart = session.get('cart', [])
    if not cart:
        return jsonify({'success': False, 'message': 'Your cart is empty.'}), 400
    
    error_messages = []
    success_messages = []
    
    try:
        for item in cart:
            product_id = item.get('product_id')
            size = item.get('size')
            quantity = item.get('quantity', 1)
    
            if not product_id or not size:
                error_messages.append(f"Missing data for item with Product ID: {product_id}.")
                continue
    
            # Fetch product from inventory
            product = Inventory.query.get(product_id)
            if not product or product.existence != 'Exists':
                error_messages.append(f"Product with ID {product_id} not found or unavailable.")
                continue
    
            if product.size != size:
                error_messages.append(f"Size mismatch for product '{product.product_name}'. Expected size: {product.size}.")
                continue
    
            if product.current_stock < quantity:
                error_messages.append(f"Insufficient stock for '{product.product_name}'. Available: {product.current_stock}.")
                continue
    
            # Fetch current gold price
            price_key = f"{product.gold_type}_{product.karat}"
            current_gold_price = GoldPrice.query.filter_by(karat=product.karat, gold_type=product.gold_type).first()
            if not current_gold_price:
                error_messages.append(f"Gold price not set for {product.karat} {product.gold_type}.")
                continue
    
            # Calculate sale price
            price_per_gram_at_sale = current_gold_price.price_per_gram
            total_price_at_sale = price_per_gram_at_sale * product.weight * quantity
    
            # Create SoldProduct record
            sold_record = SoldProduct(
                product_id=product.id,
                product_name=product.product_name,
                category=product.category,
                barcode=product.barcode,
                weight=product.weight,
                karat=product.karat,
                gold_type=product.gold_type,
                size=product.size,
                current_stock_sold=quantity,
                total_price=total_price_at_sale,
                price_per_gram=price_per_gram_at_sale,
                date_sold=datetime.utcnow(),
                customer_name=customer_name,
                sold_by=sold_by_user
            )
    
            # Update product stock and existence
            product.current_stock -= quantity
            if product.current_stock <= 0:
                product.existence = 'Deleted'  # Mark as deleted if stock is depleted
    
            # Add the sold record to the session
            db.session.add(sold_record)
            success_messages.append(f"Sold {quantity} unit(s) of '{product.product_name}'.")
    
        if error_messages:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': 'Some items could not be processed.',
                'errors': error_messages
            }), 400
    
        # Commit all changes if no errors
        db.session.commit()
        session.pop('cart', None)
    
        return jsonify({
            'success': True,
            'message': 'Checkout successful.',
            'details': success_messages
        }), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Checkout error: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': 'An unexpected error occurred during checkout.'}), 500

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    """Add a product to the shopping cart."""
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid request data."}), 400
    
    product_id = data.get('product_id')
    size = data.get('size')
    quantity = data.get('quantity', 1, type=int)
    
    if not product_id or not size:
        return jsonify({"message": "Product ID and size are required."}), 400
    
    # Fetch product from inventory
    product = Inventory.query.get(product_id)
    if not product or product.existence != 'Exists' or product.current_stock <= 0:
        return jsonify({"message": "Product not available."}), 400
    
    # Initialize the cart in session if not present
    if 'cart' not in session:
        session['cart'] = []
    
    # Check if the product is already in the cart
    cart = session['cart']
    for item in cart:
        if item['product_id'] == product_id and item['size'] == size:
            # Update quantity
            if product.current_stock >= item['quantity'] + quantity:
                item['quantity'] += quantity
                session.modified = True
                return jsonify({"success": True, "message": "Item quantity updated in cart", "cart": cart}), 200
            else:
                return jsonify({"message": "Insufficient stock for the requested quantity."}), 400
    
    # Add new item to the cart
    if product.current_stock >= quantity:
        cart_item = {
            'product_id': product_id,
            'product_name': product.product_name,
            'size': size,
            'weight': product.weight,
            'price': product.price_per_unit,
            'quantity': quantity
        }
        cart.append(cart_item)
        session.modified = True
        return jsonify({"success": True, "message": "Item added to cart", "cart": cart}), 200
    else:
        return jsonify({"message": "Insufficient stock for the requested quantity."}), 400

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = AddExpenseForm()
    if form.validate_on_submit():
        total_price = form.price_per_gram.data * form.total_weight.data
        new_expense = Expense(
            supplier=form.supplier.data,
            price_per_gram=form.price_per_gram.data,
            total_weight=form.total_weight.data,
            time_bought=datetime.strptime(form.time_bought.data, '%Y-%m-%d'),
            total_price=total_price
        )
        db.session.add(new_expense)
        db.session.commit()

        flash(f"Expense added for '{form.supplier.data}' with total price: {total_price}!", "success")
        return redirect(url_for('expenses'))

    return render_template('add_expense.html', form=form)

@app.route('/remove_expense/<int:expense_id>', methods=['POST'])
@login_required
def remove_expense(expense_id):
    # Fetch the expense from the database
    expense = Expense.query.get_or_404(expense_id)
    
    # Remove the expense from the database
    db.session.delete(expense)
    db.session.commit()
    
    # Display success message
    flash(f"Expense '{expense.supplier}' removed successfully!", "success")
    
    # Redirect to the expense list page
    return redirect(url_for('expenses'))

@app.route('/filter_sold_products', methods=['GET'])
@login_required
def filter_sold_products():
    year = request.args.get('filter_year')
    month = request.args.get('filter_month')
    day = request.args.get('filter_day')

    selected_date = datetime(int(year), int(month), int(day))

    # Query sold products based on the selected date
    sold_products = SoldProduct.query.filter(
        func.date(SoldProduct.date_sold) == selected_date.date()
    ).all()

    return render_template('admin_power.html', sold_products=sold_products)

@app.route('/filter_inventory', methods=['GET'])
@login_required
def filter_inventory():
    year = request.args.get('filter_year')
    month = request.args.get('filter_month')
    day = request.args.get('filter_day')

    selected_date = datetime(int(year), int(month), int(day))

    # Query inventory items based on the selected date
    inventory_items = Inventory.query.filter(
        func.date(Inventory.created_at) == selected_date.date()
    ).all()

    return render_template('admin_power.html', inventory_items=inventory_items)

# Initialize logging for the application
logging.basicConfig(level=logging.INFO)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role not in ['admin', 'staff']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    form = AddProductForm()
    warning_message = None

    # Define product name and image path
    product_name = secure_filename(form.product_name.data.replace(" ", "_")) if form.product_name.data else ""
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{product_name}.png")
    use_existing_image = os.path.exists(image_path)

    app.logger.info("Starting product addition process")

    if form.validate_on_submit():
        app.logger.info("Form validation passed")

        # Handle image upload
        if form.photo.data:
            photo = form.photo.data
            filename = f"{product_name}.png"
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            photo.save(photo_path)
            uploaded_photos = [filename]
            app.logger.info("Image uploaded successfully")
        else:
            if not use_existing_image:
                flash("Product photo is required since no existing image was found.", "error")
                return render_template('add_product.html', form=form, use_existing_image=use_existing_image)
            uploaded_photos = [f"{product_name}.png"]

        # Fetch gold price from GoldPrice table
        gold_price = GoldPrice.query.filter_by(
            karat=form.karat.data,
            gold_type=form.gold_type.data
        ).first()

        if not gold_price:
            flash("No gold price found for the selected karat and gold type.", "error")
            return render_template('add_product.html', form=form, warning_message="Gold price not set.")

        # Store frozen price at creation time
        frozen_price_per_gram = gold_price.price_per_gram

        try:
            # Convert form data to appropriate data types
            weight = float(form.weight.data)
            initial_quantity = int(form.initial_quantity.data)
            price_per_unit = weight * frozen_price_per_gram
            app.logger.info(f"Fetched gold price: {frozen_price_per_gram}, calculated price per unit: {price_per_unit}")

            # Get the next batch_number
            max_batch_number = db.session.query(func.max(Inventory.batch_number)).scalar() or 0
            batch_number = max_batch_number + 1

            # Add new product(s) based on the initial quantity
            for _ in range(initial_quantity):
                # Ensure barcode uniqueness
                while True:
                    barcode = generate_barcode(form.category.data, form.karat.data, form.gold_type.data)
                    if not Inventory.query.filter_by(barcode=barcode).first():
                        break

                new_product = Inventory(
                    product_name=form.product_name.data,
                    category=form.category.data,
                    initial_quantity=1,
                    current_stock=1,
                    price_per_unit=price_per_unit,
                    frozen_price_per_gram=frozen_price_per_gram,
                    karat=form.karat.data,
                    gold_type=form.gold_type.data,
                    weight=weight,
                    size=form.size.data,
                    barcode=barcode,
                    image_url=uploaded_photos[0] if uploaded_photos else None,
                    printed=False,
                    created_at=datetime.utcnow(),
                    status="Available",
                    existence="Exists",
                    batch_number=batch_number  # Assign the auto-incremented batch number
                )
                db.session.add(new_product)

            db.session.commit()
            app.logger.info("Product added successfully to the database")
            flash(f"{initial_quantity} units of '{form.product_name.data}' added to inventory with batch number {batch_number}!", "success")

            # Redirect to the add product page to reset the form
            return redirect(url_for('add_product'))

        except Exception as e:
            db.session.rollback()
            warning_message = "An error occurred while adding the product."
            app.logger.error(f"Add Product Error: {e}", exc_info=True)
            flash(warning_message, "error")

    else:
        app.logger.info("Form validation failed")
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {getattr(form, field).label.text}: {error}", "error")
            app.logger.error(f"Form validation errors: {form.errors}")

    return render_template('add_product.html', form=form, warning_message=warning_message, use_existing_image=use_existing_image)

@app.route('/get_product_image', methods=['GET'])
def get_product_image():
    product_name = request.args.get('product_name', '').strip().replace(" ", "_")
    
    if not product_name:
        return jsonify({"image_urls": []})

    # Construct the expected image filename format
    image_url = url_for('static', filename=f'images/{product_name}.png')
    
    # Check if the file exists on the server
    image_path = os.path.join(app.root_path, 'static', 'images', f"{product_name}.png")
    if os.path.exists(image_path):
        return jsonify({"image_urls": [image_url]})
    else:
        return jsonify({"image_urls": []})


@app.route('/products', methods=['GET'])
@login_required
def products():
    # Fetch unprinted products from the database
    unprinted_products = Inventory.query.filter_by(printed=False).all()
    return render_template('products.html', products=unprinted_products)

@app.route('/update_printed_status', methods=['POST'])
@login_required
def update_printed_status():
    data = request.get_json()
    product_ids = data.get('product_ids', [])

    # Update the printed status for each product
    try:
        for product_id in product_ids:
            product = Inventory.query.get(product_id)
            if product:
                product.printed = True  # Mark as printed
        db.session.commit()
        return jsonify({"message": "Printed status updated successfully."}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating printed status: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/batch_print', methods=['POST'])
@login_required
def batch_print():
    # Step 1: Fetch unprinted products from the Inventory
    unprinted_products = Inventory.query.filter_by(printed=False).all()
    
    if not unprinted_products:
        # If no unprinted products are found, return a message
        return jsonify({"message": "No unprinted products available for printing."}), 200

    try:
        # Begin a transaction
        with db.session.begin_nested():
            # Step 2: Update the products to mark them as printed
            for product in unprinted_products:
                product.printed = True  # Set printed status to True
            db.session.commit()  # Commit the changes to the database

        # Step 3: Render the print template with updated products
        rendered_content = render_template('print_batch.html', products=unprinted_products)

        # Step 4: Return success message and rendered content for printing
        return jsonify({
            "message": "Batch print completed successfully.",
            "print_content": rendered_content  # This will be sent to the frontend for the print function
        }), 200

    except Exception as e:
        db.session.rollback()  # Roll back any changes if there's an error
        app.logger.error(f"Error during batch print: {str(e)}", exc_info=True)  # Log the error
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/search_product', methods=['GET'])
@login_required
def search_product():
    barcode = request.args.get('barcode', '').strip()
    
    if not barcode:
        return jsonify([])  # Return an empty list if no barcode is provided

    # Fetch products matching the barcode from the database
    products = Inventory.query.filter(Inventory.barcode.ilike(f'%{barcode}%')).all()
    product_data = [{
        'id': product.id,
        'product_name': product.product_name,
        'category': product.category,
        'weight': product.weight,
        'karat': product.karat,
        'gold_type': product.gold_type,
        'barcode': product.barcode,
        'printed': product.printed
    } for product in products]

    return jsonify(product_data)

@app.route('/regenerate_sticker/<int:product_id>', methods=['POST'])
@login_required
def regenerate_sticker(product_id):
    product = Inventory.query.get(product_id)
    if product:
        product.printed = False  # Reset printed status
        db.session.commit()
        flash("Sticker regenerated successfully.", "success")  # Flash success message
    else:
        flash("Product not found.", "error")  # Flash error message if product is not found

    return redirect(url_for('products'))  # Redirect to the products page


# Route to edit product details (available to admin and staff)
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    # Restrict access to admin and staff only
    if current_user.role not in ['admin', 'staff']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    # Retrieve product instance or return 404 if not found
    product = Inventory.query.get_or_404(product_id)
    form = EditProductForm(obj=product)

    # Validate form on submit
    if form.validate_on_submit():
        # Update product attributes with form data
        product.product_name = form.product_name.data
        product.category = form.category.data
        product.initial_quantity = form.initial_quantity.data
        product.current_stock = form.initial_quantity.data  # Sync current stock with updated quantity
        product.price_per_unit = form.price_per_unit.data  # Save price per unit
        product.karat = form.karat.data
        product.gold_type = form.gold_type.data
        product.weight = float(form.weight.data)  # Ensure weight is a float

        try:
            db.session.commit()  # Commit updated product details to the database
            flash(f"Product '{product.product_name}' updated successfully!", "success")
            return redirect(url_for('inventory'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating the product.", "error")
            print(f"Database commit error: {e}")  # Log database error

    # Render edit product page with pre-filled form
    return render_template('edit_product.html', form=form, product=product)

# Route to delete product
@app.route('/remove_product/<int:product_id>', methods=['POST'])
@login_required
def remove_product(product_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    product = Inventory.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash(f"Product '{product.product_name}' removed successfully!", "success")
    return redirect(url_for('inventory'))

@app.route('/mark_as_sold', methods=['POST'])
@login_required
def mark_as_sold():
    # Check user role
    if current_user.role not in ['admin', 'staff']:
        flash('Access denied.', 'danger')
        return redirect(url_for('inventory'))

    # Initialize the form with form data
    form = MarkAsSoldForm()

    if form.validate_on_submit():
        # Retrieve data from the form
        product_id = form.product_id.data
        customer_name = form.customer_name.data.strip()
        sold_by = form.sold_by.data.strip()

        if not product_id:
            flash('Product ID is missing.', 'danger')
            return redirect(url_for('inventory'))

        # Fetch the product from the Inventory
        product = Inventory.query.get(product_id)
        if not product:
            flash('Product not found.', 'danger')
            return redirect(url_for('inventory'))

        # Check if the product requires a sticker to be printed
        if not product.printed:
            flash('This product cannot be marked as sold until its sticker is printed.', 'warning')
            return redirect(url_for('inventory'))

        if product.status == 'Sold':
            flash('Product is already sold.', 'warning')
            return redirect(url_for('inventory'))

        if product.current_stock < 1:
            flash('Insufficient stock for this product.', 'warning')
            return redirect(url_for('inventory'))

        # Fetch current gold price
        price_key = f"{product.gold_type}_{product.karat}"
        current_gold_price = GoldPrice.query.filter_by(karat=product.karat, gold_type=product.gold_type).first()

        if not current_gold_price:
            flash('Gold price not set for this product.', 'danger')
            return redirect(url_for('inventory'))

        # Calculate sale price
        price_per_gram_at_sale = current_gold_price.price_per_gram
        total_price_at_sale = price_per_gram_at_sale * product.weight

        # Create SoldProduct record
        sold_record = SoldProduct(
            product_id=product.id,
            product_name=product.product_name,
            category=product.category,
            barcode=product.barcode,
            weight=product.weight,
            karat=product.karat,
            gold_type=product.gold_type,
            size=product.size,
            current_stock_sold=1,  # Assuming single unit sale
            total_price=total_price_at_sale,
            price_per_gram=price_per_gram_at_sale,
            date_sold=datetime.utcnow(),
            customer_name=customer_name,
            sold_by=sold_by
        )

        # Update product stock and status
        product.current_stock -= 1
        if product.current_stock == 0:
            product.status = 'Sold Out'

        try:
            # Add the sold record and commit changes
            db.session.add(sold_record)
            db.session.commit()
            flash(f"Product '{product.product_name}' marked as sold successfully.", 'success')
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error marking product as sold: {e}", exc_info=True)
            flash(f"Error marking product as sold: {e}", 'danger')

        return redirect(url_for('inventory'))

    else:
        # Handle form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')

        return redirect(url_for('inventory'))



@app.route('/sales_summary', methods=['GET'])
@login_required
def sales_summary():
    # Fetch available sold dates for the filter (distinct dates)
    available_dates = db.session.query(
        func.DATE(SoldProduct.date_sold).label('date')
    ).distinct().order_by('date').all()

    # Extract date filter from request
    selected_date = request.args.get('date_sold', None)

    # Initialize the sales query
    sales_query = SoldProduct.query

    # If a date is selected, filter sales by that date
    if selected_date:
        sales_query = sales_query.filter(
            func.date(SoldProduct.date_sold) == selected_date
        )

    # Execute the query
    sales = sales_query.all()

    # Calculate statistics
    total_sales = sum(sale.total_price for sale in sales)
    total_items_sold = sum(sale.quantity_sold for sale in sales)
    average_price_per_gram = total_sales / total_items_sold if total_items_sold else 0

    # Retrieve gold prices from session
    gold_prices = session.get('gold_prices', {
        'chinese_18k': 0,
        'chinese_21k': 0,
        'saudi_18k': 0,
        'saudi_21k': 0
    })

    return render_template(
        'sales_summary.html',  # Change template here
        sales=sales,
        prices=gold_prices,
        available_dates=[date[0].strftime('%Y-%m-%d') for date in available_dates],
        selected_date=selected_date,
        total_sales=total_sales,
        total_items_sold=total_items_sold,
        average_price_per_gram=average_price_per_gram
    )


# Route to view individual sold product details
@app.route('/sold_product/<int:sale_id>', methods=['GET'])
@login_required
def view_sold_product(sale_id):
    sold_product = SoldProduct.query.get_or_404(sale_id)
    return render_template('view_sold_product.html', sold_product=sold_product)

@app.route('/product/<int:product_id>', methods=['GET'])
def view_product(product_id):
    product = Inventory.query.get_or_404(product_id)
    return render_template('view_product.html', product=product)

#Route for confirming remove
@app.route('/confirm_remove/<int:product_id>')
@login_required
def confirm_remove(product_id):
    product = Inventory.query.get_or_404(product_id)
    return render_template('confirm_remove.html', product=product)

@app.route('/void_sale/<int:sale_id>', methods=['POST'])
@login_required
def void_sale(sale_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    sold_product = SoldProduct.query.get_or_404(sale_id)

    try:
        # Fetch the associated product from the inventory
        product = Inventory.query.get(sold_product.product_id)
        
        if product:
            # Update the inventory to reflect the returned stock
            product.initial_quantity += sold_product.current_stock_sold  # Increase stock by the quantity sold
            product.status = 'Available'  # Change the status back to 'Available'

        # Remove the sold product record from the SoldProduct table
        db.session.delete(sold_product)

        # Commit the changes to the database
        db.session.commit()

        flash(f"Sale for product '{sold_product.product_name}' has been voided and the product has been returned to inventory.", "success")

    except Exception as e:
        # Rollback in case of any error
        db.session.rollback()
        flash(f"Failed to void sale and return product to inventory. Error: {e}", "error")

    return redirect(url_for('inventory'))


# Route for inventory report (accessible to admin and staff)
@app.route('/inventory-report', methods=['GET'])
@login_required
def inventory_report():
    low_stock_threshold = 5  # Define what is considered low stock

    # Group products by name and sum their quantities
    grouped_items = db.session.query(
        Inventory.product_name,
        Inventory.category,  # Adding category for display
        func.sum(Inventory.quantity).label('total_stock')
    ).group_by(Inventory.product_name, Inventory.category).all()

    # Filter the results to only show products below the low stock threshold
    low_stock_items = [item for item in grouped_items if item.total_stock < low_stock_threshold]

    return render_template('inventory_report.html', low_stock_items=low_stock_items)

@app.route('/sold_product', methods=['GET'])
@login_required
def sold_product():
    # Fetch available sold dates for the filter (distinct dates)
    available_dates_query = db.session.query(
        func.DATE(SoldProduct.date_sold).label('date')
    ).distinct().order_by('date')

    # Convert available_dates to a list of strings in 'YYYY-MM-DD' format
    available_dates = [date.date.strftime('%Y-%m-%d') for date in available_dates_query.all()]

    # Extract date filter and barcode search from request
    selected_date = request.args.get('date_sold', None)
    barcode_search = request.args.get('barcode', None)

    # Initialize the sales query
    sales_query = SoldProduct.query

    # If a date is selected, filter sales by that date
    if selected_date:
        try:
            selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d')
            sales_query = sales_query.filter(
                func.date(SoldProduct.date_sold) == selected_date_obj.date()
            )
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
            return redirect(url_for('sold_product'))

    # If a barcode search is provided, filter by barcode
    if barcode_search:
        sales_query = sales_query.filter(
            SoldProduct.barcode.ilike(f"%{barcode_search}%")
        )

    # Execute the query
    sales = sales_query.order_by(SoldProduct.date_sold.desc()).all()

    # Initialize statistics
    total_sales = sum(sale.total_price or 0 for sale in sales)
    total_items_sold = sum(sale.current_stock_sold or 0 for sale in sales)
    total_weight_sold = sum(sale.weight or 0 for sale in sales)

    # Calculate average price per gram
    average_price_per_gram = (total_sales / total_weight_sold) if total_weight_sold else 0.0

    return render_template(
        'sold_product.html',
        sales=sales,
        available_dates=available_dates,
        total_sales=total_sales,
        total_items_sold=total_items_sold,
        average_price_per_gram=average_price_per_gram,
        selected_date=selected_date
    )

# Route for customer report (accessible to admin and staff)
@app.route('/customer-report', methods=['GET'])
@login_required
def customer_report():
    # Group and order customers by total sales (similar logic to inventory grouping)
    top_customers = db.session.query(
        SoldProduct.customer_name,
        func.sum(SoldProduct.total_price).label('total_spent')
    ).group_by(SoldProduct.customer_name).order_by(func.sum(SoldProduct.total_price).desc()).limit(10).all()

    return render_template('customer_report.html', top_customers=top_customers)

@app.route('/financial_report')
def financial_report():
    total_sales = db.session.query(func.sum(SoldProduct.total_price)).scalar() or 0
    total_expenses = db.session.query(func.sum(Expense.total_price)).scalar() or 0
    profit = total_sales - total_expenses

    # Sales Over Time (using DATE_TRUNC for PostgreSQL)
    sales_over_time_query = db.session.query(
        func.date_trunc('month', SoldProduct.sold_by).label('month'),  # Replace 'sold_by' with the correct date field
        func.sum(SoldProduct.total_price).label('total')
    ).group_by(func.date_trunc('month', SoldProduct.sold_by)).order_by(func.date_trunc('month', SoldProduct.sold_by)).all()

    sales_over_time = {
        'labels': [record.month.strftime('%Y-%m') for record in sales_over_time_query],
        'values': [float(record.total) for record in sales_over_time_query]
    }

    # Expenses Over Time (using DATE_TRUNC for PostgreSQL)
    expenses_over_time_query = db.session.query(
        func.date_trunc('month', Expense.date).label('month'),  # Replace 'date' with the correct date field
        func.sum(Expense.total_price).label('total')
    ).group_by(func.date_trunc('month', Expense.date)).order_by(func.date_trunc('month', Expense.date)).all()

    expenses_over_time = {
        'labels': [record.month.strftime('%Y-%m') for record in expenses_over_time_query],
        'values': [float(record.total) for record in expenses_over_time_query]
    }

    # Sales by Category
    sales_by_category_query = db.session.query(
        SoldProduct.category,
        func.sum(SoldProduct.total_price).label('total')
    ).group_by(SoldProduct.category).all()

    sales_by_category = {record.category: float(record.total) for record in sales_by_category_query}

    # Expenses by Category
    expenses_by_category_query = db.session.query(
        Expense.category,
        func.sum(Expense.total_price).label('total')
    ).group_by(Expense.category).all()

    expenses_by_category = {record.category: float(record.total) for record in expenses_by_category_query}

    return render_template(
        'financial_report.html',
        total_sales=total_sales,
        total_expenses=total_expenses,
        profit=profit,
        sales_over_time=sales_over_time,
        expenses_over_time=expenses_over_time,
        sales_by_category=sales_by_category,
        expenses_by_category=expenses_by_category
    )


@app.route('/sales_report', methods=['GET'])
@login_required
def sales_report():
    # Fetch gold prices from the database
    gold_prices_query = GoldPrice.query.all()
    prices = {f"{gp.gold_type}_{gp.karat}": gp.price_per_gram for gp in gold_prices_query}

    # Fetch the selected date from request arguments
    selected_date = request.args.get('date_sold', '')

    # Fetch available dates with sold products
    try:
        available_dates = (
            db.session.query(func.date(SoldProduct.date_sold))
            .filter(SoldProduct.current_stock_sold > 0)  # Only include dates with sold products
            .distinct()
            .all()
        )
        available_dates = [date[0].strftime('%Y-%m-%d') for date in available_dates if date[0]]
    except Exception as e:
        db.session.rollback()
        flash(f"Error fetching available dates: {str(e)}", 'error')
        available_dates = []

    # Prepare the sales query
    try:
        sales_query = db.session.query(
            SoldProduct.id,
            SoldProduct.product_name,
            SoldProduct.category,
            SoldProduct.karat,
            SoldProduct.gold_type,
            SoldProduct.weight,
            SoldProduct.size,
            SoldProduct.barcode,
            SoldProduct.total_price.label('total_sales'),
            SoldProduct.price_per_gram,
            func.sum(SoldProduct.current_stock_sold).label('total_quantity')
        )

        if selected_date:
            sales_query = sales_query.filter(
                func.date(SoldProduct.date_sold) == func.to_date(selected_date, 'YYYY-MM-DD')
            )

        sales_query = sales_query.group_by(
            SoldProduct.id,
            SoldProduct.product_name,
            SoldProduct.category,
            SoldProduct.karat,
            SoldProduct.gold_type,
            SoldProduct.weight,
            SoldProduct.size,
            SoldProduct.barcode,
            SoldProduct.total_price,
            SoldProduct.price_per_gram
        ).order_by(SoldProduct.product_name)

        sales_data = sales_query.all()  # Execute the query here
    except Exception as e:
        db.session.rollback()
        flash(f"Error fetching sales data: {str(e)}", 'error')
        sales_data = []

    # Prepare sales summary data
    total_sales_summary = {}
    detailed_sales = []

    for entry in sales_data:
        total_sales_summary[entry.product_name] = total_sales_summary.get(entry.product_name, 0) + float(entry.total_sales)
        detailed_sales.append({
            'id': entry.id,
            'product_name': entry.product_name,
            'category': entry.category,
            'price': float(entry.total_sales / entry.total_quantity) if entry.total_quantity else 0,
            'karat': entry.karat,
            'gold_type': entry.gold_type,
            'weight': entry.weight,
            'size': entry.size,
            'barcode': entry.barcode,
            'total_quantity': entry.total_quantity,
            'total_sales': float(entry.total_sales),
            'price_per_gram': entry.price_per_gram
        })

    return render_template(
        'sales_report.html',
        sales_data={
            'period_label': 'Date',
            'periods': [selected_date] if selected_date else ['All Dates'],
            'sales': [total_sales_summary.get(name, 0) for name in total_sales_summary.keys()]
        },
        detailed_sales=detailed_sales,
        selected_date=selected_date,
        available_dates=available_dates
    )

@app.route('/admin_power', methods=['GET'])
@login_required
def admin_power():
    # Check if the logged-in user has the 'admin' role
    if not current_user.role == 'admin':
        flash('Access denied: You do not have permission to view this page.', 'danger')
        abort(403)  # HTTP 403 Forbidden

    today_date = datetime.today()
    current_date_str = today_date.strftime('%Y-%m-%d')

    # Get selected dates from query parameters
    selected_date = request.args.get('date', default='all', type=str)
    selected_sold_date = request.args.get('sold_date', default='all', type=str)
    selected_added_date = request.args.get('added_date', default='all', type=str)

    # Parse selected_date if not 'all'
    selected_date_obj = None
    if selected_date != "all":
        try:
            selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d')
        except ValueError:
            flash("Invalid date format for 'Login Date'. Please use YYYY-MM-DD.", 'danger')
            return redirect(url_for('admin_power'))

    # Fetch gold prices from the database
    gold_prices_query = GoldPrice.query.all()
    prices = {f"{gp.gold_type}_{gp.karat}": gp.price_per_gram for gp in gold_prices_query}

    # Fetch and count logins
    if selected_date_obj:
        login_count_today = UserLogin.query.filter(
            func.date(UserLogin.login_time) == selected_date_obj.date()
        ).count()
        user_logins = UserLogin.query.filter(
            func.date(UserLogin.login_time) == selected_date_obj.date()
        ).all()
    else:
        login_count_today = UserLogin.query.count()
        user_logins = UserLogin.query.all()

    # Fetch added products (including deleted ones)
    if selected_added_date != "all":
        try:
            added_date_obj = datetime.strptime(selected_added_date, '%Y-%m-%d')
            added_products = Inventory.query.filter(
                func.date(Inventory.created_at) == added_date_obj.date()
            ).order_by(Inventory.created_at).all()
            added_products_count = len(added_products)
        except ValueError:
            flash("Invalid date format for 'Added Date'. Please use YYYY-MM-DD.", 'danger')
            return redirect(url_for('admin_power'))
    else:
        added_products = Inventory.query.order_by(Inventory.created_at).all()
        added_products_count = len(added_products)

    # Fetch sold products
    if selected_sold_date != "all":
        try:
            sold_date_obj = datetime.strptime(selected_sold_date, '%Y-%m-%d')
            sold_products = SoldProduct.query.filter(
                func.date(SoldProduct.date_sold) == sold_date_obj.date()
            ).order_by(SoldProduct.date_sold).all()
        except ValueError:
            flash("Invalid date format for 'Sold Date'. Please use YYYY-MM-DD.", 'danger')
            return redirect(url_for('admin_power'))
    else:
        sold_products = SoldProduct.query.order_by(SoldProduct.date_sold).all()

    # Calculate total sold value and items sold
    total_sold_value = sum(float(sale.total_price) for sale in sold_products)
    total_items_sold = sum(sale.current_stock_sold for sale in sold_products)

    # Prepare dropdown dates for user logins
    dates = [('all', 'All Dates')]
    login_dates = db.session.query(func.date(UserLogin.login_time)).distinct().order_by(func.date(UserLogin.login_time).desc()).all()
    for date_tuple in login_dates:
        date_str = date_tuple[0].strftime('%Y-%m-%d')
        dates.append((date_str, date_str))

    # Fetch sold and added dates for dropdowns
    sold_product_dates = db.session.query(func.date(SoldProduct.date_sold)).distinct().order_by(func.date(SoldProduct.date_sold).desc()).all()
    sold_dates = [('all', 'All Sold Dates')]
    for date_tuple in sold_product_dates:
        date_str = date_tuple[0].strftime('%Y-%m-%d')
        sold_dates.append((date_str, date_str))

    added_product_dates = db.session.query(func.date(Inventory.created_at)).distinct().order_by(func.date(Inventory.created_at).desc()).all()
    added_dates = [('all', 'All Added Dates')]
    for date_tuple in added_product_dates:
        date_str = date_tuple[0].strftime('%Y-%m-%d')
        added_dates.append((date_str, date_str))

    # Build a dictionary to track sold quantities by batch number and other attributes
    remaining_sold_quantities = {}
    for sale in sold_products:
        batch_number = sale.product.batch_number
        key = (batch_number, sale.product_name, sale.size, sale.karat, sale.gold_type)
        if key not in remaining_sold_quantities:
            remaining_sold_quantities[key] = 0
        remaining_sold_quantities[key] += sale.current_stock_sold

    total_deleted_items = sum(1 for item in added_products if item.existence == 'Deleted')

    # Group added products by batch number and other attributes
    products_grouped = {}
    for item in added_products:
        group_key = (item.batch_number, item.product_name, item.size, item.karat, item.gold_type)
        if group_key not in products_grouped:
            products_grouped[group_key] = {
                'product': item,
                'initial_quantity': item.initial_quantity,
                'total_weight': item.weight * item.initial_quantity,
                'existence': item.existence,  # Include existence
            }
        else:
            # Aggregate quantities and weight for grouped entries
            products_grouped[group_key]['initial_quantity'] += item.initial_quantity
            products_grouped[group_key]['total_weight'] += item.weight * item.initial_quantity

    # Calculate available stock and inventory value
    inventory_grouped_list = []
    total_available_items = 0
    total_inventory_value = 0
    for group_key, data in products_grouped.items():
        batch_number, product_name, size, karat, gold_type = group_key
        item = data['product']
        initial_quantity = data['initial_quantity']
        total_weight = data['total_weight']
        existence = data['existence']

        # Fetch remaining sold quantity for this group
        remaining_sold = remaining_sold_quantities.get(group_key, 0)
        applied_sold_quantity = min(initial_quantity, remaining_sold)

        # Update remaining sold quantities
        if group_key in remaining_sold_quantities:
            remaining_sold_quantities[group_key] -= applied_sold_quantity

        # Calculate current stock
        current_stock = initial_quantity - applied_sold_quantity

        # If the batch is marked as 'Deleted', set current_stock to 0
        if existence == 'Deleted':
            current_stock = 0

        # Calculate inventory value
        price_key = f"{gold_type}_{karat}"
        price_per_gram = prices.get(price_key, 0)
        weight_per_item = total_weight / initial_quantity if initial_quantity != 0 else 0
        inventory_value = max(current_stock, 0) * weight_per_item * price_per_gram

        # Only count current stock and inventory value if the batch is not deleted
        if existence != 'Deleted':
            total_available_items += max(current_stock, 0)
            total_inventory_value += inventory_value

        # Append to grouped inventory list
        inventory_grouped_list.append({
            'batch_number': batch_number,
            'product_name': product_name,
            'size': size,
            'weight': total_weight,
            'initial_quantity': initial_quantity,
            'price_per_gram': price_per_gram,  # This represents current price if needed
            'frozen_price_per_gram': item.frozen_price_per_gram,  # Ensure this is the value used from the database
            'inventory_value': inventory_value,
            'created_at': item.created_at,
            'current_stock': max(current_stock, 0),
            'existence': existence,
            'category': item.category,
            'karat': karat,
            'gold_type': gold_type,
        })

    return render_template(
        'admin_power.html',
        login_count_today=login_count_today,
        added_products_count=added_products_count,
        total_sold_value=total_sold_value,
        total_items_sold=total_items_sold,
        sold_products=sold_products,
        inventory_grouped=inventory_grouped_list,
        total_inventory_value=total_inventory_value,
        total_available_items=total_available_items,
        total_deleted_items=total_deleted_items,  # New variable
        selected_date=selected_date,
        selected_sold_date=selected_sold_date,
        selected_added_date=selected_added_date,
        dates=dates,
        sold_dates=sold_dates,
        added_dates=added_dates,
        user_logins=user_logins,
        prices=prices
    )
    

@app.route('/remove_batch', methods=['DELETE'])
@login_required
def remove_batch():
    try:
        data = request.get_json()
        product_name = data.get("product_name")
        batch_number = data.get("batch_number")

        if not product_name or batch_number is None:
            return jsonify({"error": "Batch number and product name are required"}), 400

        # Convert batch_number to integer
        try:
            batch_number = int(batch_number)
        except ValueError:
            return jsonify({"error": "Batch number must be an integer"}), 400

        # Update 'existence' instead of deleting records
        batch_to_remove = Inventory.query.filter_by(
            product_name=product_name,
            batch_number=batch_number
        ).update({"existence": "Deleted"})

        if batch_to_remove == 0:
            return jsonify({"error": "Batch not found"}), 404

        db.session.commit()
        return jsonify({"message": "Batch marked as Deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error marking batch as Deleted: {e}")
        return jsonify({"error": f"Failed to mark batch as Deleted: {str(e)}"}), 500


@app.route('/reports')
@login_required
def reports_dashboard():
    # Initialize data for various reports
    report_data = {
        'sales_report': [],
        'inventory_report': [],
        'customer_report': [],
        'financial_report': {}
    }

    # Fetch data for the sales report
    try:
        sales_data = db.session.query(
            SoldProduct.date_sold,
            func.sum(SoldProduct.total_price).label('total_sales')
        ).group_by(SoldProduct.date_sold).all()

        report_data['sales_report'] = [{'date': date, 'total_sales': total_sales} for date, total_sales in sales_data]
    except Exception as e:
        flash(f"Error fetching sales data: {str(e)}", 'error')

    # Fetch data for the inventory report (adjust based on your Inventory model)
    try:
        low_stock_threshold = 5
        low_stock_items = db.session.query(
            Inventory.product_name,
            func.sum(Inventory.initial_quantity).label('total_stock')
        ).group_by(Inventory.product_name).having(func.sum(Inventory.current_stock) < low_stock_threshold).all()

        report_data['inventory_report'] = [{'product_name': name, 'total_stock': total_stock} for name, total_stock in low_stock_items]
    except Exception as e:
        flash(f"Error fetching inventory data: {str(e)}", 'error')

    # Fetch data for the customer report
    try:
        top_customers = db.session.query(
            SoldProduct.customer_name,
            func.sum(SoldProduct.total_price).label('total_spent')
        ).group_by(SoldProduct.customer_name).order_by(func.sum(SoldProduct.total_price).desc()).limit(10).all()

        report_data['customer_report'] = [{'customer_name': name, 'total_spent': total_spent} for name, total_spent in top_customers]
    except Exception as e:
        flash(f"Error fetching customer data: {str(e)}", 'error')

    # Fetch data for the financial report
    try:
        total_sales = db.session.query(func.sum(SoldProduct.total_price)).scalar() or 0
        total_expenses = db.session.query(func.sum(Expense.total_price)).scalar() or 0
        profit = total_sales - total_expenses

        report_data['financial_report'] = {
            'total_sales': total_sales,
            'total_expenses': total_expenses,
            'profit': profit
        }
    except Exception as e:
        flash(f"Error fetching financial data: {str(e)}", 'error')

    # Render the reports template with the gathered data
    return render_template('reports.html', report_data=report_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create the tables based on the models
    app.run(debug=True)