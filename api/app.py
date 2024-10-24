from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from models.database import db, Inventory, SoldProduct, Expense, User
from forms.forms import AddProductForm, EditProductForm, AddExpenseForm, LoginForm, GoldPricesForm
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime
from barcode.writer import ImageWriter
from math import ceil
from barcode import Code128
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_talisman import Talisman
from datetime import timedelta

import os
import random
import string
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql+pg8000://postgres:password@localhost/jewelry_management')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

with app.app_context():
    users = User.query.all()
    for user in users:
        # Only hash if the password is not already hashed
        if not user.password.startswith('pbkdf2:sha256') and not user.password.startswith('scrypt:'):
            hashed_password = generate_password_hash(user.password)
            user.password = hashed_password
    db.session.commit()
    print("All passwords have been hashed!")


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
    return db.session.get(User, int(user_id))  # Ensure compatibility with SQLAlchemy 2.x

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
        '24K': '24'
    }
    gold_type_prefixes = {
        'Chinese Gold': 'CHI',
        'Saudi Gold': 'SAU',
        'Italian Gold': 'ITA'
    }
    category_prefix = category_prefixes.get(category, 'OTH')
    karat_prefix = karat_prefixes.get(karat, 'UNK')
    gold_type_prefix = gold_type_prefixes.get(gold_type, 'OTH')
    random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    barcode = f"{category_prefix}-{karat_prefix}-{gold_type_prefix}-{random_suffix}"
    return barcode

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # Check if the form is submitted and validated correctly
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        # Try to find the user by username
        user = User.query.filter_by(username=username).first()

        # Logging for debugging purposes
        if user:
            app.logger.debug(f"User found: {user.username}")
        else:
            app.logger.debug(f"No user found with username: {username}")

        # Check if the user exists and if the password is correct
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')

            # Logging successful login
            app.logger.debug(f"User {username} logged in successfully.")

            return redirect(url_for('dashboard'))
        else:
            # Provide a more specific log for failed login attempts
            app.logger.debug(f"Failed login attempt for username: {username}")

            # Flash message for incorrect credentials
            flash('Invalid username or password', 'error')

    # If the request is a GET or the form validation fails, render the login template
    return render_template('login.html', form=form)


@app.route('/create_user', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
def create_user():
    # Only allow admins to access the page
    if current_user.role != 'admin':
        flash('Access denied. Only admins can create new users.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        role = request.form.get('role').lower()

        # Basic validation for empty fields
        if not username or not password or not role:
            flash('All fields are required.', 'error')
            return redirect(url_for('create_user'))

        # Ensure the role is valid
        if role not in ['admin', 'staff', 'guest']:
            flash('Invalid role. Choose admin, staff, or guest.', 'error')
            return redirect(url_for('create_user'))

        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('create_user'))

        # Hash the password
        hashed_password = generate_password_hash(password)

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
            return redirect(url_for('create_user'))

    return render_template('create_user.html')

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

@app.before_request
def enforce_logout():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))  # Redirect to login if session expired

# General dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
# Expense list route (restricted to admin only)
@app.route('/expenses')
@login_required
def expenses():
    if current_user.role == 'staff':
        flash('You are not authorized to view this page', 'error')
        return redirect(url_for('dashboard'))
    expenses_list = Expense.query.all()
    return render_template('expense_list.html', expenses=expenses_list)

# Inventory accessible to admin and staff (guests cannot access)

@app.route('/update_gold_prices', methods=['POST'])
@login_required
def update_gold_prices():
    # Get new prices from the form
    new_chinese_18k = float(request.form.get('chinese_18k'))
    new_chinese_21k = float(request.form.get('chinese_21k'))
    new_saudi_18k = float(request.form.get('saudi_18k'))
    new_saudi_21k = float(request.form.get('saudi_21k'))

    # Store the updated prices in session (or save to the database)
    session['gold_prices'] = {
        'chinese_18k': new_chinese_18k,
        'chinese_21k': new_chinese_21k,
        'saudi_18k': new_saudi_18k,
        'saudi_21k': new_saudi_21k
    }

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

    # Fetch necessary data
    page = request.args.get('page', 1, type=int)
    per_page = 1000  # Number of items per page for the main table

    # Base query for inventory (assuming sizes is a relationship or attribute in the Inventory model)
    query = Inventory.query.options(db.joinedload('sizes'))  # Load sizes with the inventory items

    # Paginate the main inventory items
    paginated_items = query.paginate(page=page, per_page=per_page, error_out=False)

    # Retrieve gold prices from session or use default values if not set
    gold_prices = session.get('gold_prices', {
        'chinese_18k': 0,
        'chinese_21k': 0,
        'saudi_18k': 0,
        'saudi_21k': 0
    })

    # Pass the form and the paginated items to the template
    return render_template(
        'inventory.html',
        items=paginated_items.items,  # Pass the items directly
        total_pages=paginated_items.pages,
        current_page=page,
        previous_page=paginated_items.prev_num,
        next_page=paginated_items.next_num,
        prices=gold_prices,
        form=gold_prices_form  # Pass the GoldPricesForm instance to the template
    )


@app.route('/inventory_tree')
@login_required
def inventory_tree():
    # Group products by category and subcategory, and calculate the count
    inventory_items = Inventory.query.all()
    
    inventory_tree = {}
    for item in inventory_items:
        if item.category not in inventory_tree:
            inventory_tree[item.category] = {'products': [], 'count': 0}

        # Add product to the category group and increase the count
        inventory_tree[item.category]['products'].append(item)
        inventory_tree[item.category]['count'] += 1

    return render_template('inventory_tree.html', inventory_tree=inventory_tree)


# Catalog accessible to everyone (Guests do not need login)
@app.route('/catalog')
def catalog():
    # Retrieve gold prices from session or use default values
    gold_prices = session.get('gold_prices', {
        'chinese_18k': 0,
        'chinese_21k': 0,
        'saudi_18k': 0,
        'saudi_21k': 0
    })

    # Fetch filters from request arguments
    category = request.args.get('category', 'all')
    price_min = request.args.get('price_min', 0, type=float)
    price_max = request.args.get('price_max', float('inf'), type=float)
    sort_by = request.args.get('sort_by', 'price_asc')
    karat = request.args.get('karat', 'all')
    gold_type = request.args.get('gold_type', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 48, type=int)
    search_query = request.args.get('search_query', '').strip()

    # Fetch distinct categories, karats, and gold types from the inventory
    categories = Inventory.query.with_entities(Inventory.category).distinct().all()
    categories = [c[0] for c in categories]

    karats = Inventory.query.with_entities(Inventory.karat).distinct().all()
    karats = [k[0] for k in karats]

    gold_types = Inventory.query.with_entities(Inventory.gold_type).distinct().all()
    gold_types = [g[0] for g in gold_types]

    # Fetch products based on filters
    query = Inventory.query

    # Filter by category
    if category != 'all':
        query = query.filter(Inventory.category == category)

    # Filter by price range
    query = query.filter(Inventory.price_per_unit >= price_min, Inventory.price_per_unit <= price_max)

    # Filter by karat
    if karat != 'all':
        query = query.filter(Inventory.karat == karat)

    # Filter by gold type
    if gold_type != 'all':
        query = query.filter(Inventory.gold_type == gold_type)

    # Filter by search query (case-insensitive)
    if search_query:
        query = query.filter(Inventory.product_name.ilike(f'%{search_query}%'))

    # Sorting logic
    if sort_by == 'price_asc':
        query = query.order_by(Inventory.price_per_unit.asc())
    elif sort_by == 'price_desc':
        query = query.order_by(Inventory.price_per_unit.desc())
    else:
        query = query.order_by(Inventory.id.desc())  # Default sort by newest

    # Fetch the products with pagination
    total_items = query.count()
    total_pages = ceil(total_items / per_page)
    paginated_items = query.paginate(page=page, per_page=per_page, error_out=False)

    # Group products by name and size, then aggregate stock for each size
    products_grouped = {}
    for item in paginated_items.items:
        product_key = item.product_name

        if product_key not in products_grouped:
            products_grouped[product_key] = {
                'product': item,
                'sizes': {},
                'stock': 0
            }

        size = item.size
        if size not in products_grouped[product_key]['sizes']:
            products_grouped[product_key]['sizes'][size] = 0

        products_grouped[product_key]['sizes'][size] += item.quantity
        products_grouped[product_key]['stock'] += item.quantity

    products_grouped_list = [
        {'product': data['product'], 'sizes': data['sizes'], 'stock': data['stock']}
        for data in products_grouped.values()
    ]

    recently_viewed = Inventory.query.order_by(Inventory.id.desc()).limit(4).all()

    return render_template(
        'catalog.html',
        products=products_grouped_list,
        recently_viewed=recently_viewed,
        categories=categories,
        karats=karats,
        gold_types=gold_types,
        previous_page=page - 1 if page > 1 else None,
        next_page=page + 1 if page < total_pages else None,
        total_pages=total_pages,
        current_page=page,
        category=category,
        price_min=price_min,
        price_max=price_max,
        karat=karat,
        gold_type=gold_type,
        sort_by=sort_by,
        per_page=per_page,
        search_query=search_query,  # Pass the search query to the template
        prices=gold_prices  # Pass the prices to the template
    )


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

# Route to add a product (available to admins and staff)
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role not in ['admin', 'staff']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    form = AddProductForm()
    warning_message = None

    if form.validate_on_submit():
        photo = form.photo.data  # Use form.photo.data

        # Ensure the upload folder exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        # Save the uploaded photo securely
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_path)

        # Retrieve gold prices from session
        gold_prices = session.get('gold_prices', {
            'chinese_18k': 0,
            'chinese_21k': 0,
            'saudi_18k': 0,
            'saudi_21k': 0
        })

        # Determine price per gram based on karat and gold type
        karat = form.karat.data
        gold_type = form.gold_type.data

        if karat == '18K' and gold_type == 'Chinese Gold':
            price_per_gram = gold_prices['chinese_18k']
        elif karat == '21K' and gold_type == 'Chinese Gold':
            price_per_gram = gold_prices['chinese_21k']
        elif karat == '18K' and gold_type == 'Saudi Gold':
            price_per_gram = gold_prices['saudi_18k']
        elif karat == '21K' and gold_type == 'Saudi Gold':
            price_per_gram = gold_prices['saudi_21k']
        else:
            price_per_gram = 0  # Default or handle as needed

        # Calculate price per unit
        price_per_unit = form.weight.data * price_per_gram

        # Check if a product with the same name and size already exists
        existing_product = Inventory.query.filter_by(
            product_name=form.product_name.data,
            size=form.size.data
        ).first()

        if existing_product:
            # Update the quantity of the existing product
            existing_product.quantity += form.quantity.data
            flash(f"Updated quantity of {form.product_name.data} (Size: {form.size.data}) to {existing_product.quantity}.", "success")
        else:
            # Create new product entries based on quantity
            for _ in range(form.quantity.data):
                barcode_value = generate_barcode(form.category.data, form.karat.data, form.gold_type.data)
                new_product = Inventory(
                        product_name=form.product_name.data,
                        category=form.category.data,
                        quantity=1,
                        price_per_unit=price_per_unit,
                        karat=form.karat.data,
                        gold_type=form.gold_type.data,
                        weight=form.weight.data,
                        size=form.size.data,
                        barcode=barcode_value,
                        image_url=photo_path,
                        printed=False  # Set printed to False for new products
                    )
                db.session.add(new_product)

        try:
            db.session.commit()

            # If a new product was created, generate the barcode
            if not existing_product:
                barcode_path = os.path.join('static', 'barcodes', f"{barcode_value}.png")
                code128 = Code128(barcode_value, writer=ImageWriter())
                code128.save(barcode_path)

                # Redirect to the new product details page
                return redirect(url_for('new_product', product_id=new_product.id))

            flash(f"{form.quantity.data} units of '{form.product_name.data}' added successfully!", "success")
            return redirect(url_for('inventory'))

        except Exception as e:
            db.session.rollback()
            warning_message = f"Error adding product to inventory: {e}"

    if form.errors:
        warning_message = "Please fill in all fields correctly."

    return render_template('add_product.html', form=form, warning_message=warning_message)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/products', methods=['GET'])
@login_required
def products():
    # Fetch unprinted products from the database
    unprinted_products = Inventory.query.filter_by(printed=False).all()
    return render_template('products.html', products=unprinted_products)

@app.before_request
def session_management():
    session.permanent = True  # Make the session permanent
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

@app.route('/update_printed_status', methods=['POST'])
@login_required
def update_printed_status():
    data = request.get_json()
    product_ids = data.get('product_ids', [])
    
    try:
        for product_id in product_ids:
            product = Inventory.query.get(product_id)
            if product:
                product.printed = True  # Set printed to True
        db.session.commit()
        return jsonify({"message": "Printed status updated successfully."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": str(e)}), 400
    
@app.route('/batch_print', methods=['POST'])
@login_required
def batch_print():
    # Fetch unprinted products from the database
    unprinted_products = Inventory.query.filter_by(printed=False).all()
    
    if not unprinted_products:
        flash('No unprinted products available for printing.', 'info')
        return jsonify({"message": "No unprinted products available."}), 404

    # Render the template for printing (you can customize this as needed)
    return render_template('print_batch.html', products=unprinted_products)

# Route to edit product details (available to admin and staff)
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role not in ['admin', 'staff']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    product = Inventory.query.get_or_404(product_id)
    form = EditProductForm(obj=product)
    if form.validate_on_submit():
        product.product_name = form.product_name.data
        product.category = form.category.data
        product.quantity = form.quantity.data
        product.price_per_unit = form.price_per_unit.data
        product.karat = form.karat.data
        product.gold_type = form.gold_type.data
        product.weight = form.weight.data
        product.size = form.size.data
        db.session.commit()
        flash(f"Product '{product.product_name}' updated successfully!", "success")
        return redirect(url_for('inventory'))
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

# Mark as sold and move to sold products (available to admin and staff)
@app.route('/mark_as_sold/<int:product_id>', methods=['POST'])
@login_required
def mark_as_sold(product_id):
    if current_user.role not in ['admin', 'staff']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    product = Inventory.query.get_or_404(product_id)

    try:
        sold_record = SoldProduct(
            product_name=product.product_name,
            category=product.category,
            quantity_sold=1,
            total_price=product.price_per_unit,
            date_sold=datetime.now(),
            karat=product.karat,
            gold_type=product.gold_type,
            weight=product.weight,
            size=product.size,  # Fetch size directly from Inventory
            barcode=product.barcode
        )

        db.session.add(sold_record)
        
        if product.quantity > 1:
            product.quantity -= 1
        else:
            db.session.delete(product)

        db.session.commit()
        flash(f"Product '{product.product_name}' marked as sold!", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Failed to mark the product as sold. Error: {e}", "error")

    return redirect(url_for('inventory'))

@app.route('/sold_product', methods=['GET'])
@login_required
def sold_product():
    sales_data = SoldProduct.query.all()
    
    # Debugging: log the sales data
    if not sales_data:
        app.logger.debug("No sales records found.")
    else:
        # Check for None entries
        sales_data = [sale for sale in sales_data if sale is not None]

    # Retrieve gold prices from session or use default values if not set
    gold_prices = session.get('gold_prices', {
        'chinese_18k': 0,
        'chinese_21k': 0,
        'saudi_18k': 0,
        'saudi_21k': 0
    })
    return render_template('sold_product.html', sales=sales_data, prices=gold_prices)



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

# Route for voiding sales
@app.route('/void_sale/<int:sale_id>', methods=['POST'])
@login_required
def void_sale(sale_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    # Fetch the sold product record
    sold_product = SoldProduct.query.get_or_404(sale_id)
    
    try:
        # Check if the product exists in the inventory
        inventory_product = Inventory.query.filter_by(
            product_name=sold_product.product_name,
            size=sold_product.size,
            karat=sold_product.karat,
            gold_type=sold_product.gold_type
        ).first()
        
        # If the product is found in inventory, increase its quantity
        if inventory_product:
            inventory_product.quantity += sold_product.quantity_sold
        else:
            # If the product was fully sold out, re-add it to the inventory
            new_inventory_product = Inventory(
                product_name=sold_product.product_name,
                category=sold_product.category,
                weight=sold_product.weight,
                karat=sold_product.karat,
                gold_type=sold_product.gold_type,
                size=sold_product.size,
                barcode=sold_product.barcode,
                quantity=sold_product.quantity_sold,  # Add back the sold quantity
                price_per_unit=sold_product.total_price / sold_product.quantity_sold if sold_product.quantity_sold else 0,
                price_per_gram=None,  # Adjust this if price per gram is needed
                image_url=None,  # Optional: Add this if product images are tracked
                printed=False  # Optional: Set this based on your system
            )
            db.session.add(new_inventory_product)
        
        # Remove the sold product record from the sold products table
        db.session.delete(sold_product)
        
        # Commit the changes to the database
        db.session.commit()

        flash(f"Sale for product '{sold_product.product_name}' has been voided and returned to inventory.", "success")
    
    except Exception as e:
        # Rollback in case of any error
        db.session.rollback()
        flash(f"Failed to void sale. Error: {e}", "error")
    
    return redirect(url_for('sold_product'))

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

@app.route('/sales_report', methods=['GET', 'POST'])
@login_required
def sales_report():
    # Time frame filter from URL
    time_frame = request.args.get('time_frame', 'monthly')

    # Date filter inputs (optional)
    start_date = request.args.get('start_date', '2023-01-01')
    end_date = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))

    # Initialize sales data dictionary
    sales_data = {}

    # Query for daily sales
    daily_sales_query = db.session.query(
        func.strftime('%Y-%m-%d', SoldProduct.date_sold).label('period'),
        func.sum(SoldProduct.total_price).label('total_sales')
    ).group_by('period').order_by('period').all()

    # Query for weekly sales
    weekly_sales_query = db.session.query(
        func.strftime('%Y-%W', SoldProduct.date_sold).label('period'),
        func.sum(SoldProduct.total_price).label('total_sales')
    ).group_by('period').order_by('period').all()

    # Query for monthly sales
    monthly_sales_query = db.session.query(
        func.strftime('%Y-%m', SoldProduct.date_sold).label('period'),
        func.sum(SoldProduct.total_price).label('total_sales')
    ).group_by('period').order_by('period').all()

    # Query for yearly sales
    yearly_sales_query = db.session.query(
        func.strftime('%Y', SoldProduct.date_sold).label('period'),
        func.sum(SoldProduct.total_price).label('total_sales')
    ).group_by('period').order_by('period').all()

    # Convert query results to list of dictionaries
    sales_data['daily'] = [{'period': period, 'total_sales': float(total_sales)} for period, total_sales in daily_sales_query]
    sales_data['weekly'] = [{'period': period, 'total_sales': float(total_sales)} for period, total_sales in weekly_sales_query]
    sales_data['monthly'] = [{'period': period, 'total_sales': float(total_sales)} for period, total_sales in monthly_sales_query]
    sales_data['yearly'] = [{'period': period, 'total_sales': float(total_sales)} for period, total_sales in yearly_sales_query]

    # Prepare labels and data for the chart based on the selected time frame
    labels = [entry['period'] for entry in sales_data.get(time_frame, [])]
    data = [entry['total_sales'] for entry in sales_data.get(time_frame, [])]

    # Retrieve filtered sales records (based on start and end date)
    sales_records = SoldProduct.query.filter(
        SoldProduct.date_sold.between(start_date, end_date)
    ).all()

    # Compute statistics for the filtered records
    total_sales = sum(sale.total_price for sale in sales_records)
    total_products_sold = len(sales_records)

    # Render template with both sales summary and detailed records
    return render_template(
        'sales_report.html',
        sales_data=sales_data,
        sales_records=sales_records,
        time_frame=time_frame,
        labels=labels,
        data=data,
        start_date=start_date,
        end_date=end_date,
        total_sales=total_sales,
        total_products_sold=total_products_sold
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

# Route for financial report (accessible to admin and staff)
@app.route('/financial-report', methods=['GET'])
@login_required
def financial_report():
    # Get filter from URL parameters
    start_date = request.args.get('start_date', '2023-01-01')
    end_date = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))

    # Calculate total sales and expenses for the given date range
    total_sales = db.session.query(func.sum(SoldProduct.total_price)).filter(
        SoldProduct.date_sold.between(start_date, end_date)).scalar()

    total_expenses = db.session.query(func.sum(Expense.total_price)).filter(
        Expense.time_bought.between(start_date, end_date)).scalar()

    profit = total_sales - total_expenses if total_sales and total_expenses else 0

    return render_template('financial_report.html', profit=profit, total_sales=total_sales, total_expenses=total_expenses)

@app.route('/reports')
@login_required
def reports_dashboard():
    return render_template('reports.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create the tables based on the models
    app.run(debug=True)

