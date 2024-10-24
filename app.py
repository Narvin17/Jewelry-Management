from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from models.database import db, Inventory, SoldProduct, Expense, UserLogin, User
from forms.forms import AddProductForm, EditProductForm, AddExpenseForm, LoginForm, GoldPricesForm, CreateUserForm  
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
from sqlalchemy import cast, Date
from dotenv import load_dotenv

import os
import random
import string

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql+pg8000://postgres:password@localhost/jewelry_management')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            # Log the login time
            new_login = UserLogin(user_id=user.id)
            db.session.add(new_login)
            db.session.commit()

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    # Create an instance of your form class
    form = CreateUserForm()

    if form.validate_on_submit():  # Validate form on POST
        username = form.username.data.strip()
        password = form.password.data.strip()
        role = form.role.data.lower()

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

    tree_page = request.args.get('tree_page', 1, type=int)
    tree_per_page = 10  # Number of categories per page in the tree

    # Base query for inventory
    query = Inventory.query

    # Paginate the main inventory items
    paginated_items = query.paginate(page=page, per_page=per_page, error_out=False)

    # Create an inventory tree grouped by Category -> Karat -> Gold Type
    inventory_tree = {}

    for item in paginated_items.items:
        category = item.category
        karat = item.karat
        gold_type = item.gold_type

        if category not in inventory_tree:
            inventory_tree[category] = {'karat': {}, 'count': 0}

        if karat not in inventory_tree[category]['karat']:
            inventory_tree[category]['karat'][karat] = {'gold_type': {}, 'count': 0}

        if gold_type not in inventory_tree[category]['karat'][karat]['gold_type']:
            inventory_tree[category]['karat'][karat]['gold_type'][gold_type] = {'items': [], 'count': 0}

        # Add item details under the correct category, karat, and gold type
        inventory_tree[category]['karat'][karat]['gold_type'][gold_type]['items'].append(item)

        # Increment stock counts at each level
        inventory_tree[category]['count'] += item.quantity
        inventory_tree[category]['karat'][karat]['count'] += item.quantity
        inventory_tree[category]['karat'][karat]['gold_type'][gold_type]['count'] += item.quantity

    # Pagination logic for the inventory tree
    total_tree_items = len(inventory_tree)
    total_tree_pages = ceil(total_tree_items / tree_per_page)

    # Slicing inventory tree for pagination (simulated as list for simplicity)
    paginated_tree_items = list(inventory_tree.items())[(tree_page - 1) * tree_per_page:tree_page * tree_per_page]

    # Retrieve gold prices from session or use default values if not set
    gold_prices = session.get('gold_prices', {
        'chinese_18k': 0,
        'chinese_21k': 0,
        'saudi_18k': 0,
        'saudi_21k': 0
    })

    # Pass the form to the template
    return render_template(
        'inventory.html',
        items=paginated_items.items,
        inventory_tree=dict(paginated_tree_items),
        total_pages=paginated_items.pages,
        current_page=page,
        previous_page=paginated_items.prev_num,
        next_page=paginated_items.next_num,
        total_tree_pages=total_tree_pages,
        current_tree_page=tree_page,
        previous_tree_page=tree_page - 1 if tree_page > 1 else None,
        next_tree_page=tree_page + 1 if tree_page < total_tree_pages else None,
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
        previous_page=page-1 if page > 1 else None,
        next_page=page+1 if page < total_pages else None,
        total_pages=total_pages,
        current_page=page,
        category=category,
        price_min=price_min,
        price_max=price_max,
        karat=karat,
        gold_type=gold_type,
        sort_by=sort_by,
        per_page=per_page,
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
                    printed=False,  # Set printed to False for new products
                    created_at=datetime.utcnow()  # Set the creation timestamp
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

# Route for voiding sales
@app.route('/void_sale/<int:sale_id>', methods=['POST'])
@login_required
def void_sale(sale_id):
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    sold_product = SoldProduct.query.get_or_404(sale_id)
    
    try:
        # Check if the product exists in the inventory
        inventory_product = Inventory.query.filter_by(
            product_name=sold_product.product_name,
            size=sold_product.size,
            karat=sold_product.karat,
            gold_type=sold_product.gold_type,
            barcode=sold_product.barcode
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

        # Remove the sold product record from the SoldProduct table
        db.session.delete(sold_product)
        
        # Commit the changes to the database
        db.session.commit()

        flash(f"Sale for product '{sold_product.product_name}' has been voided and the product has been returned to inventory.", "success")
    
    except Exception as e:
        # Rollback in case of any error
        db.session.rollback()
        flash(f"Failed to void sale and return product to inventory. Error: {e}", "error")
    
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

@app.route('/sold_product', methods=['GET'])
@login_required
def sold_product():
    # Fetch available sold dates for the filter (distinct dates)
    available_dates = db.session.query(
        func.DATE(SoldProduct.date_sold).label('date')
    ).distinct().order_by('date').all()

    # Extract date filter and barcode search from request
    selected_date = request.args.get('date_sold', None)
    barcode_search = request.args.get('barcode', None)

    # Initialize the sales query
    sales_query = SoldProduct.query

    # If a date is selected, filter sales by that date
    if selected_date and selected_date != "None":
        sales_query = sales_query.filter(func.date(SoldProduct.date_sold) == func.date(selected_date))

    # If a barcode search is provided, filter by barcode
    if barcode_search:
        # Use ilike for case-insensitive search, adding wildcards for partial matches
        sales_query = sales_query.filter(SoldProduct.barcode.ilike(f"%{barcode_search}%"))

    # Execute the query
    sales = sales_query.all()

    # Calculate statistics
    total_sales = sum(sale.total_price for sale in sales)
    total_items_sold = sum(sale.quantity_sold for sale in sales)
    average_price_per_gram = total_sales / total_items_sold if total_items_sold else 0

    # Retrieve gold prices from session or use default values if not set
    gold_prices = session.get('gold_prices', {
        'chinese_18k': 0,
        'chinese_21k': 0,
        'saudi_18k': 0,
        'saudi_21k': 0
    })

    return render_template(
        'sold_product.html',
        sales=sales,
        prices=gold_prices,
        available_dates=[date[0].strftime('%Y-%m-%d') for date in available_dates],
        selected_date=selected_date,
        total_sales=total_sales,
        total_items_sold=total_items_sold,
        average_price_per_gram=average_price_per_gram
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

@app.route('/admin_power', methods=['GET'])
@login_required
def admin_power():
    today_date = datetime.today()
    current_year = today_date.year

    # Get selected date from query parameters for logins (default to today)
    selected_date = request.args.get('date', default=today_date.strftime('%Y-%m-%d'), type=str)
    selected_sold_date = request.args.get('sold_date', default=None, type=str)
    selected_added_date = request.args.get('added_date', default=None, type=str)

    selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d') if selected_date != "all" else None

    # Count logins for the selected date or all dates
    if selected_date_obj:
        login_count_today = UserLogin.query.filter(func.date(UserLogin.login_time) == selected_date_obj.date()).count()
    else:
        login_count_today = UserLogin.query.count()

    # Count products added on the selected date or all dates
    if selected_date_obj:
        added_products_today = Inventory.query.filter(func.date(Inventory.created_at) == selected_date_obj.date()).count()
        added_products = Inventory.query.filter(func.date(Inventory.created_at) == selected_date_obj.date()).all()
    else:
        added_products_today = Inventory.query.count()
        added_products = Inventory.query.all()

    # Fetch sold products for the selected sold date or all dates
    if selected_sold_date:
        sold_date_obj = datetime.strptime(selected_sold_date, '%Y-%m-%d')
        sold_products = SoldProduct.query.filter(func.date(SoldProduct.date_sold) == sold_date_obj.date()).all()
    else:
        sold_products = SoldProduct.query.all()

    total_sold_value = sum(sale.total_price for sale in sold_products)  # Example calculation
    total_items_sold = sum(sale.quantity_sold for sale in sold_products)  # Example calculation

    # Prepare dates for the dropdown for user logins
    dates = []  # Add the "All Dates" option
    for year in range(current_year - 10, current_year + 1):
        for month in range(1, 13):
            for day in range(1, 32):
                try:
                    datetime(year, month, day)
                    dates.append((f"{year}-{month:02d}-{day:02d}", f"{year}-{month:02d}-{day:02d}"))
                except ValueError:
                    continue

    # Fetch dates for sold products for dropdown
    sold_product_dates = db.session.query(func.date(SoldProduct.date_sold)).distinct().order_by(func.date(SoldProduct.date_sold).desc()).all()
    sold_dates = [date[0].strftime('%Y-%m-%d') for date in sold_product_dates]  # Extracting dates as strings

    # Fetch dates for added products for dropdown
    added_product_dates = db.session.query(func.date(Inventory.created_at)).distinct().order_by(func.date(Inventory.created_at).desc()).all()
    added_dates = [date[0].strftime('%Y-%m-%d') for date in added_product_dates]  # Extracting dates as strings

    # Fetch user logins for the selected date
    user_logins = UserLogin.query.filter(func.date(UserLogin.login_time) == selected_date_obj.date()).all() if selected_date_obj else UserLogin.query.all()

    return render_template('admin_power.html', 
                           login_count_today=login_count_today,
                           added_products_today=added_products_today,
                           total_sold_value=total_sold_value,
                           total_items_sold=total_items_sold,
                           sold_products=sold_products,
                           inventory_items=added_products,  # Show inventory items based on the added products filter
                           total_inventory_value=sum(item.price_per_unit * item.quantity for item in added_products),  # Example calculation
                           selected_date=selected_date,
                           selected_sold_date=selected_sold_date,
                           selected_added_date=selected_added_date,
                           dates=dates,
                           sold_dates=sold_dates,  # Pass sold dates to the template
                           added_dates=added_dates,  # Pass added dates to the template
                           user_logins=user_logins)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create the tables based on the models
    app.run(debug=True)

