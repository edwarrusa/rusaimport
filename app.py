import csv
import io
import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, session, g
from sqlalchemy import func, text
from models import (
    db,
    User,
    Location,
    Product,
    LocationStock,
    Contact,
    Wallet,
    FinancialTransaction,
    PurchaseOrder,
    PurchaseItem,
    StockMovement,
    Sale,
    SaleItem,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "rusaimport-secret-key-2026")

database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if not database_url:
    default_sqlite_path = os.path.join(BASE_DIR, "rusaimport.db")
    if os.path.isdir("/var/data") and os.access("/var/data", os.W_OK):
        default_sqlite_path = "/var/data/rusaimport.db"
    elif os.path.isdir("/data") and os.access("/data", os.W_OK):
        default_sqlite_path = "/data/rusaimport.db"

    sqlite_path = os.environ.get("SQLITE_DB_PATH", default_sqlite_path).strip()
    sqlite_dir = os.path.dirname(os.path.abspath(sqlite_path))
    if sqlite_dir and not os.path.exists(sqlite_dir):
        os.makedirs(sqlite_dir, exist_ok=True)
    database_url = "sqlite:///" + os.path.abspath(sqlite_path)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


def ensure_schema_migrations():
    """Safely add new columns to existing SQLite tables without losing data."""
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(products)")).fetchall()]
        if "min_stock" not in cols:
            db.session.execute(text("ALTER TABLE products ADD COLUMN min_stock INTEGER NOT NULL DEFAULT 5"))
            db.session.commit()


def ensure_default_admin():
    """Ensure at least one initial admin account exists with a securely hashed password."""
    default_username = os.environ.get("ADMIN_USERNAME", "admin").strip()
    default_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    if User.query.count() == 0:
        admin = User(username=default_username, role="Admin", is_admin=True)
        admin.set_password(default_password)
        db.session.add(admin)
        db.session.commit()


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if g.get("current_user") is None:
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped_view


@app.before_request
def load_logged_in_user_and_protect_routes():
    user_id = session.get("user_id")
    g.current_user = db.session.get(User, int(user_id)) if user_id is not None else None

    # Allow access to login and static assets without authentication
    public_endpoints = {"login", "static"}
    if request.endpoint and request.endpoint not in public_endpoints:
        if g.current_user is None:
            next_url = request.full_path.rstrip("?") if request.query_string else request.path
            return redirect(url_for("login", next=next_url))


@app.context_processor
def inject_current_user():
    return {"current_user": g.get("current_user")}


# -------------------------------------------------------------------------
# 0. AUTHENTICATION & USER MANAGEMENT (/login, /logout, /users)
# -------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if g.get("current_user") is not None:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or request.args.get("next") or url_for("dashboard")

        user = User.query.filter(func.lower(User.username) == username.lower()).first()
        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            session["is_admin"] = user.is_admin
            flash(f"Welcome back, {user.username}!", "success")
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("dashboard")
            return redirect(next_url)

        flash("Invalid username or password. Please try again.", "error")

    return render_template("login.html", next_url=request.args.get("next", ""))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been signed out of RusaImport.", "success")
    return redirect(url_for("login"))


@app.route("/users", methods=["GET", "POST"])
@login_required
def users_manage():
    if request.method == "POST":
        action = request.form.get("action", "create")
        if action == "create":
            if not g.current_user.is_admin:
                flash("Only administrators can create new user accounts.", "error")
                return redirect(url_for("users_manage"))

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "Manager").strip()
            is_admin = role == "Admin"

            if not username or len(password) < 4:
                flash("Username and a password of at least 4 characters are required.", "error")
                return redirect(url_for("users_manage"))

            if User.query.filter(func.lower(User.username) == username.lower()).first():
                flash(f"User '{username}' already exists.", "error")
                return redirect(url_for("users_manage"))

            new_user = User(username=username, role=role, is_admin=is_admin)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f"User '{username}' ({role}) created with a hashed password.", "success")
            return redirect(url_for("users_manage"))

        elif action == "change_password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            if not g.current_user.check_password(current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("users_manage"))
            if len(new_password) < 4:
                flash("New password must be at least 4 characters long.", "error")
                return redirect(url_for("users_manage"))
            g.current_user.set_password(new_password)
            db.session.commit()
            flash("Your password has been updated.", "success")
            return redirect(url_for("users_manage"))

    all_users = User.query.order_by(User.id).all()
    return render_template("users.html", users=all_users)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if not g.current_user.is_admin:
        flash("Only administrators can delete users.", "error")
        return redirect(url_for("users_manage"))

    target = db.session.get(User, user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("users_manage"))

    if target.id == g.current_user.id:
        flash("You cannot delete your own active account.", "error")
        return redirect(url_for("users_manage"))

    uname = target.username
    db.session.delete(target)
    db.session.commit()
    flash(f"User '{uname}' removed.", "success")
    return redirect(url_for("users_manage"))


def get_or_create_stock(location_id: int, product_id: int) -> LocationStock:
    stock = LocationStock.query.filter_by(location_id=location_id, product_id=product_id).first()
    if not stock:
        stock = LocationStock(location_id=location_id, product_id=product_id, quantity=0)
        db.session.add(stock)
        db.session.flush()
    return stock


# -------------------------------------------------------------------------
# 1. DASHBOARD
# -------------------------------------------------------------------------
@app.route("/")
def dashboard():
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    products = Product.query.all()
    total_inventory_valuation = sum(p.total_valuation for p in products)
    total_units = sum(p.total_quantity for p in products)

    active_locations_count = Location.query.filter_by(is_active=True).count()
    locations = Location.query.order_by(Location.name).all()

    monthly_sales_total = (
        db.session.query(func.coalesce(func.sum(Sale.total_amount), 0.0))
        .filter(Sale.created_at >= month_start)
        .scalar()
    )
    monthly_orders_count = Sale.query.filter(Sale.created_at >= month_start).count()

    wallets = Wallet.query.order_by(Wallet.name).all()
    total_wallet_balance = sum(w.balance for w in wallets)

    recent_sales = Sale.query.order_by(Sale.created_at.desc()).limit(5).all()
    recent_movements = StockMovement.query.order_by(StockMovement.created_at.desc()).limit(6).all()

    location_summaries = []
    for loc in locations:
        loc_units = sum(s.quantity for s in loc.stocks)
        loc_val = sum(s.quantity * s.product.cost for s in loc.stocks if s.product)
        location_summaries.append(
            {
                "location": loc,
                "units": loc_units,
                "valuation": loc_val,
            }
        )

    return render_template(
        "dashboard.html",
        total_inventory_valuation=total_inventory_valuation,
        total_units=total_units,
        active_locations_count=active_locations_count,
        monthly_sales_total=monthly_sales_total,
        monthly_orders_count=monthly_orders_count,
        wallets=wallets,
        total_wallet_balance=total_wallet_balance,
        recent_sales=recent_sales,
        recent_movements=recent_movements,
        location_summaries=location_summaries,
        current_month_label=now.strftime("%B %Y"),
    )


# -------------------------------------------------------------------------
# 2. INVENTORY LOCATIONS MANAGEMENT & MULTI-LOCATION INVENTORY CRUD
# -------------------------------------------------------------------------
@app.route("/locations", methods=["GET", "POST"])
def locations_manage():
    """Dedicated CRUD page for managing Warehouse and Store Locations."""
    if request.method == "POST":
        return _handle_create_location(redirect_endpoint="locations_manage")

    locations = Location.query.order_by(Location.id).all()
    location_stats = []
    for loc in locations:
        total_skus = sum(1 for s in loc.stocks if s.quantity > 0)
        total_units = sum(s.quantity for s in loc.stocks)
        valuation = sum(s.quantity * s.product.cost for s in loc.stocks if s.product)
        sales_count = Sale.query.filter_by(location_id=loc.id).count()
        location_stats.append(
            {
                "location": loc,
                "total_skus": total_skus,
                "total_units": total_units,
                "valuation": valuation,
                "sales_count": sales_count,
            }
        )

    return render_template("locations.html", location_stats=location_stats)


def _handle_create_location(redirect_endpoint="inventory"):
    name = request.form.get("name", "").strip()
    location_type = request.form.get("location_type", "Warehouse").strip()
    address = request.form.get("address", "").strip()
    next_page = request.form.get("next") or redirect_endpoint

    if not name:
        flash("Location name is required.", "error")
        return redirect(url_for(next_page))

    if Location.query.filter(func.lower(Location.name) == name.lower()).first():
        flash(f"Location '{name}' already exists.", "error")
        return redirect(url_for(next_page))

    loc = Location(name=name, location_type=location_type, address=address, is_active=True)
    db.session.add(loc)
    db.session.commit()
    flash(f"Location '{name}' ({location_type}) created and saved to SQLite.", "success")
    return redirect(url_for(next_page))


@app.route("/inventory")
def inventory():
    locations = Location.query.order_by(Location.id).all()
    active_locations = Location.query.filter_by(is_active=True).order_by(Location.id).all()
    products = Product.query.order_by(Product.sku).all()

    location_filter = request.args.get("location_id", "all").strip()
    selected_location = None
    if location_filter != "all":
        try:
            selected_location = db.session.get(Location, int(location_filter))
        except ValueError:
            selected_location = None
        if not selected_location:
            location_filter = "all"

    stock_map = {}
    for s in LocationStock.query.all():
        stock_map[(s.product_id, s.location_id)] = s.quantity

    # Build filtered stock rows for the Current Stock table
    stock_rows = []
    if selected_location is not None:
        # Query only products and quantities belonging to the chosen location
        loc_stocks = (
            LocationStock.query.filter_by(location_id=selected_location.id)
            .join(Product)
            .order_by(Product.sku)
            .all()
        )
        for ls in loc_stocks:
            p = ls.product
            qty = ls.quantity
            min_req = p.min_stock if p.min_stock is not None else 5
            if qty <= 0:
                status = "Out of Stock"
            elif qty < min_req:
                status = "Low Stock"
            else:
                status = "Optimal"
            stock_rows.append(
                {
                    "product": p,
                    "quantity": qty,
                    "min_stock": min_req,
                    "status": status,
                    "valuation": qty * p.cost,
                    "location_name": selected_location.name,
                }
            )
    else:
        # All Locations view: show all catalog products with their total stock across active locations
        for p in products:
            qty = p.total_quantity
            min_req = p.min_stock if p.min_stock is not None else 5
            if qty <= 0:
                status = "Out of Stock"
            elif qty < min_req:
                status = "Low Stock"
            else:
                status = "Optimal"
            loc_breakdown = []
            for loc in active_locations:
                l_qty = stock_map.get((p.id, loc.id), 0)
                if l_qty > 0 or (p.id, loc.id) in stock_map:
                    loc_breakdown.append({"loc_id": loc.id, "loc_name": loc.name, "qty": l_qty})
            stock_rows.append(
                {
                    "product": p,
                    "quantity": qty,
                    "min_stock": min_req,
                    "status": status,
                    "valuation": qty * p.cost,
                    "loc_breakdown": loc_breakdown,
                }
            )

    total_view_units = sum(r["quantity"] for r in stock_rows)
    total_view_valuation = sum(r["valuation"] for r in stock_rows)
    low_stock_count = sum(1 for r in stock_rows if r["status"] in ("Low Stock", "Out of Stock"))

    return render_template(
        "inventory.html",
        locations=locations,
        active_locations=active_locations,
        products=products,
        stock_map=stock_map,
        stock_rows=stock_rows,
        location_filter=location_filter,
        selected_location=selected_location,
        total_view_units=total_view_units,
        total_view_valuation=total_view_valuation,
        low_stock_count=low_stock_count,
    )


@app.route("/inventory/location/add", methods=["POST"])
def add_location():
    return _handle_create_location(redirect_endpoint="inventory")


@app.route("/inventory/location/<int:loc_id>/edit", methods=["POST"])
def edit_location(loc_id):
    loc = db.session.get(Location, loc_id)
    if not loc:
        flash("Location not found.", "error")
        return redirect(url_for("locations_manage"))

    name = request.form.get("name", "").strip()
    location_type = request.form.get("location_type", loc.location_type).strip()
    address = request.form.get("address", "").strip()
    next_page = request.form.get("next") or "locations_manage"

    if not name:
        flash("Location name cannot be empty.", "error")
        return redirect(url_for(next_page))

    duplicate = Location.query.filter(func.lower(Location.name) == name.lower(), Location.id != loc.id).first()
    if duplicate:
        flash(f"Another location with name '{name}' already exists.", "error")
        return redirect(url_for(next_page))

    loc.name = name
    loc.location_type = location_type
    loc.address = address
    db.session.commit()
    flash(f"Location '{loc.name}' updated.", "success")
    return redirect(url_for(next_page))


@app.route("/inventory/location/<int:loc_id>/toggle", methods=["POST"])
def toggle_location(loc_id):
    loc = db.session.get(Location, loc_id)
    if not loc:
        flash("Location not found.", "error")
        return redirect(url_for("inventory"))

    loc.is_active = not loc.is_active
    db.session.commit()
    status = "activated" if loc.is_active else "deactivated"
    next_page = request.form.get("next") or "inventory"
    flash(f"Location '{loc.name}' {status}.", "success")
    return redirect(url_for(next_page))


@app.route("/inventory/location/<int:loc_id>/delete", methods=["POST"])
def delete_location(loc_id):
    loc = db.session.get(Location, loc_id)
    next_page = request.form.get("next") or "locations_manage"
    if not loc:
        flash("Location not found.", "error")
        return redirect(url_for(next_page))

    total_units = sum(s.quantity for s in loc.stocks)
    sales_count = Sale.query.filter_by(location_id=loc.id).count()
    po_count = PurchaseOrder.query.filter_by(location_id=loc.id).count()
    if total_units > 0 or sales_count > 0 or po_count > 0:
        flash(
            f"Cannot delete '{loc.name}' because it holds {total_units} stock units or has historical sales/purchases. Deactivate it or transfer stock out first.",
            "error",
        )
        return redirect(url_for(next_page))

    StockMovement.query.filter(
        (StockMovement.from_location_id == loc.id) | (StockMovement.to_location_id == loc.id)
    ).delete(synchronize_session=False)

    loc_name = loc.name
    db.session.delete(loc)
    db.session.commit()
    flash(f"Location '{loc_name}' deleted.", "success")
    return redirect(url_for(next_page))


@app.route("/inventory/product/add", methods=["POST"])
def add_product():
    sku = request.form.get("sku", "").strip().upper()
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "General").strip() or "General"
    try:
        cost = float(request.form.get("cost", 0))
        price = float(request.form.get("price", 0))
        initial_qty = int(request.form.get("initial_qty", 0) or 0)
        min_stock = int(request.form.get("min_stock", 5) or 5)
    except ValueError:
        flash("Invalid numeric values for cost, price, min stock, or quantity.", "error")
        return redirect(url_for("inventory"))

    initial_location_id = request.form.get("initial_location_id")

    if not sku or not name:
        flash("SKU and Product Name are required.", "error")
        return redirect(url_for("inventory"))

    if cost < 0 or price < 0 or initial_qty < 0 or min_stock < 0:
        flash("Cost, price, min stock, and quantity must be non-negative.", "error")
        return redirect(url_for("inventory"))

    if Product.query.filter(func.lower(Product.sku) == sku.lower()).first():
        flash(f"Product with SKU '{sku}' already exists.", "error")
        return redirect(url_for("inventory"))

    product = Product(sku=sku, name=name, category=category, cost=cost, price=price, min_stock=min_stock)
    db.session.add(product)
    db.session.flush()

    if initial_location_id:
        loc_id = int(initial_location_id)
        stock = get_or_create_stock(loc_id, product.id)
        if initial_qty > 0:
            stock.quantity += initial_qty
            db.session.add(
                StockMovement(
                    movement_type="PURCHASE",
                    product_id=product.id,
                    to_location_id=loc_id,
                    quantity=initial_qty,
                    unit_cost=cost,
                    notes="Initial opening stock",
                )
            )

    db.session.commit()
    flash(f"Product '{sku} - {name}' added to catalog.", "success")
    if initial_location_id and request.form.get("active_location_filter") not in (None, "", "all"):
        return redirect(url_for("inventory", location_id=request.form.get("active_location_filter")))
    return redirect(url_for("inventory"))


@app.route("/inventory/product/<int:prod_id>/edit", methods=["POST"])
def edit_product(prod_id):
    product = db.session.get(Product, prod_id)
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("inventory"))

    sku = request.form.get("sku", "").strip().upper()
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "General").strip() or "General"
    try:
        cost = float(request.form.get("cost", product.cost))
        price = float(request.form.get("price", product.price))
        min_stock = int(request.form.get("min_stock", product.min_stock))
    except ValueError:
        flash("Invalid cost, price, or min stock.", "error")
        return redirect(url_for("inventory"))

    if not sku or not name or cost < 0 or price < 0 or min_stock < 0:
        flash("Valid SKU, name, cost, price, and min stock are required.", "error")
        return redirect(url_for("inventory"))

    dup = Product.query.filter(func.lower(Product.sku) == sku.lower(), Product.id != product.id).first()
    if dup:
        flash(f"SKU '{sku}' is already in use by another product.", "error")
        return redirect(url_for("inventory"))

    product.sku = sku
    product.name = name
    product.category = category
    product.cost = cost
    product.price = price
    product.min_stock = min_stock
    db.session.commit()
    flash(f"Product '{product.sku}' updated.", "success")
    loc_filter = request.form.get("location_filter", "all")
    return redirect(url_for("inventory", location_id=loc_filter))


@app.route("/inventory/product/<int:prod_id>/delete", methods=["POST"])
def delete_product(prod_id):
    product = db.session.get(Product, prod_id)
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("inventory"))

    if SaleItem.query.filter_by(product_id=product.id).count() > 0 or PurchaseItem.query.filter_by(product_id=product.id).count() > 0:
        flash(f"Cannot delete '{product.sku}' because it appears on historical sales or purchase orders.", "error")
        return redirect(url_for("inventory"))

    StockMovement.query.filter_by(product_id=product.id).delete(synchronize_session=False)
    sku_name = f"{product.sku} - {product.name}"
    db.session.delete(product)
    db.session.commit()
    flash(f"Product '{sku_name}' removed from catalog.", "success")
    return redirect(url_for("inventory"))


# -------------------------------------------------------------------------
# 3. MERCHANDISE PURCHASES MODULE (COMPRAS DE MERCANCÍA)
# -------------------------------------------------------------------------
@app.route("/purchases", methods=["GET", "POST"])
def purchases():
    """Dedicated Merchandise Purchases module with Supplier, Multi-Product rows, Target Location, Ship Fee, and Wallet Outflow."""
    if request.method == "POST":
        supplier_id = request.form.get("supplier_id")
        default_location_id = request.form.get("location_id")
        wallet_id = request.form.get("wallet_id")
        notes = request.form.get("notes", "").strip()

        try:
            ship_fee = float(request.form.get("ship_fee", 0) or 0.0)
        except ValueError:
            flash("Invalid Ship Fee (costo de envío) value.", "error")
            return redirect(url_for("purchases"))

        if ship_fee < 0:
            flash("Ship Fee cannot be negative.", "error")
            return redirect(url_for("purchases"))

        if not supplier_id or not default_location_id or not wallet_id:
            flash("Supplier, Target Inventory Location, and Paying Financial Wallet are required.", "error")
            return redirect(url_for("purchases"))

        supplier = db.session.get(Contact, int(supplier_id))
        default_loc = db.session.get(Location, int(default_location_id))
        wallet = db.session.get(Wallet, int(wallet_id))

        if not supplier or not default_loc or not wallet:
            flash("Selected supplier, location, or wallet does not exist.", "error")
            return redirect(url_for("purchases"))

        product_ids = request.form.getlist("product_id[]")
        quantities = request.form.getlist("quantity[]")
        unit_costs = request.form.getlist("unit_cost[]")
        item_locations = request.form.getlist("item_location_id[]")

        parsed_items = []
        for idx, (pid_raw, qty_raw, cost_raw) in enumerate(zip(product_ids, quantities, unit_costs)):
            if not pid_raw or not qty_raw:
                continue
            try:
                pid = int(pid_raw)
                qty = int(qty_raw)
                ucost = float(cost_raw) if cost_raw not in (None, "") else None
            except ValueError:
                continue

            loc_override_id = default_loc.id
            if idx < len(item_locations) and item_locations[idx]:
                try:
                    loc_override_id = int(item_locations[idx])
                except ValueError:
                    loc_override_id = default_loc.id

            if qty > 0:
                parsed_items.append((pid, qty, ucost, loc_override_id))

        if not parsed_items:
            flash("Please add at least one product with a positive quantity to the purchase order.", "error")
            return redirect(url_for("purchases"))

        validated_rows = []
        products_subtotal = 0.0
        for pid, qty, ucost, target_loc_id in parsed_items:
            product = db.session.get(Product, pid)
            target_loc = db.session.get(Location, target_loc_id) or default_loc
            if not product:
                flash("Invalid product selected in purchase order.", "error")
                return redirect(url_for("purchases"))
            effective_cost = ucost if (ucost is not None and ucost >= 0) else product.cost
            validated_rows.append((product, target_loc, qty, effective_cost))
            products_subtotal += qty * effective_cost

        total_purchase_outflow = products_subtotal + ship_fee

        if wallet.balance < total_purchase_outflow:
            flash(
                f"Insufficient balance in wallet '{wallet.name}' (${wallet.balance:,.2f}) to cover total purchase of ${total_purchase_outflow:,.2f} (Products: ${products_subtotal:,.2f} + Ship Fee: ${ship_fee:,.2f}).",
                "error",
            )
            return redirect(url_for("purchases"))

        # Generate PO Number
        po_count = PurchaseOrder.query.count() + 1
        po_number = f"PO-{datetime.utcnow().strftime('%Y%m')}-{po_count:04d}"
        while PurchaseOrder.query.filter_by(po_number=po_number).first():
            po_count += 1
            po_number = f"PO-{datetime.utcnow().strftime('%Y%m')}-{po_count:04d}"

        po = PurchaseOrder(
            po_number=po_number,
            supplier_id=supplier.id,
            location_id=default_loc.id,
            wallet_id=wallet.id,
            products_subtotal=products_subtotal,
            ship_fee=ship_fee,
            total_amount=total_purchase_outflow,
            notes=notes,
        )
        db.session.add(po)
        db.session.flush()

        # Update inventory per location, update product unit cost, and record stock movements
        sku_summary_parts = []
        for product, target_loc, qty, effective_cost in validated_rows:
            stock = get_or_create_stock(target_loc.id, product.id)
            stock.quantity += qty
            product.cost = effective_cost
            sku_summary_parts.append(f"{qty}x {product.sku}")

            db.session.add(
                PurchaseItem(
                    purchase_order_id=po.id,
                    product_id=product.id,
                    location_id=target_loc.id,
                    quantity=qty,
                    unit_cost=effective_cost,
                )
            )
            db.session.add(
                StockMovement(
                    movement_type="PURCHASE",
                    product_id=product.id,
                    to_location_id=target_loc.id,
                    quantity=qty,
                    unit_cost=effective_cost,
                    supplier_id=supplier.id,
                    wallet_id=wallet.id,
                    notes=f"{po_number} ({supplier.name})" + (f" — {notes}" if notes else ""),
                )
            )

        # Deduct total amount (products_subtotal + ship_fee) from selected Wallet
        wallet.balance -= total_purchase_outflow
        items_summary = ", ".join(sku_summary_parts[:4])

        # Record Merchandise Purchase Outflow in Wallet Ledger
        if products_subtotal > 0:
            db.session.add(
                FinancialTransaction(
                    wallet_id=wallet.id,
                    tx_type="OUTFLOW",
                    category="Purchase",
                    amount=products_subtotal,
                    description=f"Merchandise Purchase {po_number} ({supplier.name}): {items_summary}",
                    reference_id=po_number,
                )
            )

        # Record Ship Fee Outflow in Wallet Ledger if ship_fee > 0
        if ship_fee > 0:
            db.session.add(
                FinancialTransaction(
                    wallet_id=wallet.id,
                    tx_type="OUTFLOW",
                    category="Ship Fee",
                    amount=ship_fee,
                    description=f"Supplier Ship Fee / Freight for {po_number} ({supplier.name})",
                    reference_id=po_number,
                )
            )

        db.session.commit()
        flash(
            f"Purchase Order {po_number} registered! Added stock to '{default_loc.name}' and deducted ${total_purchase_outflow:,.2f} (Products: ${products_subtotal:,.2f} + Ship Fee: ${ship_fee:,.2f}) from '{wallet.name}'.",
            "success",
        )
        return redirect(url_for("purchases"))

    suppliers = Contact.query.filter_by(contact_type="Supplier").order_by(Contact.name).all()
    locations = Location.query.filter_by(is_active=True).order_by(Location.name).all()
    wallets = Wallet.query.order_by(Wallet.name).all()
    products = Product.query.order_by(Product.name).all()
    purchase_orders = PurchaseOrder.query.order_by(PurchaseOrder.created_at.desc()).limit(25).all()

    products_data = [
        {
            "id": p.id,
            "sku": p.sku,
            "name": p.name,
            "cost": p.cost,
            "price": p.price,
        }
        for p in products
    ]
    locations_data = [{"id": loc.id, "name": loc.name} for loc in locations]

    return render_template(
        "purchases.html",
        suppliers=suppliers,
        locations=locations,
        locations_data=locations_data,
        wallets=wallets,
        products=products,
        products_data=products_data,
        purchase_orders=purchase_orders,
    )


# -------------------------------------------------------------------------
# 4. STOCK ADJUSTMENTS & MOVEMENTS (TRANSFERS, LOSSES & QUICK PURCHASE)
# -------------------------------------------------------------------------
@app.route("/movements", methods=["GET", "POST"])
def movements():
    if request.method == "POST":
        movement_type = request.form.get("movement_type", "").strip()
        try:
            product_id = int(request.form.get("product_id", 0))
            quantity = int(request.form.get("quantity", 0))
        except ValueError:
            flash("Please select a valid product and positive integer quantity.", "error")
            return redirect(url_for("movements"))

        notes = request.form.get("notes", "").strip()
        product = db.session.get(Product, product_id)

        if not product or quantity <= 0:
            flash("Product and a quantity greater than 0 are required.", "error")
            return redirect(url_for("movements"))

        if movement_type == "PURCHASE":
            to_location_id = request.form.get("to_location_id")
            supplier_id = request.form.get("supplier_id")
            wallet_id = request.form.get("wallet_id")
            try:
                unit_cost = float(request.form.get("unit_cost") or product.cost)
                ship_fee = float(request.form.get("ship_fee") or 0.0)
            except ValueError:
                unit_cost = product.cost
                ship_fee = 0.0

            if not to_location_id or not supplier_id or not wallet_id:
                flash("Supplier, Destination Location, and Paying Wallet are required for purchases.", "error")
                return redirect(url_for("movements"))

            to_loc_id = int(to_location_id)
            supplier = db.session.get(Contact, int(supplier_id))
            wallet_obj = db.session.get(Wallet, int(wallet_id))
            if not supplier or not wallet_obj:
                flash("Valid supplier and wallet are required.", "error")
                return redirect(url_for("movements"))

            products_subtotal = quantity * unit_cost
            total_purchase_cost = products_subtotal + ship_fee

            if wallet_obj.balance < total_purchase_cost:
                flash(
                    f"Insufficient funds in '{wallet_obj.name}' (${wallet_obj.balance:,.2f}) for total purchase of ${total_purchase_cost:,.2f} (Products: ${products_subtotal:,.2f} + Ship Fee: ${ship_fee:,.2f}).",
                    "error",
                )
                return redirect(url_for("movements"))

            stock = get_or_create_stock(to_loc_id, product.id)
            stock.quantity += quantity
            product.cost = unit_cost

            po_count = PurchaseOrder.query.count() + 1
            po_number = f"PO-{datetime.utcnow().strftime('%Y%m')}-{po_count:04d}"
            while PurchaseOrder.query.filter_by(po_number=po_number).first():
                po_count += 1
                po_number = f"PO-{datetime.utcnow().strftime('%Y%m')}-{po_count:04d}"

            po = PurchaseOrder(
                po_number=po_number,
                supplier_id=supplier.id,
                location_id=to_loc_id,
                wallet_id=wallet_obj.id,
                products_subtotal=products_subtotal,
                ship_fee=ship_fee,
                total_amount=total_purchase_cost,
                notes=notes or "Quick purchase entry",
            )
            db.session.add(po)
            db.session.flush()

            db.session.add(
                PurchaseItem(
                    purchase_order_id=po.id,
                    product_id=product.id,
                    location_id=to_loc_id,
                    quantity=quantity,
                    unit_cost=unit_cost,
                )
            )

            wallet_obj.balance -= total_purchase_cost
            db.session.add(
                FinancialTransaction(
                    wallet_id=wallet_obj.id,
                    tx_type="OUTFLOW",
                    category="Purchase",
                    amount=products_subtotal,
                    description=f"Merchandise Purchase {po_number} ({supplier.name}): {quantity}x {product.sku}",
                    reference_id=po_number,
                )
            )
            if ship_fee > 0:
                db.session.add(
                    FinancialTransaction(
                        wallet_id=wallet_obj.id,
                        tx_type="OUTFLOW",
                        category="Ship Fee",
                        amount=ship_fee,
                        description=f"Supplier Ship Fee / Freight for {po_number} ({supplier.name})",
                        reference_id=po_number,
                    )
                )

            db.session.add(
                StockMovement(
                    movement_type="PURCHASE",
                    product_id=product.id,
                    to_location_id=to_loc_id,
                    quantity=quantity,
                    unit_cost=unit_cost,
                    supplier_id=supplier.id,
                    wallet_id=wallet_obj.id,
                    notes=f"{po_number}: " + (notes or "Inventory replenishment purchase"),
                )
            )
            db.session.commit()
            flash(
                f"Registered purchase {po_number} ({quantity}x {product.name}) and deducted ${total_purchase_cost:,.2f} from '{wallet_obj.name}'.",
                "success",
            )
            return redirect(url_for("movements"))

        elif movement_type == "TRANSFER":
            from_location_id = request.form.get("from_location_id")
            to_location_id = request.form.get("to_location_id")
            if not from_location_id or not to_location_id:
                flash("Both origin and destination locations are required for transfers.", "error")
                return redirect(url_for("movements"))

            from_loc_id = int(from_location_id)
            to_loc_id = int(to_location_id)
            if from_loc_id == to_loc_id:
                flash("Origin and destination locations must be different.", "error")
                return redirect(url_for("movements"))

            source_stock = get_or_create_stock(from_loc_id, product.id)
            if source_stock.quantity < quantity:
                flash(
                    f"Insufficient stock at origin ({source_stock.quantity} available, tried to transfer {quantity}).",
                    "error",
                )
                return redirect(url_for("movements"))

            dest_stock = get_or_create_stock(to_loc_id, product.id)
            source_stock.quantity -= quantity
            dest_stock.quantity += quantity

            db.session.add(
                StockMovement(
                    movement_type="TRANSFER",
                    product_id=product.id,
                    from_location_id=from_loc_id,
                    to_location_id=to_loc_id,
                    quantity=quantity,
                    unit_cost=product.cost,
                    notes=notes or "Inter-location stock transfer",
                )
            )
            db.session.commit()
            flash(f"Transferred {quantity}x {product.name} between locations.", "success")
            return redirect(url_for("movements"))

        elif movement_type in ("LOSS_EXPIRATION", "LOSS_DAMAGE", "LOSS_DONATION"):
            from_location_id = request.form.get("from_location_id")
            if not from_location_id:
                flash("Source location is required to deduct an inventory loss/adjustment.", "error")
                return redirect(url_for("movements"))

            from_loc_id = int(from_location_id)
            source_stock = get_or_create_stock(from_loc_id, product.id)
            if source_stock.quantity < quantity:
                flash(
                    f"Cannot deduct {quantity} units; location only holds {source_stock.quantity} units.",
                    "error",
                )
                return redirect(url_for("movements"))

            source_stock.quantity -= quantity
            db.session.add(
                StockMovement(
                    movement_type=movement_type,
                    product_id=product.id,
                    from_location_id=from_loc_id,
                    quantity=quantity,
                    unit_cost=product.cost,
                    notes=notes or f"Inventory adjustment ({movement_type.replace('LOSS_', '').title()})",
                )
            )
            db.session.commit()
            flash(
                f"Recorded stock deduction ({movement_type.replace('LOSS_', '').title()}): -{quantity}x {product.name}.",
                "success",
            )
            return redirect(url_for("movements"))
        else:
            flash("Invalid movement type selected.", "error")
            return redirect(url_for("movements"))

    products = Product.query.order_by(Product.name).all()
    locations = Location.query.filter_by(is_active=True).order_by(Location.name).all()
    suppliers = Contact.query.filter_by(contact_type="Supplier").order_by(Contact.name).all()
    wallets = Wallet.query.order_by(Wallet.name).all()
    history = StockMovement.query.order_by(StockMovement.created_at.desc()).limit(50).all()

    return render_template(
        "movements.html",
        products=products,
        locations=locations,
        suppliers=suppliers,
        wallets=wallets,
        history=history,
    )


# -------------------------------------------------------------------------
# 5. SALES MODULE (POS)
# -------------------------------------------------------------------------
@app.route("/pos", methods=["GET", "POST"])
def pos():
    if request.method == "POST":
        location_id = request.form.get("location_id")
        wallet_id = request.form.get("wallet_id")
        customer_id = request.form.get("customer_id") or None
        notes = request.form.get("notes", "").strip()

        if not location_id or not wallet_id:
            flash("You must select both a Dispatch Location and a Receiving Payment Wallet.", "error")
            return redirect(url_for("pos"))

        loc = db.session.get(Location, int(location_id))
        wallet = db.session.get(Wallet, int(wallet_id))
        if not loc or not wallet:
            flash("Selected location or wallet was not found.", "error")
            return redirect(url_for("pos"))

        product_ids = request.form.getlist("product_id[]")
        quantities = request.form.getlist("quantity[]")
        unit_prices = request.form.getlist("unit_price[]")

        line_items = []
        for pid_raw, qty_raw, price_raw in zip(product_ids, quantities, unit_prices):
            if not pid_raw or not qty_raw:
                continue
            try:
                pid = int(pid_raw)
                qty = int(qty_raw)
                custom_price = float(price_raw) if price_raw else None
            except ValueError:
                continue
            if qty > 0:
                line_items.append((pid, qty, custom_price))

        if not line_items:
            flash("Please add at least one product with a positive quantity to complete the sale.", "error")
            return redirect(url_for("pos"))

        aggregated = {}
        for pid, qty, custom_price in line_items:
            if pid not in aggregated:
                aggregated[pid] = {"qty": 0, "price": custom_price}
            aggregated[pid]["qty"] += qty
            if custom_price is not None:
                aggregated[pid]["price"] = custom_price

        validated_items = []
        total_amount = 0.0
        total_cogs = 0.0

        for pid, data in aggregated.items():
            product = db.session.get(Product, pid)
            if not product:
                flash("Invalid product in order.", "error")
                return redirect(url_for("pos"))

            stock = get_or_create_stock(loc.id, product.id)
            if stock.quantity < data["qty"]:
                flash(
                    f"Insufficient stock for '{product.name}' at {loc.name}: available {stock.quantity}, requested {data['qty']}.",
                    "error",
                )
                return redirect(url_for("pos"))

            selling_price = data["price"] if (data["price"] is not None and data["price"] >= 0) else product.price
            validated_items.append((product, stock, data["qty"], selling_price))
            total_amount += data["qty"] * selling_price
            total_cogs += data["qty"] * product.cost

        sale_count = Sale.query.count() + 1
        invoice_number = f"INV-{datetime.utcnow().strftime('%Y%m')}-{sale_count:04d}"
        while Sale.query.filter_by(invoice_number=invoice_number).first():
            sale_count += 1
            invoice_number = f"INV-{datetime.utcnow().strftime('%Y%m')}-{sale_count:04d}"

        customer = db.session.get(Contact, int(customer_id)) if customer_id else None

        sale = Sale(
            invoice_number=invoice_number,
            customer_id=customer.id if customer else None,
            location_id=loc.id,
            wallet_id=wallet.id,
            total_amount=total_amount,
            total_cogs=total_cogs,
            notes=notes,
        )
        db.session.add(sale)
        db.session.flush()

        for product, stock, qty, selling_price in validated_items:
            stock.quantity -= qty
            db.session.add(
                SaleItem(
                    sale_id=sale.id,
                    product_id=product.id,
                    quantity=qty,
                    unit_price=selling_price,
                    unit_cost=product.cost,
                )
            )
            db.session.add(
                StockMovement(
                    movement_type="SALE",
                    product_id=product.id,
                    from_location_id=loc.id,
                    quantity=qty,
                    unit_cost=product.cost,
                    wallet_id=wallet.id,
                    notes=f"POS Sale {invoice_number}",
                )
            )

        wallet.balance += total_amount
        customer_label = customer.name if customer else "Walk-in Customer"
        db.session.add(
            FinancialTransaction(
                wallet_id=wallet.id,
                tx_type="INFLOW",
                category="Sale",
                amount=total_amount,
                description=f"POS Sale {invoice_number} ({customer_label}) from {loc.name}",
                reference_id=invoice_number,
            )
        )

        db.session.commit()
        flash(
            f"Sale {invoice_number} completed! Deducted from '{loc.name}' and credited ${total_amount:,.2f} to '{wallet.name}'.",
            "success",
        )
        return redirect(url_for("pos"))

    locations = Location.query.filter_by(is_active=True).order_by(Location.name).all()
    wallets = Wallet.query.order_by(Wallet.name).all()
    customers = Contact.query.filter_by(contact_type="Customer").order_by(Contact.name).all()
    products = Product.query.order_by(Product.name).all()
    recent_sales = Sale.query.order_by(Sale.created_at.desc()).limit(15).all()

    stock_by_loc = {}
    for s in LocationStock.query.all():
        stock_by_loc.setdefault(str(s.location_id), {})[str(s.product_id)] = s.quantity

    products_data = [
        {
            "id": p.id,
            "sku": p.sku,
            "name": p.name,
            "price": p.price,
            "cost": p.cost,
        }
        for p in products
    ]

    return render_template(
        "pos.html",
        locations=locations,
        wallets=wallets,
        customers=customers,
        products=products,
        products_data=products_data,
        stock_by_loc=stock_by_loc,
        recent_sales=recent_sales,
    )


# -------------------------------------------------------------------------
# 6. WALLETS & FINANCIALS CRUD + FULL MOVEMENTS LEDGER
# -------------------------------------------------------------------------
@app.route("/wallets")
def wallets():
    all_wallets = Wallet.query.order_by(Wallet.id).all()
    category_filter = request.args.get("category", "all")
    wallet_filter = request.args.get("wallet_id", "all")

    tx_query = FinancialTransaction.query
    if category_filter != "all":
        tx_query = tx_query.filter_by(category=category_filter)
    if wallet_filter != "all":
        try:
            tx_query = tx_query.filter_by(wallet_id=int(wallet_filter))
        except ValueError:
            pass

    transactions = tx_query.order_by(FinancialTransaction.created_at.desc()).limit(100).all()
    total_balance = sum(w.balance for w in all_wallets)

    # Category totals across all transactions
    all_txs = FinancialTransaction.query.all()
    sales_inflow_total = sum(t.amount for t in all_txs if t.tx_type == "INFLOW" and t.category == "Sale")
    purchases_outflow_total = sum(t.amount for t in all_txs if t.tx_type == "OUTFLOW" and t.category == "Purchase")
    ship_fees_outflow_total = sum(t.amount for t in all_txs if t.tx_type == "OUTFLOW" and t.category == "Ship Fee")
    opex_outflow_total = sum(t.amount for t in all_txs if t.tx_type == "OUTFLOW" and t.category == "Operating Expense")

    return render_template(
        "wallets.html",
        wallets=all_wallets,
        transactions=transactions,
        total_balance=total_balance,
        category_filter=category_filter,
        wallet_filter=wallet_filter,
        sales_inflow_total=sales_inflow_total,
        purchases_outflow_total=purchases_outflow_total,
        ship_fees_outflow_total=ship_fees_outflow_total,
        opex_outflow_total=opex_outflow_total,
    )


@app.route("/wallets/add", methods=["POST"])
def add_wallet():
    name = request.form.get("name", "").strip()
    wallet_type = request.form.get("wallet_type", "Bank").strip()
    currency = request.form.get("currency", "USD").strip().upper() or "USD"
    try:
        opening_balance = float(request.form.get("opening_balance", 0) or 0)
    except ValueError:
        flash("Invalid opening balance.", "error")
        return redirect(url_for("wallets"))

    if not name:
        flash("Wallet name is required.", "error")
        return redirect(url_for("wallets"))

    if opening_balance < 0:
        flash("Initial balance cannot be negative.", "error")
        return redirect(url_for("wallets"))

    if Wallet.query.filter(func.lower(Wallet.name) == name.lower()).first():
        flash(f"Wallet '{name}' already exists.", "error")
        return redirect(url_for("wallets"))

    w = Wallet(name=name, wallet_type=wallet_type, currency=currency, balance=opening_balance)
    db.session.add(w)
    db.session.flush()

    if opening_balance > 0:
        db.session.add(
            FinancialTransaction(
                wallet_id=w.id,
                tx_type="INFLOW",
                category="Capital",
                amount=opening_balance,
                description="Opening account balance",
                reference_id="INIT-BAL",
            )
        )

    db.session.commit()
    flash(f"Financial wallet '{name}' ({wallet_type}) created with initial balance ${opening_balance:,.2f}.", "success")
    return redirect(url_for("wallets"))


@app.route("/wallets/<int:wallet_id>/edit", methods=["POST"])
def edit_wallet(wallet_id):
    wallet = db.session.get(Wallet, wallet_id)
    if not wallet:
        flash("Wallet not found.", "error")
        return redirect(url_for("wallets"))

    name = request.form.get("name", "").strip()
    wallet_type = request.form.get("wallet_type", wallet.wallet_type).strip()
    currency = request.form.get("currency", wallet.currency).strip().upper() or "USD"

    if not name:
        flash("Wallet name cannot be empty.", "error")
        return redirect(url_for("wallets"))

    dup = Wallet.query.filter(func.lower(Wallet.name) == name.lower(), Wallet.id != wallet.id).first()
    if dup:
        flash(f"Another wallet named '{name}' already exists.", "error")
        return redirect(url_for("wallets"))

    wallet.name = name
    wallet.wallet_type = wallet_type
    wallet.currency = currency
    db.session.commit()
    flash(f"Wallet '{wallet.name}' updated.", "success")
    return redirect(url_for("wallets"))


@app.route("/wallets/<int:wallet_id>/delete", methods=["POST"])
def delete_wallet(wallet_id):
    wallet = db.session.get(Wallet, wallet_id)
    if not wallet:
        flash("Wallet not found.", "error")
        return redirect(url_for("wallets"))

    if Sale.query.filter_by(wallet_id=wallet.id).count() > 0 or PurchaseOrder.query.filter_by(wallet_id=wallet.id).count() > 0:
        flash(
            f"Cannot delete wallet '{wallet.name}' because it has linked sales or purchase orders.",
            "error",
        )
        return redirect(url_for("wallets"))

    w_name = wallet.name
    db.session.delete(wallet)
    db.session.commit()
    flash(f"Wallet '{w_name}' deleted.", "success")
    return redirect(url_for("wallets"))


@app.route("/wallets/transaction/add", methods=["POST"])
def add_wallet_transaction():
    wallet_id = request.form.get("wallet_id")
    tx_type = request.form.get("tx_type", "OUTFLOW").strip()
    category = request.form.get("category", "Operating Expense").strip()
    description = request.form.get("description", "").strip()
    reference_id = request.form.get("reference_id", "").strip()

    try:
        amount = float(request.form.get("amount", 0))
    except ValueError:
        flash("Please enter a valid numeric amount.", "error")
        return redirect(url_for("wallets"))

    if not wallet_id or amount <= 0:
        flash("Wallet and an amount greater than 0 are required.", "error")
        return redirect(url_for("wallets"))

    wallet = db.session.get(Wallet, int(wallet_id))
    if not wallet:
        flash("Selected wallet not found.", "error")
        return redirect(url_for("wallets"))

    if tx_type == "OUTFLOW":
        if wallet.balance < amount:
            flash(
                f"Insufficient balance in '{wallet.name}' (${wallet.balance:,.2f}) for outflow of ${amount:,.2f}.",
                "error",
            )
            return redirect(url_for("wallets"))
        wallet.balance -= amount
    elif tx_type == "INFLOW":
        wallet.balance += amount
    else:
        flash("Invalid transaction type.", "error")
        return redirect(url_for("wallets"))

    db.session.add(
        FinancialTransaction(
            wallet_id=wallet.id,
            tx_type=tx_type,
            category=category,
            amount=amount,
            description=description or f"{category} ({tx_type.title()})",
            reference_id=reference_id or f"TX-{datetime.utcnow().strftime('%m%d%H%M')}",
        )
    )
    db.session.commit()
    flash(f"Recorded {tx_type.lower()} ({category}) of ${amount:,.2f} in '{wallet.name}'.", "success")
    return redirect(url_for("wallets"))


# -------------------------------------------------------------------------
# 7. CONTACTS MODULE (CUSTOMERS & SUPPLIERS) CRUD
# -------------------------------------------------------------------------
@app.route("/contacts", methods=["GET", "POST"])
def contacts():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        contact_type = request.form.get("contact_type", "Customer").strip()
        tax_id = request.form.get("tax_id", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()

        if not name or contact_type not in ("Customer", "Supplier"):
            flash("Valid contact name and role (Customer / Supplier) are required.", "error")
            return redirect(url_for("contacts"))

        c = Contact(
            name=name,
            contact_type=contact_type,
            tax_id=tax_id,
            phone=phone,
            email=email,
            address=address,
        )
        db.session.add(c)
        db.session.commit()
        role_label = "Customer (Cliente)" if contact_type == "Customer" else "Supplier (Proveedor)"
        flash(f"{role_label} '{name}' registered in SQLite database.", "success")
        return redirect(url_for("contacts"))

    filter_type = request.args.get("type", "all")
    search_q = request.args.get("q", "").strip()

    query = Contact.query
    if filter_type in ("Customer", "Supplier"):
        query = query.filter_by(contact_type=filter_type)
    if search_q:
        like_pattern = f"%{search_q}%"
        query = query.filter(
            (Contact.name.ilike(like_pattern))
            | (Contact.tax_id.ilike(like_pattern))
            | (Contact.email.ilike(like_pattern))
            | (Contact.phone.ilike(like_pattern))
        )

    all_contacts = query.order_by(Contact.contact_type, Contact.name).all()

    customer_count = Contact.query.filter_by(contact_type="Customer").count()
    supplier_count = Contact.query.filter_by(contact_type="Supplier").count()

    return render_template(
        "contacts.html",
        contacts=all_contacts,
        filter_type=filter_type,
        search_q=search_q,
        customer_count=customer_count,
        supplier_count=supplier_count,
    )


@app.route("/contacts/<int:contact_id>/edit", methods=["POST"])
def edit_contact(contact_id):
    contact = db.session.get(Contact, contact_id)
    if not contact:
        flash("Contact not found.", "error")
        return redirect(url_for("contacts"))

    name = request.form.get("name", "").strip()
    contact_type = request.form.get("contact_type", contact.contact_type).strip()
    tax_id = request.form.get("tax_id", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()

    if not name or contact_type not in ("Customer", "Supplier"):
        flash("Valid contact name and role (Customer / Supplier) are required.", "error")
        return redirect(url_for("contacts"))

    contact.name = name
    contact.contact_type = contact_type
    contact.tax_id = tax_id
    contact.phone = phone
    contact.email = email
    contact.address = address
    db.session.commit()
    flash(f"Contact '{contact.name}' updated.", "success")
    return redirect(url_for("contacts"))


@app.route("/contacts/<int:contact_id>/delete", methods=["POST"])
def delete_contact(contact_id):
    contact = db.session.get(Contact, contact_id)
    if not contact:
        flash("Contact not found.", "error")
        return redirect(url_for("contacts"))

    if PurchaseOrder.query.filter_by(supplier_id=contact.id).count() > 0:
        flash(f"Cannot delete supplier '{contact.name}' because it is linked to historical purchase orders.", "error")
        return redirect(url_for("contacts"))

    Sale.query.filter_by(customer_id=contact.id).update({"customer_id": None})
    StockMovement.query.filter_by(supplier_id=contact.id).update({"supplier_id": None})

    name = contact.name
    db.session.delete(contact)
    db.session.commit()
    flash(f"Contact '{name}' deleted.", "success")
    return redirect(url_for("contacts"))


# -------------------------------------------------------------------------
# 8. MONTHLY CLOSING (CIERRE DE MES) INTEGRATED WITH WALLETS, SALES & PURCHASES
# -------------------------------------------------------------------------
MONTH_NAMES = [
    (1, "January"),
    (2, "February"),
    (3, "March"),
    (4, "April"),
    (5, "May"),
    (6, "June"),
    (7, "July"),
    (8, "August"),
    (9, "September"),
    (10, "October"),
    (11, "November"),
    (12, "December"),
]


def _compile_closing_data(month_param: str):
    now = datetime.utcnow()
    if month_param == "all":
        start_date = datetime(2000, 1, 1)
        end_date = datetime(2100, 1, 1)
        period_label = "All-Time Cumulative"
        selected_year = now.year
        selected_month_num = now.month
    else:
        try:
            year, month = map(int, month_param.split("-"))
            if not (1 <= month <= 12):
                raise ValueError("Invalid month")
            start_date = datetime(year, month, 1)
            end_date = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)
            selected_year = year
            selected_month_num = month
            period_label = start_date.strftime("%B %Y")
        except ValueError:
            selected_year, selected_month_num = now.year, now.month
            month_param = f"{selected_year:04d}-{selected_month_num:02d}"
            start_date = datetime(selected_year, selected_month_num, 1)
            end_date = (
                datetime(selected_year + 1, 1, 1)
                if selected_month_num == 12
                else datetime(selected_year, selected_month_num + 1, 1)
            )
            period_label = start_date.strftime("%B %Y")

    # 1. Sales & COGS for the period
    monthly_sales = (
        Sale.query.filter(Sale.created_at >= start_date, Sale.created_at < end_date)
        .order_by(Sale.created_at.desc())
        .all()
    )

    # 2. Purchase Orders for the period
    monthly_pos = (
        PurchaseOrder.query.filter(PurchaseOrder.created_at >= start_date, PurchaseOrder.created_at < end_date)
        .order_by(PurchaseOrder.created_at.desc())
        .all()
    )

    # 3. All Wallet Movements for the period
    monthly_txs = (
        FinancialTransaction.query.filter(
            FinancialTransaction.created_at >= start_date,
            FinancialTransaction.created_at < end_date,
        )
        .order_by(FinancialTransaction.created_at.desc())
        .all()
    )

    # Aggregate directly from Wallet Movements & Sales
    wallet_sales_inflow = sum(
        tx.amount for tx in monthly_txs if tx.tx_type == "INFLOW" and tx.category == "Sale"
    )
    sales_table_revenue = sum(s.total_amount for s in monthly_sales)
    sales_revenue = max(wallet_sales_inflow, sales_table_revenue)

    cogs_total = sum(s.total_cogs for s in monthly_sales)
    gross_profit = sales_revenue - cogs_total

    # Outflows from Wallet Movements by Category
    inventory_purchases_outflow = sum(
        tx.amount for tx in monthly_txs if tx.tx_type == "OUTFLOW" and tx.category == "Purchase"
    )
    ship_fees_total = sum(
        tx.amount for tx in monthly_txs if tx.tx_type == "OUTFLOW" and tx.category == "Ship Fee"
    )
    operating_expenses = sum(
        tx.amount
        for tx in monthly_txs
        if tx.tx_type == "OUTFLOW" and tx.category not in ("Purchase", "Ship Fee")
    )
    other_income = sum(
        tx.amount
        for tx in monthly_txs
        if tx.tx_type == "INFLOW" and tx.category not in ("Sale", "Capital")
    )

    # Total Wallet Cash Flow (All Inflows vs All Outflows in Wallets)
    total_wallet_inflows = sum(tx.amount for tx in monthly_txs if tx.tx_type == "INFLOW")
    total_wallet_outflows = sum(tx.amount for tx in monthly_txs if tx.tx_type == "OUTFLOW")
    net_wallet_cashflow = total_wallet_inflows - total_wallet_outflows

    # 4. Inventory Shrinkage / Losses (Expiration, Damage, Donations)
    loss_movements = (
        StockMovement.query.filter(
            StockMovement.created_at >= start_date,
            StockMovement.created_at < end_date,
            StockMovement.movement_type.in_(["LOSS_EXPIRATION", "LOSS_DAMAGE", "LOSS_DONATION"]),
        )
        .order_by(StockMovement.created_at.desc())
        .all()
    )
    inventory_loss_value = sum(m.quantity * m.unit_cost for m in loss_movements)

    # 5. Accurate Net Profit calculation:
    # Revenue + Other Income - COGS - Operating Expenses - Shipping Fees (- Inventory Shrinkage)
    net_profit = (
        sales_revenue
        + other_income
        - cogs_total
        - operating_expenses
        - ship_fees_total
        - inventory_loss_value
    )
    gross_margin_pct = (gross_profit / sales_revenue * 100.0) if sales_revenue > 0 else 0.0
    net_margin_pct = (net_profit / sales_revenue * 100.0) if sales_revenue > 0 else 0.0

    # Breakdown by Wallet for the period
    wallet_monthly_summary = {}
    for w in Wallet.query.order_by(Wallet.name).all():
        wallet_monthly_summary[w.name] = {
            "wallet": w,
            "sales_in": 0.0,
            "other_in": 0.0,
            "purchases_out": 0.0,
            "ship_fee_out": 0.0,
            "opex_out": 0.0,
        }

    for tx in monthly_txs:
        w_name = tx.wallet.name if tx.wallet else "Unknown"
        if w_name not in wallet_monthly_summary:
            wallet_monthly_summary[w_name] = {
                "wallet": tx.wallet,
                "sales_in": 0.0,
                "other_in": 0.0,
                "purchases_out": 0.0,
                "ship_fee_out": 0.0,
                "opex_out": 0.0,
            }
        entry = wallet_monthly_summary[w_name]
        if tx.tx_type == "INFLOW":
            if tx.category == "Sale":
                entry["sales_in"] += tx.amount
            else:
                entry["other_in"] += tx.amount
        elif tx.tx_type == "OUTFLOW":
            if tx.category == "Purchase":
                entry["purchases_out"] += tx.amount
            elif tx.category == "Ship Fee":
                entry["ship_fee_out"] += tx.amount
            else:
                entry["opex_out"] += tx.amount

    # Breakdown by Location for the period
    location_sales = {}
    for s in monthly_sales:
        loc_name = s.location.name if s.location else "Unknown"
        if loc_name not in location_sales:
            location_sales[loc_name] = {"orders": 0, "revenue": 0.0, "cogs": 0.0}
        location_sales[loc_name]["orders"] += 1
        location_sales[loc_name]["revenue"] += s.total_amount
        location_sales[loc_name]["cogs"] += s.total_cogs

    return {
        "selected_month": month_param,
        "selected_year": selected_year,
        "selected_month_num": selected_month_num,
        "period_label": period_label,
        "sales_revenue": sales_revenue,
        "cogs_total": cogs_total,
        "gross_profit": gross_profit,
        "gross_margin_pct": gross_margin_pct,
        "operating_expenses": operating_expenses,
        "ship_fees_total": ship_fees_total,
        "inventory_purchases_outflow": inventory_purchases_outflow,
        "other_income": other_income,
        "inventory_loss_value": inventory_loss_value,
        "net_profit": net_profit,
        "net_margin_pct": net_margin_pct,
        "total_wallet_inflows": total_wallet_inflows,
        "total_wallet_outflows": total_wallet_outflows,
        "net_wallet_cashflow": net_wallet_cashflow,
        "wallet_monthly_summary": wallet_monthly_summary,
        "monthly_sales": monthly_sales,
        "monthly_pos": monthly_pos,
        "monthly_txs": monthly_txs,
        "loss_movements": loss_movements,
        "location_sales": location_sales,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def _resolve_requested_month() -> str:
    now = datetime.utcnow()
    source = request.form if request.method == "POST" else request.args
    period_mode = source.get("period_mode", "").strip()
    if period_mode == "all" or source.get("month") == "all":
        return "all"

    year_val = source.get("year")
    month_num_val = source.get("month_num")
    if year_val and month_num_val:
        try:
            return f"{int(year_val):04d}-{int(month_num_val):02d}"
        except ValueError:
            pass

    month_str = source.get("month", "").strip()
    if month_str:
        return month_str

    return now.strftime("%Y-%m")


@app.route("/closing", methods=["GET", "POST"])
def closing():
    month_param = _resolve_requested_month()
    data = _compile_closing_data(month_param)

    report_generated = (
        request.method == "POST"
        or request.args.get("generate") == "1"
        or "month" in request.args
        or "year" in request.args
    )

    if request.method == "POST" or request.args.get("generate") == "1":
        flash(
            f"Monthly Closing Report generated for {data['period_label']} — Net Profit: ${data['net_profit']:,.2f}",
            "success",
        )

    now_year = datetime.utcnow().year
    available_years = list(range(now_year - 3, now_year + 2))

    return render_template(
        "closing.html",
        report_generated=report_generated,
        month_names=MONTH_NAMES,
        available_years=available_years,
        **data,
    )


@app.route("/closing/api", methods=["GET"])
def closing_api():
    month_param = _resolve_requested_month()
    data = _compile_closing_data(month_param)
    return jsonify(
        {
            "selected_month": data["selected_month"],
            "period_label": data["period_label"],
            "generated_at": data["generated_at"],
            "sales_revenue": round(data["sales_revenue"], 2),
            "cogs_total": round(data["cogs_total"], 2),
            "gross_profit": round(data["gross_profit"], 2),
            "gross_margin_pct": round(data["gross_margin_pct"], 2),
            "operating_expenses": round(data["operating_expenses"], 2),
            "ship_fees_total": round(data["ship_fees_total"], 2),
            "inventory_purchases_outflow": round(data["inventory_purchases_outflow"], 2),
            "other_income": round(data["other_income"], 2),
            "inventory_loss_value": round(data["inventory_loss_value"], 2),
            "net_profit": round(data["net_profit"], 2),
            "net_margin_pct": round(data["net_margin_pct"], 2),
            "total_wallet_inflows": round(data["total_wallet_inflows"], 2),
            "total_wallet_outflows": round(data["total_wallet_outflows"], 2),
            "net_wallet_cashflow": round(data["net_wallet_cashflow"], 2),
            "sales_count": len(data["monthly_sales"]),
            "purchases_count": len(data["monthly_pos"]),
            "transactions_count": len(data["monthly_txs"]),
        }
    )


@app.route("/closing/export", methods=["GET"])
def closing_export():
    month_param = _resolve_requested_month()
    data = _compile_closing_data(month_param)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["RUSAIMPORT - MONTHLY CLOSING REPORT (CIERRE DE MES)"])
    writer.writerow(["Period", data["period_label"]])
    writer.writerow(["Generated At", data["generated_at"]])
    writer.writerow([])

    writer.writerow(["INCOME STATEMENT (P&L) SUMMARY", "AMOUNT (USD)"])
    writer.writerow(["(+) Sales Revenue", f"{data['sales_revenue']:.2f}"])
    writer.writerow(["(+) Other Operating Inflows", f"{data['other_income']:.2f}"])
    writer.writerow(["(-) Cost of Goods Sold (COGS)", f"-{data['cogs_total']:.2f}"])
    writer.writerow(["(=) Gross Profit", f"{data['gross_profit']:.2f}"])
    writer.writerow(["(-) Operating Expenses", f"-{data['operating_expenses']:.2f}"])
    writer.writerow(["(-) Supplier Shipping Fees (Fletes)", f"-{data['ship_fees_total']:.2f}"])
    writer.writerow(["(-) Inventory Shrinkage / Losses", f"-{data['inventory_loss_value']:.2f}"])
    writer.writerow(["(=) NET PROFIT (UTILIDAD NETA)", f"{data['net_profit']:.2f}"])
    writer.writerow([])

    writer.writerow(["WALLET CASH FLOW SUMMARY", "AMOUNT (USD)"])
    writer.writerow(["Total Wallet Inflows", f"{data['total_wallet_inflows']:.2f}"])
    writer.writerow(["Merchandise Purchases Outflows", f"-{data['inventory_purchases_outflow']:.2f}"])
    writer.writerow(["Shipping Fees Outflows", f"-{data['ship_fees_total']:.2f}"])
    writer.writerow(["Operating Expenses Outflows", f"-{data['operating_expenses']:.2f}"])
    writer.writerow(["Total Wallet Outflows", f"-{data['total_wallet_outflows']:.2f}"])
    writer.writerow(["Net Monthly Wallet Cash Flow", f"{data['net_wallet_cashflow']:.2f}"])
    writer.writerow([])

    writer.writerow(["WALLET TRANSACTIONS DETAIL"])
    writer.writerow(["Date", "Reference", "Wallet", "Direction", "Category", "Description", "Amount (USD)"])
    for tx in data["monthly_txs"]:
        sign = "+" if tx.tx_type == "INFLOW" else "-"
        writer.writerow(
            [
                tx.created_at.strftime("%Y-%m-%d %H:%M"),
                tx.reference_id,
                tx.wallet.name if tx.wallet else "",
                tx.tx_type,
                tx.category,
                tx.description,
                f"{sign}{tx.amount:.2f}",
            ]
        )

    csv_content = output.getvalue()
    filename = f"RusaImport_Closing_{data['selected_month']}.csv"
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


with app.app_context():
    db.create_all()
    ensure_schema_migrations()
    ensure_default_admin()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
