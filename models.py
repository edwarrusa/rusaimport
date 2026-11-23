from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="Admin")  # Admin, Manager, Cashier
    is_admin = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Location(db.Model):
    __tablename__ = "locations"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    location_type = db.Column(db.String(50), nullable=False, default="Warehouse")  # Warehouse, Store, Transit Hub
    address = db.Column(db.String(200), default="")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    stocks = db.relationship("LocationStock", back_populates="location", cascade="all, delete-orphan")


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(50), nullable=False, unique=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(80), default="General")
    cost = db.Column(db.Float, nullable=False, default=0.0)
    price = db.Column(db.Float, nullable=False, default=0.0)
    min_stock = db.Column(db.Integer, nullable=False, default=5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    stocks = db.relationship("LocationStock", back_populates="product", cascade="all, delete-orphan")

    @property
    def total_quantity(self):
        return sum(s.quantity for s in self.stocks)

    @property
    def total_valuation(self):
        return self.total_quantity * self.cost


class LocationStock(db.Model):
    __tablename__ = "location_stocks"
    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)

    location = db.relationship("Location", back_populates="stocks")
    product = db.relationship("Product", back_populates="stocks")

    __table_args__ = (db.UniqueConstraint("location_id", "product_id", name="uq_location_product"),)


class Contact(db.Model):
    __tablename__ = "contacts"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    contact_type = db.Column(db.String(30), nullable=False)  # Customer, Supplier
    tax_id = db.Column(db.String(50), default="")
    phone = db.Column(db.String(50), default="")
    email = db.Column(db.String(120), default="")
    address = db.Column(db.String(200), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Wallet(db.Model):
    __tablename__ = "wallets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    wallet_type = db.Column(db.String(50), nullable=False)  # Cash, Bank, Zelle, Crypto, Crypto/Zelle
    currency = db.Column(db.String(10), nullable=False, default="USD")
    balance = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    transactions = db.relationship(
        "FinancialTransaction",
        back_populates="wallet",
        order_by="desc(FinancialTransaction.created_at)",
        cascade="all, delete-orphan",
    )


class FinancialTransaction(db.Model):
    __tablename__ = "financial_transactions"
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallets.id"), nullable=False)
    tx_type = db.Column(db.String(20), nullable=False)  # INFLOW, OUTFLOW
    # Categories: Sale, Purchase, Ship Fee, Operating Expense, Capital, Adjustment
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255), default="")
    reference_id = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    wallet = db.relationship("Wallet", back_populates="transactions")


class PurchaseOrder(db.Model):
    __tablename__ = "purchase_orders"
    id = db.Column(db.Integer, primary_key=True)
    po_number = db.Column(db.String(40), nullable=False, unique=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("contacts.id"), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallets.id"), nullable=False)
    products_subtotal = db.Column(db.Float, nullable=False, default=0.0)
    ship_fee = db.Column(db.Float, nullable=False, default=0.0)
    total_amount = db.Column(db.Float, nullable=False, default=0.0)
    notes = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    supplier = db.relationship("Contact")
    location = db.relationship("Location")
    wallet = db.relationship("Wallet")
    items = db.relationship("PurchaseItem", back_populates="purchase_order", cascade="all, delete-orphan")


class PurchaseItem(db.Model):
    __tablename__ = "purchase_items"
    id = db.Column(db.Integer, primary_key=True)
    purchase_order_id = db.Column(db.Integer, db.ForeignKey("purchase_orders.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_cost = db.Column(db.Float, nullable=False)

    purchase_order = db.relationship("PurchaseOrder", back_populates="items")
    product = db.relationship("Product")
    location = db.relationship("Location")

    @property
    def subtotal(self):
        return self.quantity * self.unit_cost


class StockMovement(db.Model):
    __tablename__ = "stock_movements"
    id = db.Column(db.Integer, primary_key=True)
    movement_type = db.Column(
        db.String(30), nullable=False
    )  # PURCHASE, TRANSFER, LOSS_EXPIRATION, LOSS_DAMAGE, LOSS_DONATION, SALE
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    from_location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=True)
    to_location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=True)
    quantity = db.Column(db.Integer, nullable=False)
    unit_cost = db.Column(db.Float, nullable=False, default=0.0)
    supplier_id = db.Column(db.Integer, db.ForeignKey("contacts.id"), nullable=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallets.id"), nullable=True)
    notes = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship("Product")
    from_location = db.relationship("Location", foreign_keys=[from_location_id])
    to_location = db.relationship("Location", foreign_keys=[to_location_id])
    supplier = db.relationship("Contact")
    wallet = db.relationship("Wallet")


class Sale(db.Model):
    __tablename__ = "sales"
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(40), nullable=False, unique=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("contacts.id"), nullable=True)
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallets.id"), nullable=False)
    total_amount = db.Column(db.Float, nullable=False, default=0.0)
    total_cogs = db.Column(db.Float, nullable=False, default=0.0)
    notes = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer = db.relationship("Contact")
    location = db.relationship("Location")
    wallet = db.relationship("Wallet")
    items = db.relationship("SaleItem", back_populates="sale", cascade="all, delete-orphan")


class SaleItem(db.Model):
    __tablename__ = "sale_items"
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey("sales.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    unit_cost = db.Column(db.Float, nullable=False)

    sale = db.relationship("Sale", back_populates="items")
    product = db.relationship("Product")

    @property
    def subtotal(self):
        return self.quantity * self.unit_price

    @property
    def cogs_subtotal(self):
        return self.quantity * self.unit_cost
