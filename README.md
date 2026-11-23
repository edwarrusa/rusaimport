# RusaImport — Business Management & Multi-Location Inventory System

**RusaImport** is a full-stack business management, point-of-sale (POS), treasury wallets, and multi-location inventory web application built with **Python (Flask)**, **SQLite (SQLAlchemy)**, and **Tailwind CSS**.

## Key Features

1. **Executive Dashboard**: Real-time metrics for total inventory valuation, active locations, monthly sales revenue, and combined treasury wallet balances.
2. **Multi-Location Inventory & Location Filter**: Manage multiple warehouses, retail stores, and transit hubs. Create products (`SKU`, `Name`, `Category`, `Cost`, `Price`, `Min Stock Alert`) and filter stock by individual location or view all locations.
3. **Merchandise Purchases (*Compras de Mercancía*)**: Create supplier purchase orders with multi-item support, target location assignment, and supplier **Ship Fee (*Costo de Envío / Flete*)** automatically deducted from the selected financial wallet.
4. **Stock Movements & Adjustments**: Inter-location transfers and write-off adjustments for expiration, damage, and donations.
5. **Sales Module (POS)**: Create customer sales invoices selecting the exact **Dispatch Inventory Location** and **Receiving Payment Wallet**.
6. **Wallets & Financials**: Track `Cash`, `Zelle`, `Bank`, and `Crypto` accounts with a full inflow/outflow ledger.
7. **Contacts (CRM & Suppliers)**: Full CRUD directory for Customers (*Clientes*) and Suppliers (*Proveedores*).
8. **Monthly Closing (*Cierre de Mes*)**: Automated P&L statement ($\text{Revenue} - \text{COGS} - \text{Operating Expenses} - \text{Shipping Fees} - \text{Inventory Shrinkage}$), Wallet Cash Flow summary, printable PDF view, and CSV export.
9. **Authentication & Security**: Session-based authentication with `werkzeug.security` password hashing and role management.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.
- Default Admin Username: `admin`
- Default Admin Password: `admin123` (or reset via `python create_admin.py <username> <password>`)
