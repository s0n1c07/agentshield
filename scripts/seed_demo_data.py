from __future__ import annotations

from dotenv import load_dotenv

from config import Settings
from engine.authorization import SQLiteAuthorizationAuthority
from engine.catalog import SQLiteCatalog
from models.authorization import AgentAuthorization
from models.catalog import CatalogProduct


def main() -> None:
    load_dotenv()

    settings = Settings.from_environment()

    authorization_authority = SQLiteAuthorizationAuthority(
        f"{settings.database_path}.authorization",
    )

    catalog = SQLiteCatalog(
        f"{settings.database_path}.catalog",
    )

    authorization = AgentAuthorization(
        user_id=settings.api_user_id,
        agent_id=settings.api_agent_id,
        authorization_id="demo-auth-001",
        active=True,
        revoked=False,
        max_amount_paise=500000,
        allowed_merchants=["merchant_001"],
        allowed_categories=["footwear"],
        allowed_skus=["shoe_001"],
        max_quantity=2,
        currency="INR",
        daily_limit_paise=1000000,
        monthly_limit_paise=5000000,
        timezone="Asia/Kolkata",
        approval_threshold_paise=300000,
    )

    existing_authorization = authorization_authority.get(
        authorization.authorization_id,
    )

    if existing_authorization is None:
        authorization_authority.create(
            authorization,
        )
        print("Created demo authorization: demo-auth-001")
    elif (
        existing_authorization.user_id != authorization.user_id
        or existing_authorization.agent_id != authorization.agent_id
        or existing_authorization.authorization_id
        != authorization.authorization_id
        or existing_authorization.active
        != authorization.active
        or existing_authorization.revoked
        != authorization.revoked
        or existing_authorization.max_amount_paise
        != authorization.max_amount_paise
        or existing_authorization.allowed_merchants
        != authorization.allowed_merchants
        or existing_authorization.allowed_categories
        != authorization.allowed_categories
        or existing_authorization.allowed_skus
        != authorization.allowed_skus
        or existing_authorization.max_quantity
        != authorization.max_quantity
        or existing_authorization.currency
        != authorization.currency
        or existing_authorization.expires_at
        != authorization.expires_at
        or existing_authorization.daily_limit_paise
        != authorization.daily_limit_paise
        or existing_authorization.monthly_limit_paise
        != authorization.monthly_limit_paise
        or existing_authorization.timezone
        != authorization.timezone
        or existing_authorization.approval_threshold_paise
        != authorization.approval_threshold_paise
    ):
        raise RuntimeError(
            "demo-auth-001 already exists with different bounds"
        )
    else:
        print("Demo authorization already exists")

    product = CatalogProduct(
        merchant_id="merchant_001",
        sku="shoe_001",
        name="AgentShield Running Shoe",
        category="footwear",
        price_paise=450000,
        currency="INR",
        stock=10,
    )

    existing_product = catalog.get(product.sku)

    if existing_product is None:
        catalog.create(product)
        print("Created demo catalog product: shoe_001")
    elif existing_product != product:
        raise RuntimeError(
            "shoe_001 already exists with different catalog facts"
        )
    else:
        print("Demo catalog product already exists")

    print()
    print("Demo data ready")
    print("Authorization: demo-auth-001")
    print("Merchant: merchant_001")
    print("SKU: shoe_001")
    print("Price: ₹4,500")
    print("Maximum authorization: ₹5,000")
    print("Maximum quantity: 2")
    print("Stock: 10")


if __name__ == "__main__":
    main()
