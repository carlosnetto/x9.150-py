import json
import os
import uuid
import random
import copy
import yaml
import argparse
from openapi_schema_validator import validate
from datetime import datetime, timedelta, timezone

# --- 1. CONFIGURATION SEED DATA ---
RAIL_MAPPING = {
    "USD": ["FedNow", "RTP", "ACH", "Zelle"],
    "BRL": ["Pix"],
    "USDC": ["Base", "Solana", "Ethereum"],
    "PYUSD": ["Ethereum", "Solana"],
    "WETH-V2": ["Ethereum", "Polygon"]
}

NETWORK_DEFINITIONS = {
    "FedNow": "banking",
    "RTP": "banking",
    "ACH": "banking",
    "Zelle": "zelle",
    "Pix": "pix",
    "Base": "evm",
    "Solana": "solana",
    "Ethereum": "evm",
    "Polygon": "evm"
}

EVM_ADDRESSES = [
    "0xa6d0AeFeB0427E0011003BFD8486f7b12b8C2ceb",
    "0xDd1Cb5CbcF8B05C88aE47Cb32402719B99FeD811"
]

SOLANA_ADDRESSES = [
    "7xKXq2unvS9Yv6p7mP99999999999999999999999999",
    "H6ARHf6Y2snU8986JS2S899999999999999999999999",
    "Gv999999999999999999999999999999999999999999"
]

PERSONAS = {
    "INDIRECT_PAYEE": {
        "is_aggregated": True,
        "aggregators": [
            {
                "name": "Intuit Payments Inc.",
                "MCC": "7399",
                "email": "payments-support@intuit.com",
                "phone": "+18004468848",
                "address": {"line1": "2700 Coast Ave", "city": "Mountain View", "state": "CA", "country": "US", "postalCode": "94043"},
                "account_suffix": "@quickbooks.com"
            },
            {
                "name": "PayPal Inc.",
                "MCC": "7399",
                "email": "support@paypal.com",
                "phone": "+18882211161",
                "address": {"line1": "2211 North First Street", "city": "San Jose", "state": "CA", "country": "US", "postalCode": "95131"},
                "account_suffix": "@paypal.com"
            },
            {
                "name": "Cash App (Block Inc.)",
                "MCC": "7399",
                "email": "support@cash.app",
                "phone": "+18009691940",
                "address": {"line1": "1455 Market Street", "city": "San Francisco", "state": "CA", "country": "US", "postalCode": "94103"},
                "account_suffix": "@cash.app"
            },
            {
                "name": "Venmo",
                "MCC": "7399",
                "email": "support@venmo.com",
                "phone": "+18558124430",
                "address": {"line1": "117 Barrow St", "city": "New York", "state": "NY", "country": "US", "postalCode": "10014"},
                "account_suffix": "@venmo.com"
            },
            {
                "name": "Apple Cash",
                "MCC": "7399",
                "email": "support@apple.com",
                "phone": "+18002752273",
                "address": {"line1": "One Apple Park Way", "city": "Cupertino", "state": "CA", "country": "US", "postalCode": "95014"},
                "account_suffix": "@apple.com"
            }
        ],
        "sub_types": [
            {"name": "Green Leaf Landscaping", "MCC": "0780", "unstructured": "Invoice #{ref} - Monthly Lawn Care", "city": "San Jose", "country": "US"},
            {"name": "Top Tier Plumbing", "MCC": "1711", "unstructured": "Service Call #{ref} - Leak Repair", "city": "Palo Alto", "country": "US"},
            {"name": "Sparky's Electric", "MCC": "1731", "unstructured": "Job #{ref} - Panel Upgrade", "city": "Sunnyvale", "country": "US"},
            {"name": "Mama's Bakery", "MCC": "5462", "unstructured": "Order #{ref} - Catering Deposit", "city": "San Francisco", "country": "US"},
            {"name": "Joe's Auto Repair", "MCC": "7538", "unstructured": "Repair Order #{ref}", "city": "Oakland", "country": "US"},
            {"name": "Bella's Boutique", "MCC": "5621", "unstructured": "Purchase #{ref}", "city": "Los Angeles", "country": "US"},
            {"name": "Tech Fixers", "MCC": "7379", "unstructured": "Repair #{ref}", "city": "San Diego", "country": "US"},
            {"name": "City Yoga Studio", "MCC": "7991", "unstructured": "Class Pack #{ref}", "city": "Santa Monica", "country": "US"},
            {"name": "Pet Palace Grooming", "MCC": "0742", "unstructured": "Grooming #{ref}", "city": "Pasadena", "country": "US"},
            {"name": "Dr. Smith Dental", "MCC": "8021", "unstructured": "Visit #{ref}", "city": "Sacramento", "country": "US"},
            {"name": "Legal Services LLC", "MCC": "8111", "unstructured": "Retainer #{ref}", "city": "Fresno", "country": "US"},
            {"name": "Happy Kids Daycare", "MCC": "8351", "unstructured": "Tuition #{ref}", "city": "Long Beach", "country": "US"},
            {"name": "Downtown Parking", "MCC": "7523", "unstructured": "Monthly Pass #{ref}", "city": "San Francisco", "country": "US"},
            {"name": "Clean & Press Dry Cleaners", "MCC": "7216", "unstructured": "Order #{ref}", "city": "San Jose", "country": "US"},
            {"name": "Fit Life Gym", "MCC": "7997", "unstructured": "Membership #{ref}", "city": "Irvine", "country": "US"},
            {"name": "Quick Print Shop", "MCC": "7338", "unstructured": "Job #{ref}", "city": "Glendale", "country": "US"},
            {"name": "Valley Vet Clinic", "MCC": "0742", "unstructured": "Exam #{ref}", "city": "Bakersfield", "country": "US"},
            {"name": "Sunset Cafe", "MCC": "5812", "unstructured": "Table #{ref}", "city": "Santa Barbara", "country": "US"},
            {"name": "Mobile Car Wash", "MCC": "7542", "unstructured": "Wash #{ref}", "city": "Anaheim", "country": "US"},
            {"name": "Home Cleaning Pros", "MCC": "7349", "unstructured": "Service #{ref}", "city": "Riverside", "country": "US"}
        ]
    },
    "DIRECT_PAYEE": {
        "is_aggregated": False,
        "sub_types": [
            {"name": "Skybound Airlines", "MCC": "4511", "unstructured": "Booking {ref} - JFK to GRU", "city": "New York", "country": "US"},
            {"name": "Central Power & Light", "MCC": "4900", "unstructured": "Account {ref} - Jan 2026 Bill", "city": "Chicago", "country": "US"},
            {"name": "Metro Water Services", "MCC": "4941", "unstructured": "Bill {ref} - Water/Sewer", "city": "Seattle", "country": "US"},
            {"name": "Global Telecom", "MCC": "4814", "unstructured": "Invoice {ref} - Monthly Plan", "city": "Dallas", "country": "US"},
            {"name": "City General Hospital", "MCC": "8062", "unstructured": "Patient Account {ref}", "city": "Boston", "country": "US"},
            {"name": "State University", "MCC": "8220", "unstructured": "Tuition Payment {ref}", "city": "Austin", "country": "US"},
            {"name": "Luxury Hotels Int.", "MCC": "7011", "unstructured": "Reservation {ref}", "city": "Miami", "country": "US"},
            {"name": "Rapid Rail Transit", "MCC": "4111", "unstructured": "Ticket {ref}", "city": "Washington", "country": "US"},
            {"name": "National Insurance", "MCC": "6300", "unstructured": "Policy {ref} Premium", "city": "Hartford", "country": "US"},
            {"name": "Streamline Internet", "MCC": "4816", "unstructured": "Account {ref} - Fiber Optic", "city": "Denver", "country": "US"},
            {"name": "Prime Logistics", "MCC": "4214", "unstructured": "Invoice {ref} - Freight", "city": "Memphis", "country": "US"},
            {"name": "TechGadget Store", "MCC": "5732", "unstructured": "Order {ref}", "city": "San Diego", "country": "US"},
            {"name": "Fresh Market", "MCC": "5411", "unstructured": "Receipt {ref}", "city": "Atlanta", "country": "US"},
            {"name": "Mega Gym", "MCC": "7997", "unstructured": "Membership {ref}", "city": "Los Angeles", "country": "US"},
            {"name": "City Parking", "MCC": "7523", "unstructured": "Ticket {ref}", "city": "Chicago", "country": "US"},
            {"name": "Streaming Plus", "MCC": "5815", "unstructured": "Subscription {ref}", "city": "New York", "country": "US"},
            {"name": "RideShare Corp", "MCC": "4121", "unstructured": "Trip {ref}", "city": "San Francisco", "country": "US"},
            {"name": "Home Security Sys", "MCC": "7393", "unstructured": "Account {ref}", "city": "Phoenix", "country": "US"},
            {"name": "Waste Management", "MCC": "4953", "unstructured": "Invoice {ref}", "city": "Houston", "country": "US"},
            {"name": "Gas & Oil Co.", "MCC": "5541", "unstructured": "Pump {ref}", "city": "Detroit", "country": "US"}
        ]
    }
}

# --- 2. THE DATA FACTORY (VALID SAMPLES) ---
class X9150DataFactory:
    def _generate_uuid_no_dashes(self):
        return uuid.uuid4().hex  # 32 chars, no dashes

    def _get_timestamp(self, offset_minutes=0):
        dt = datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.000Z') # Mandatory .000Z precision

    def generate_sample(self, force_indirect=False):
        category = "INDIRECT_PAYEE" if force_indirect else random.choice(list(PERSONAS.keys()))
        persona = PERSONAS[category]
        sub_biz = random.choice(persona["sub_types"])
        
        if persona["is_aggregated"]:
            aggregator = random.choice(persona["aggregators"])
            creditor = {
                "name": aggregator["name"],
                "MCC": aggregator["MCC"],
                "email": aggregator["email"],
                "phone": aggregator["phone"],
                "address": aggregator["address"]
            }
            suffix = aggregator.get("account_suffix", "@quickbooks.com")
            creditor["ultimateCreditor"] = {
                "name": sub_biz["name"],
                "address": {"city": sub_biz["city"], "country": sub_biz["country"]},
                "account": {
                    "id": f"{sub_biz['name'].lower().replace(' ', '.')}{suffix}",
                    "schemaName": "email"
                }
            }
        else:
            creditor = {
                "name": sub_biz["name"], 
                "MCC": sub_biz["MCC"],
                "address": {"city": sub_biz["city"], "country": sub_biz["country"]}
            }

        ref_id = random.randint(1000, 9999)
        methods = self._generate_payment_methods()
        now = self._get_timestamp()

        # Tip logic: if allowed, range and presets are mandatory
        tip_allowed = random.random() < 0.3  # 30% chance of allowing tips
        tip_config = {"allowed": tip_allowed}
        if tip_allowed:
            tip_config["range"] = {"min": 0, "max": 300}  # 0% to 30.0%
            tip_config["presets"] = [100, 150, 200]       # 10%, 15%, 20%

        amount_due = {
            "amount": methods[0]["amount"],
            "currency": methods[0]["currency"]
        }
        # Randomly add an adjustment (20% chance) to test the schema
        if random.random() < 0.2:
            amount_due["adjustments"] = [{
                "explanation": "Loyalty Discount",
                "amount": -50, # -0.50
                "validUntil": self._get_timestamp(offset_minutes=30)
            }]

        return {
            "id": self._generate_uuid_no_dashes(),
            "revision": 0, # Initial version
            "qrCodeContent": "bank_com_fetch_" + self._generate_uuid_no_dashes()[:12],
            "status": "ACTIVE",
            # X9.150 Rule: For revision 0, createdAt SHALL equal revisedAt
            "createdAt": now, 
            "revisedAt": now, 
            "sentAt": now,
            "validUntil": self._get_timestamp(offset_minutes=60),
            "creditor": creditor,
            "bill": {
                "description": sub_biz["unstructured"].format(ref=ref_id),
                "paymentTiming": random.choice(["immediate", "deferred"]),
                "amountDue": amount_due,
                "tip": tip_config
            },
            "unstructured": sub_biz["unstructured"].format(ref=ref_id),
            "paymentMethods": methods
        }

    def _generate_payment_methods(self):
        currencies = random.sample(list(RAIL_MAPPING.keys()), k=random.randint(1, 2))
        # Base amount in USD cents (max 9999 = $99.99)
        base_usd_cents = random.randint(1000, 9999)

        methods = []
        for curr in currencies:
            if curr == "USD":
                amount = base_usd_cents
            elif curr == "USDC":
                # 1:1 with USD, but 6 decimals (10^6) vs USD 2 decimals (10^2)
                amount = base_usd_cents * 10000
            elif curr == "BRL":
                # Always 5x the USD amount for consistency
                amount = base_usd_cents * 5
            elif curr == "PYUSD":
                # Assuming 6 decimals for consistency with USDC
                amount = base_usd_cents * 10000
            else:
                # Fallback for other currencies like WETH-V2
                amount = base_usd_cents

            methods.append({
                "currency": curr,
                "amount": amount,
                "validUntil": self._get_timestamp(offset_minutes=30),
                "networks": self._generate_network_details(curr)
            })
        return methods

    def _generate_network_details(self, currency):
        networks = {}
        for net in RAIL_MAPPING[currency]:
            net_type = NETWORK_DEFINITIONS.get(net, "banking")

            if net_type == "evm":
                networks[net] = {"address": random.choice(EVM_ADDRESSES)}
            elif net_type == "solana":
                networks[net] = {"address": random.choice(SOLANA_ADDRESSES)}
            elif net_type == "pix":
                key_type = random.choice(["email", "phone", "cpf", "uuid"])
                if key_type == "email":
                    key = "payments@business.com.br"
                elif key_type == "phone":
                    key = "+55119" + "".join([str(random.randint(0, 9)) for _ in range(8)])
                elif key_type == "cpf":
                    key = "".join([str(random.randint(0, 9)) for _ in range(11)])
                else:
                    key = self._generate_uuid_no_dashes()
                networks[net] = {"key": key, "keyType": key_type}
            elif net_type == "zelle":
                key_type = random.choice(["email", "phone"])
                if key_type == "email":
                    key = "customer@example.com"
                else: # phone
                    key = "+1" + "".join([str(random.randint(0, 9)) for _ in range(10)])
                networks[net] = {"key": key, "keyType": key_type}
            else:
                networks[net] = {
                    "routingNumber": str(random.randint(100000000, 999999999)),
                    "accountNumber": str(random.randint(100000000, 9999999999)),
                    "protectionType": random.choice(["tokenized", "encrypted", "plaintext"])
                }
        return networks

# --- 3. THE CHAOS FACTORY (INVALID SAMPLES) ---
class ChaosFactory(X9150DataFactory):
    def generate_invalid_sample(self):
        data = self.generate_sample()
        rule = random.choice([
            self._missing_mcc, self._bad_uuid, self._bad_timestamp,
            self._invalid_protection, self._missing_tip_range, self._invalid_chronology,
            self._missing_id, self._missing_qr_content, self._missing_status,
            self._missing_creditor_name, self._missing_bill_amount, self._missing_currency,
            self._invalid_network_structure
        ])
        return rule(data)

    def _missing_mcc(self, data):
        data["creditor"].pop("MCC", None) # MCC is mandatory
        return data

    def _missing_id(self, data):
        data.pop("id", None)
        return data

    def _missing_qr_content(self, data):
        data.pop("qrCodeContent", None)
        return data

    def _missing_status(self, data):
        data.pop("status", None)
        return data

    def _missing_creditor_name(self, data):
        if "creditor" in data:
            data["creditor"].pop("name", None)
        return data

    def _missing_bill_amount(self, data):
        if "bill" in data and "amountDue" in data["bill"]:
            data["bill"]["amountDue"].pop("amount", None)
        return data

    def _missing_currency(self, data):
        if "bill" in data and "amountDue" in data["bill"]:
            data["bill"]["amountDue"].pop("currency", None)
        return data

    def _invalid_chronology(self, data):
        # Violates: createdAt SHALL be less than or equal to revisedAt
        data["createdAt"] = self._get_timestamp(offset_minutes=10)
        data["revisedAt"] = self._get_timestamp(offset_minutes=0)
        return data

    def _missing_tip_range(self, data):
        data["bill"]["tip"]["allowed"] = True
        data["bill"]["tip"].pop("range", None) # Range is mandatory if allowed is true
        return data

    def _invalid_protection(self, data):
        corrupted = False
        for method in data.get("paymentMethods", []):
            for net in ["FedNow", "RTP", "ACH"]:
                if net in method.get("networks", {}):
                    method["networks"][net]["protectionType"] = "cleartext" # Invalid enum value
                    corrupted = True
        
        if not corrupted:
            # If no suitable network was found to corrupt, inject a new invalid one
            data["paymentMethods"].append({
                "currency": "USD",
                "amount": 100,
                "validUntil": self._get_timestamp(offset_minutes=30),
                "networks": {
                    "ACH": {"routingNumber": "123456789", "accountNumber": "123456789", "protectionType": "cleartext"}
                }
            })

        return data

    def _invalid_network_structure(self, data):
        # Corrupts a network definition by adding fields that don't belong to its type
        # e.g. Adding routingNumber to Pix, or address to Zelle.
        # This tests if the validator catches structural violations that OpenAPI might allow.
        corrupted = False
        for method in data.get("paymentMethods", []):
            networks = method.get("networks", {})
            for net in networks:
                net_type = NETWORK_DEFINITIONS.get(net)
                if net_type == "pix":
                    networks[net]["routingNumber"] = "123456789" # Invalid for Pix
                    corrupted = True
                elif net_type == "evm":
                    networks[net]["routingNumber"] = "123456789" # Invalid for EVM
                    corrupted = True
                elif net_type == "solana":
                    networks[net]["routingNumber"] = "123456789" # Invalid for Solana
                    corrupted = True
                elif net_type == "zelle":
                    networks[net]["address"] = "0x1234567890abcdef" # Invalid for Zelle
                    corrupted = True
                
                if corrupted: break
            if corrupted: break
        
        if not corrupted:
            # If no suitable network found, force inject a bad Pix rail
            if "paymentMethods" in data and len(data["paymentMethods"]) > 0:
                data["paymentMethods"][0]["networks"]["Pix"] = {"key": "123", "keyType": "email", "routingNumber": "999"}

        return data

    def _bad_uuid(self, data):
        data["id"] = str(uuid.uuid4()) # Adds dashes, violating regex
        return data

    def _bad_timestamp(self, data):
        data["createdAt"] = "2026-01-24" # Missing time and milliseconds
        return data

# --- 4. VALIDATION UTILITY ---
class X9150Validator:
    def __init__(self, spec_path):
        if not os.path.exists(spec_path):
            raise FileNotFoundError(f"OpenAPI spec not found at: {spec_path}")
            
        with open(spec_path, 'r') as f:
            self.spec = yaml.safe_load(f)
        # Extract the specific schema and the components for reference resolution
        self.schema = self.spec['components']['schemas']['PaymentRequest']
        self.components = self.spec['components']

    def validate_json(self, data):
        # The validator needs the full components context to resolve $refs
        full_schema = {
            "components": self.components,
            **self.schema
        }
        validate(instance=data, schema=full_schema)
        
        # Custom X9.150 Chronological Validation
        created = data.get("createdAt")
        revised = data.get("revisedAt")
        sent = data.get("sentAt")
        revision = data.get("revision")

        # X9.150 Chronological Rules
        if all([created, revised, sent]):
            # 1. For revision 0, createdAt SHALL equal revisedAt
            if revision == 0 and created != revised:
                raise ValueError(f"X9.150 Violation: For revision 0, createdAt ({created}) must equal revisedAt ({revised})")
            
            # 2. In all cases, createdAt SHALL be <= revisedAt
            if created > revised:
                raise ValueError(f"X9.150 Violation: createdAt ({created}) cannot be after revisedAt ({revised})")
            
            # 3. In all cases, createdAt SHALL be <= sentAt
            if created > sent:
                raise ValueError(f"X9.150 Violation: createdAt ({created}) cannot be after sentAt ({sent})")
        
        # Custom X9.150 Network Structure Validation
        # OpenAPI often allows additional properties or loose schemas for maps.
        # We must strictly validate that specific rails only contain their allowed fields.
        self._validate_networks(data)

    def _validate_networks(self, data):
        if "paymentMethods" not in data:
            return

        # Allowed fields per network type
        type_fields = {
            "banking": {"routingNumber", "accountNumber", "protectionType"},
            "zelle": {"key", "keyType"},
            "pix": {"key", "keyType"},
            "evm": {"address"},
            "solana": {"address"}
        }

        for pm in data.get("paymentMethods", []):
            networks = pm.get("networks", {})
            for net_name, net_data in networks.items():
                if net_name not in NETWORK_DEFINITIONS:
                    continue # Skip unknown rails
                
                net_type = NETWORK_DEFINITIONS[net_name]
                allowed = type_fields.get(net_type, set())
                actual = set(net_data.keys())
                
                extra = actual - allowed
                if extra:
                    raise ValueError(f"Network '{net_name}' ({net_type}) contains invalid fields: {extra}. Allowed: {allowed}")
                
                missing = allowed - actual
                if missing:
                    raise ValueError(f"Network '{net_name}' ({net_type}) is missing required fields: {missing}")

# --- 5. THE RUNNER ---
def main():
    parser = argparse.ArgumentParser(description="Generate X9.150 Test Data or Explain Invalid JSONs")
    parser.add_argument("--explain", help="Path to a JSON file to validate and explain errors", metavar="FILE")
    parser.add_argument("--generate", type=int, help="Number of files to generate", metavar="NUMBER")
    parser.add_argument("--testOpenApi", action="store_true", help="Validate test data against OpenAPI spec only")
    args = parser.parse_args()

    # Calculate path relative to this script: ./spec/openapi.yaml
    base_dir = os.path.dirname(os.path.abspath(__file__))
    spec_path = os.path.join(base_dir, "spec", "openapi.yaml")
    validator = X9150Validator(spec_path)

    if args.explain:
        if not os.path.exists(args.explain):
            print(f"Error: File '{args.explain}' not found.")
            return
        try:
            with open(args.explain, 'r') as f:
                data = json.load(f)
            validator.validate_json(data)
            print("JSON is valid")
        except Exception as e:
            print(f"JSON is invalid: {getattr(e, 'message', str(e))}")
        return

    if args.testOpenApi:
        print(f"Validating against OpenAPI Spec: {spec_path}")
        print("Only structural/schema validation is applied (no custom business rules).\n")

        full_schema = {
            "components": validator.components,
            **validator.schema
        }

        stats = {
            "valid_total": 0,
            "valid_passed": 0,
            "invalid_total": 0,
            "invalid_caught": 0
        }

        # 1. Test Valid Files
        valid_dir = os.path.join(base_dir, "test_data", "valid")
        if os.path.exists(valid_dir):
            files = sorted([f for f in os.listdir(valid_dir) if f.endswith(".json")])
            stats["valid_total"] = len(files)
            for filename in files:
                filepath = os.path.join(valid_dir, filename)
                with open(filepath, 'r') as f:
                    data = json.load(f)
                try:
                    validate(instance=data, schema=full_schema)
                    stats["valid_passed"] += 1
                except Exception as e:
                    print(f"[Valid Fail] {filename}: {getattr(e, 'message', str(e))}")

        # 2. Test Invalid Files
        invalid_dir = os.path.join(base_dir, "test_data", "invalid")
        if os.path.exists(invalid_dir):
            files = sorted([f for f in os.listdir(invalid_dir) if f.endswith(".json")])
            stats["invalid_total"] = len(files)
            for filename in files:
                filepath = os.path.join(invalid_dir, filename)
                with open(filepath, 'r') as f:
                    data = json.load(f)
                try:
                    validate(instance=data, schema=full_schema)
                    # It passed OpenAPI (False Negative)
                    print(f"[Invalid Pass] {filename}: Schema accepted invalid data.")
                    
                    # Explain why it should have failed (using full validator)
                    try:
                        validator.validate_json(data)
                        print(f"   -> Warning: Full validator also accepted it! (Generator issue?)")
                    except Exception as e:
                        print(f"   -> Reason: {getattr(e, 'message', str(e))}")
                        
                except Exception:
                    stats["invalid_caught"] += 1

        # 3. Report
        print("\n" + "="*40)
        print("VALIDATION ACCURACY REPORT")
        print("="*40)
        
        v_rate = (stats["valid_passed"] / stats["valid_total"] * 100) if stats["valid_total"] > 0 else 0
        i_rate = (stats["invalid_caught"] / stats["invalid_total"] * 100) if stats["invalid_total"] > 0 else 0
        
        print(f"Valid Data:   {stats['valid_passed']}/{stats['valid_total']} passed ({v_rate:.1f}%)")
        print(f"Invalid Data: {stats['invalid_caught']}/{stats['invalid_total']} caught ({i_rate:.1f}%)")
        
        total_files = stats["valid_total"] + stats["invalid_total"]
        total_correct = stats["valid_passed"] + stats["invalid_caught"]
        overall = (total_correct / total_files * 100) if total_files > 0 else 0
        
        print("-" * 40)
        print(f"Overall Accuracy: {overall:.2f}%")
        print("="*40)
        return

    if args.generate:
        # Setup directories
        for folder in ["valid", "invalid"]:
            os.makedirs(os.path.join(base_dir, "test_data", folder), exist_ok=True)

        valid_gen = X9150DataFactory()
        invalid_gen = ChaosFactory()

        print(f"Generating {args.generate} samples...")
        for i in range(args.generate):
            # 80% Valid, 20% Invalid
            is_invalid = random.random() < 0.2
            if is_invalid:
                sample = invalid_gen.generate_invalid_sample()
                filename = os.path.join(base_dir, "test_data", "invalid", f"invalid_sample_{i}.json")
                try:
                    validator.validate_json(sample)
                    print(f"Warning: Invalid sample {i} unexpectedly PASSED validation.")
                except Exception:
                    # Expected behavior for invalid samples
                    pass
            else:
                sample = valid_gen.generate_sample(force_indirect=(i % 2 == 0))
                filename = os.path.join(base_dir, "test_data", "valid", f"valid_sample_{i}.json")
                try:
                    validator.validate_json(sample)
                except Exception as e:
                    print(f"Error: Valid sample {i} FAILED validation: {getattr(e, 'message', str(e))}")
                    continue

            with open(filename, "w") as f:
                json.dump(sample, f, indent=2) #

        print("Done! Check the 'test_data/' directory.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
