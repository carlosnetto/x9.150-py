# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Utility to clean up generated QR codes and payloads.

import os

PAYEE_DB = "payee_db/qrs"
PAYER_DB = "payer_db/qrs"

def get_qr_sets():
    qr_sets = {}

    # Check Payee DB (JSON payloads)
    if os.path.exists(PAYEE_DB):
        for f in os.listdir(PAYEE_DB):
            if f.endswith(".json"):
                txn_id = f[:-5]
                if txn_id not in qr_sets:
                    qr_sets[txn_id] = {'files': []}
                qr_sets[txn_id]['files'].append(os.path.join(PAYEE_DB, f))
                qr_sets[txn_id]['display'] = txn_id # Default display

    # Check Payer DB (TXT and PNG)
    if os.path.exists(PAYER_DB):
        for f in os.listdir(PAYER_DB):
            if f.endswith(".txt") or f.endswith(".png"):
                # Filename format: "{txn_id} - {merchant_name}.{ext}"
                parts = f.split(' - ')
                txn_id = parts[0]
                
                # Handle case where filename might not match expected pattern strictly
                if len(parts) == 1:
                     txn_id = os.path.splitext(f)[0]

                if txn_id not in qr_sets:
                    qr_sets[txn_id] = {'files': []}
                    qr_sets[txn_id]['display'] = os.path.splitext(f)[0]
                
                qr_sets[txn_id]['files'].append(os.path.join(PAYER_DB, f))
                # Update display name if we found a more descriptive one (from payer db)
                if ' - ' in f:
                     qr_sets[txn_id]['display'] = os.path.splitext(f)[0]

    return qr_sets

def main():
    while True:
        qr_sets = get_qr_sets()
        
        if not qr_sets:
            print("\nNo QR codes found in payee_db or payer_db.")
            choice = input("\n(q to quit, Enter to refresh) ").strip()
            if choice.lower() == 'q':
                break
            continue

        # Sort by modification time of the first file in the set (approximate "latest")
        sorted_qrs = []
        for txn_id, data in qr_sets.items():
            mtime = 0
            for fpath in data['files']:
                try:
                    t = os.path.getmtime(fpath)
                    if t > mtime:
                        mtime = t
                except OSError:
                    pass
            sorted_qrs.append({'id': txn_id, 'data': data, 'mtime': mtime})
        
        # Sort descending (newest first)
        sorted_qrs.sort(key=lambda x: x['mtime'], reverse=True)

        print("\nExisting QR Codes:")
        for i, item in enumerate(sorted_qrs, 1):
            print(f"{i}. {item['data'].get('display', item['id'])}")

        choice = input("\nWhich one do you want to delete? (q to quit) ").strip()
        
        if choice.lower() == 'q':
            break
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sorted_qrs):
                selected = sorted_qrs[idx]
                print(f"Deleting {selected['data'].get('display')}...")
                for fpath in selected['data']['files']:
                    try:
                        os.remove(fpath)
                        print(f"  - Deleted {fpath}")
                    except OSError as e:
                        print(f"  ! Failed to delete {fpath}: {e}")
            else:
                print(f"[!] Invalid selection. Please enter a number between 1 and {len(sorted_qrs)}.")
        except ValueError:
            print("[!] Invalid input. Please enter a number.")

if __name__ == "__main__":
    main()