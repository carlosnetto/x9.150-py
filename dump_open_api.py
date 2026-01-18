#!/usr/bin/env python3
import yaml
import csv
import os
import argparse

def resolve_ref(spec, ref):
    """Resolves internal JSON pointers within the spec."""
    if not ref.startswith('#'):
        return {} 
    parts = ref.split('/')
    curr = spec
    for p in parts[1:]:
        curr = curr.get(p, {})
    return curr

def get_info(schema, spec):
    """Extracts display type, the actual schema object, pattern, and array status."""
    if "$ref" in schema:
        ref = schema["$ref"]
        name = ref.split("/")[-1]
        resolved = resolve_ref(spec, ref)
        pattern = resolved.get("pattern", "")
        is_array = "Yes" if resolved.get("type") == "array" else "No"
        return name, resolved, pattern, is_array
    
    t = schema.get("type", "string")
    return t, schema, schema.get("pattern", ""), ("Yes" if t == "array" else "No")

def walk(schema, spec, path, mandatory, rows, seen=None):
    """Recursively traverses the schema to flatten the structure."""
    if seen is None: seen = set()
    
    t_name, actual, pattern, is_array = get_info(schema, spec)
    
    # Prevent infinite recursion for circular refs
    if "$ref" in schema:
        if t_name in seen: return
        seen.add(t_name)

    # Process properties if the schema is an object
    if actual.get("type") == "object":
        props = actual.get("properties", {})
        reqs = actual.get("required", [])
        for k, v in props.items():
            m = "Yes" if k in reqs else "No"
            p_path = f"{path}.{k}"
            p_t_name, p_actual, p_pattern, p_is_array = get_info(v, spec)
            
            # Extract constraints
            p_min_len = p_actual.get("minLength", "")
            p_max_len = p_actual.get("maxLength", "")
            p_min_val = p_actual.get("minimum", "")
            p_max_val = p_actual.get("maximum", "")

            rows.append([p_path, m, p_t_name, p_pattern, p_is_array, p_min_len, p_max_len, p_min_val, p_max_val])
            walk(v, spec, p_path, m, rows, seen.copy())

    # Handle polymorphic structures (like Address)
    if "oneOf" in actual:
        for opt in actual["oneOf"]:
            walk(opt, spec, path, mandatory, rows, seen.copy())

    # Handle arrays
    if actual.get("type") == "array":
        items = actual.get("items", {})
        i_path = f"{path}[]"
        i_t_name, i_actual, i_pattern, i_is_array = get_info(items, spec)
        # If items are primitives, add a row to show constraints (e.g. for presets)
        if i_actual.get("type") != "object":
            rows.append([i_path, "No", i_t_name, i_pattern, i_is_array, i_actual.get("minLength", ""), i_actual.get("maxLength", ""), i_actual.get("minimum", ""), i_actual.get("maximum", "")])
        walk(items, spec, i_path, "No", rows, seen.copy())

def main():
    parser = argparse.ArgumentParser(description="Flatten OpenAPI definition to CSV for X9.150 validation.")
    parser.add_argument("openapi_file", help="Path to the openapi.yaml file")
    args = parser.parse_args()

    if not os.path.exists(args.openapi_file):
        print(f"Error: {args.openapi_file} not found.")
        return

    with open(args.openapi_file, 'r') as f:
        spec = yaml.safe_load(f)

    rows = []
    # Entry points for both APIs (Fetch and Notification)
    api_payloads = [
        ("Fetch Request (JWS Payload)", "FetchRequestPayload"),
        ("Fetch Response (JWS Payload)", "PaymentRequest"),
        ("Notification Request (JWS Payload)", "NotificationPayload"),
        ("Notification Response (JWS Payload)", "SignedStatusCodePayload")
    ]

    for label, schema_name in api_payloads:
        rows.append([f"::: {label} :::", "", "", "", "", "", "", "", ""])
        schema = {"$ref": f"#/components/schemas/{schema_name}"}
        walk(schema, spec, "$", "Yes", rows)
        rows.append([]) 

    output_file = "openapi_flattened.csv"
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["JSON Path", "Mandatory", "Type", "Regexp", "Array", "Min Length", "Max Length", "Min Value", "Max Value"])
        writer.writerows(rows)

    print(f"Flattened OpenAPI definition exported to {output_file}")

if __name__ == "__main__":
    main()