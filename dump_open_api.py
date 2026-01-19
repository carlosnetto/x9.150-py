# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import yaml
import csv
import os
import re
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

def format_field_name(name):
    """Converts camelCase to Space Separated Title Case. e.g. qrCodeContent -> QR Code Content."""
    tag = name.split('.')[-1].replace('[]', '')
    if not tag or tag == '$': return ""
    
    # Split camelCase: qrCodeContent -> qr Code Content
    res = re.sub(r'([a-z])([A-Z])', r'\1 \2', tag)
    
    # Capitalize first letter of each word, with special handling for 'qr'
    words = res.split()
    formatted_words = []
    for w in words:
        if w.lower() == 'qr':
            formatted_words.append('QR')
        else:
            formatted_words.append(w.capitalize())
    return ' '.join(formatted_words)

def extract_max_length(schema):
    """Extracts the maximum length from maxLength or falls back to parsing the regex pattern."""
    # 1. Direct attribute check
    max_len = schema.get("maxLength")
    if max_len is not None:
        return str(max_len)

    # 2. Regex pattern parsing fallback
    pattern = schema.get("pattern")
    if pattern:
        # Find all quantifiers like {n} or {m,n}
        # Group 1 matches {n}, Group 2 matches the 'max' in {min,max}
        matches = re.findall(r'\{(\d+)\}|\{\d+,(\d+)\}', pattern)
        if matches:
            # Sum the maximums of all quantifiers found (e.g. for UUIDs with multiple parts)
            total = sum(int(m[0] or m[1]) for m in matches)
            return str(total) if total > 0 else ""
            
    return ""

def get_info(schema, spec):
    """Extracts the actual schema object, display type, format, description, and example."""
    if not isinstance(schema, dict):
        return {}, "Field", "Any", "", ""
        
    description = schema.get("description", "")
    example = schema.get("example", "")
    actual = schema
    if "$ref" in schema:
        ref = schema["$ref"]
        actual = resolve_ref(spec, ref)
        if not description:
            description = actual.get("description", "")
        if example == "":
            example = actual.get("example", "")
    
    # If type is missing, check combiners (common in polymorphic schemas or description overrides)
    if "type" not in actual:
        for combiner in ["allOf", "anyOf", "oneOf"]:
            if combiner in actual and isinstance(actual[combiner], list) and actual[combiner]:
                # Infer type/format from the first element of the combiner
                sub_actual, sub_type, sub_fmt, sub_desc, sub_ex = get_info(actual[combiner][0], spec)
                return sub_actual, sub_type, sub_fmt, description or sub_desc, example or sub_ex

    t = actual.get("type", "string")
    fmt = actual.get("format", "")
    
    # Map format to requested strings
    fmt_map = {
        "date-time": "UTC Timestamp",
        "uri": "URL",
        "email": "e-mail",
        "int64": "Int64",
        "int32": "Integer"
    }
    
    if t == "integer":
        display_fmt = fmt_map.get(fmt, "Integer")
    elif t == "string":
        display_fmt = fmt_map.get(fmt, "String")
    else:
        display_fmt = t.capitalize()
    
    # Determine Type (Field, Object, Array)
    if t == "object":
        display_type = "Object"
    elif t == "array":
        display_type = "Array"
    else:
        display_type = "Field"
        
    return actual, display_type, display_fmt, description, example

def walk(schema, spec, path, rows, seen=None, is_conditional=False):
    """Recursively traverses the schema to flatten the structure."""
    if seen is None: seen = set()
    
    actual, display_type, display_fmt, description, example = get_info(schema, spec)
    
    if "$ref" in schema:
        t_name = schema["$ref"].split("/")[-1]
        if t_name in seen: return
        seen.add(t_name)

    if not isinstance(actual, dict):
        return

    if actual.get("type") == "object" or "properties" in actual:
        props = actual.get("properties", {})
        reqs = actual.get("required", [])
        for k, v in props.items():
            p_path = f"{path}.{k}"
            p_actual, p_type, p_fmt, p_desc, p_ex = get_info(v, spec)
            
            # Determine Mandatory/Conditional/Optional status
            p_status = "Mandatory" if k in reqs else ("Conditional" if is_conditional else "Optional")
            
            # Extract Length (Max size)
            length_val = extract_max_length(p_actual)

            rows.append([
                format_field_name(k),
                p_status,
                p_type,
                length_val,
                p_fmt,
                p_path,
                p_actual.get("pattern", ""),
                p_desc.replace('\n', ' ').strip(),
                str(p_ex) if p_ex not in [None, ""] else ""
            ])
            walk(v, spec, p_path, rows, seen.copy(), is_conditional)

    for combiner in ["oneOf", "anyOf", "allOf"]:
        if combiner in actual:
            for opt in actual[combiner]:
                walk(opt, spec, path, rows, seen.copy(), is_conditional or (combiner in ["oneOf", "anyOf"]))

    if actual.get("type") == "array":
        items = actual.get("items", {})
        i_path = f"{path}[]"
        i_actual, i_type, i_fmt, i_desc, i_ex = get_info(items, spec)
        
        if i_actual.get("type") != "object":
            length_val = extract_max_length(i_actual)
            
            rows.append([
                format_field_name(path) + " Item",
                "Optional",
                i_type,
                length_val,
                i_fmt,
                i_path,
                i_actual.get("pattern", ""),
                i_desc.replace('\n', ' ').strip(),
                str(i_ex) if i_ex not in [None, ""] else ""
            ])
        walk(items, spec, i_path, rows, seen.copy(), is_conditional)

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
        walk(schema, spec, "$", rows)
        rows.append([]) 

    output_file = "openapi_flattened.csv"
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Field Name", "Mandatory, Conditional, Optional", "Type", "Length", "Format", "JSON Path", "Regexp", "Comment", "Example"])
        writer.writerows(rows)

    print(f"Flattened OpenAPI definition exported to {output_file}")

if __name__ == "__main__":
    main()