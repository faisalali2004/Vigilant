def extract_form_findings(forms):
    findings = []
    for form in forms:
        findings.append({
            "id": None,
            "title": "Form Discovered",
            "category": "Forms",
            "severity": "Info",
            "location": form["page"],
            "description": f"Form found with method={{form['method'].upper()}} action={{form['action']}}",
            "evidence": f"Inputs: {[i['name'] for i in form['inputs'] if i['name']]}",
            "recommendation": "Ensure proper server-side validation and sanitization."
        })
    return findings
