def fingerprint_stack(pages):
    if not pages:
        return {}
    first = next(iter(pages.values()))
    headers = first.get("headers", {})
    stack = {}
    for key in ["Server","X-Powered-By","Via","X-AspNet-Version","X-Generator"]:
        if key in headers:
            stack[key] = headers[key]
    content = first.get("content") or ""
    hints = []
    if "wp-content" in content:
        hints.append("WordPress")
    if "Drupal.settings" in content:
        hints.append("Drupal")
    if "content=\"Joomla!" in content:
        hints.append("Joomla")
    if hints:
        stack["HTML-Hints"] = ", ".join(hints)
    return stack
