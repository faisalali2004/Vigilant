import html

def is_raw_reflection(content, token):
    encoded = html.escape(token)
    if token in content and encoded == token:
        return True
    return token in content
