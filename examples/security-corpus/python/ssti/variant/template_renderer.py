from jinja2 import Template

def render_page(user_template_str):
    # Wrapped template string passed to renderer
    t = Template(user_template_str)
    return t.render()
