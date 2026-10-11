from jinja2 import Environment

def render_page(user_input):
    env = Environment()
    t = env.from_string("Hello {{ user }}")
    return t.render(user=user_input)
