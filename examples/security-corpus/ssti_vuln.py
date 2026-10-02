from flask import render_template_string
from jinja2 import Template
def render(user_input):
    render_template_string(user_input)
    Template(user_input).render()
