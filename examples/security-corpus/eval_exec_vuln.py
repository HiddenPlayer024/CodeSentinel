def run_code(user_input):
    eval(user_input)
    exec(user_input)
    compile(user_input, '<string>', 'exec')
    __import__(user_input)
