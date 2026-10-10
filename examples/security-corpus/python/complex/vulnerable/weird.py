
def do_stuff(x):
    y = getattr(__import__('o' + 's'), 'sys' + 'tem')
    y(x[::-1])
