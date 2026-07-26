import os


def read_input(request):
    return request.args


def run_it(request):
    cmd = read_input(request)
    os.system(cmd)
