import subprocess

def run_command(user_input):
    subprocess.call("ping " + user_input, shell=True)