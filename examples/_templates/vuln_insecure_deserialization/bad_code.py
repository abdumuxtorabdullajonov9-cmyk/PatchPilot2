import yaml

def load_user_config(file_path):
    with open(file_path) as f:
        return yaml.load(f)