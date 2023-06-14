import json
import os

from cryptography import fernet
from utils import random_alphanumeric_str

current_dir = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    with open(current_dir + "/secrets.json", "r") as sjson:
        secrets = json.load(sjson)

    fernet_key = fernet.Fernet.generate_key().decode()
    aiohttp_secret_key = random_alphanumeric_str(32)
    jwt_secret_key = random_alphanumeric_str(32)

    for key in ("server", "misc"):
        if key not in secrets:
            secrets[key] = dict()

    secrets["server"]["SECRET_KEY"] = aiohttp_secret_key
    secrets["server"]["JWT_SECRET_KEY"] = jwt_secret_key
    secrets["misc"]["fernet_key"] = fernet_key

    # save
    with open(current_dir + "/secrets.json", "w") as sjson:
        json.dump(secrets, sjson, indent=2)
