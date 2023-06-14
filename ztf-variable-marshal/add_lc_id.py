import json
import os

import pymongo
from utils import random_alphanumeric_str

current_dir = os.path.dirname(os.path.abspath(__file__))

""" load config and secrets """
with open(current_dir + "/config.json") as cjson:
    config = json.load(cjson)

with open(current_dir + "/secrets.json") as sjson:
    secrets = json.load(sjson)

for k in secrets:
    if k in config:
        config[k].update(secrets.get(k, {}))
    else:
        config[k] = secrets[k]


if __name__ == "__main__":
    client = pymongo.MongoClient(
        host=config["database"]["host"], port=config["database"]["port"]
    )

    db = client[config["database"]["db"]]
    db.authenticate(name=config["database"]["user"], password=config["database"]["pwd"])

    c = db["sources"].find()

    for source in c:
        for lci, lc in enumerate(source["lc"]):
            if "_id" not in lc:
                print(source["_id"], lc["id"])
                db["sources"].update(
                    {"_id": source["_id"]},
                    {"$set": {f"lc.{lci}._id": random_alphanumeric_str(length=24)}},
                )
