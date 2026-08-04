import json
import os

CONFIG_PATH = os.path.join(
  os.path.dirname(__file__),
  "config.json"
)

def load_settings():
  if not os.path.exists(CONFIG_PATH):
    return {
      "provider": "",
      "api_key": ""
    }

with open(CONFIG_PATH, "r") as f:
  return json.load(f)

def save_settings(provider, api_key):

  data = {
    "provider": provider,
    "api_key": api_key

  }

with open(CONFIG_PATH, "w") as f:
  json.dump(data, f, indent=4)
