#!/usr/bin/python3

# unicorn path
# if you don't have it check https://github.com/trustedsec/unicorn
# unicorn used to convert powershell agent into vba macro

unicorn_path = "/opt/redteaming/unicorn-3.15/unicorn.py"


basic_http_username = "octopus"
basic_http_password = "e9394cecde3a038a82e922892e45436f" # octopus_password

#assert os.environ.get("OUTWARD_ADDRESS") and os.environ.get("PORT")

conf__port = os.getenv("PORT")
conf__outward_address = os.getenv("OUTWARD_ADDRESS")


conf__aes_key = "".join([random.choice(string.ascii_uppercase) for i in range(32)]) if not os.getenv("AES_KEY") else os.getenv("AES_KEY")
conf__aes_iv = "".join([random.choice(string.ascii_uppercase) for i in range(AES.block_size)]) if not os.getenv("AES_IV") else os.getenv("AES_IV")
