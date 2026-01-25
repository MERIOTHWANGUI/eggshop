import requests
from requests.auth import HTTPBasicAuth

ck = "YOUR_CONSUMER_KEY"
cs = "YOUR_CONSUMER_SECRET"

url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

r = requests.get(url, auth=HTTPBasicAuth(ck, cs))
print(r.status_code)
print(r.text)
