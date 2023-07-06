# JSOwned


## Install
```
git clone git@github.com:gabrieltetz/JSOwned.git
cd JSOwned
pip3 install -r requirements.txt
python3 JSowned.py crawlingJS.txt regex.txt

```

## Using

```
positional arguments:
  input_path            caminho do arquivo de entrada contendo as URLs
  regex_path            caminho do arquivo de regex

options:
  -h, --help            show this help message and exit
  --output_path OUTPUT_PATH, -o OUTPUT_PATH caminho do arquivo de saída
```
## Exemple 

```
python3 JSOwned.py crawlingJS.txt regex.txt
```

```
python3 JSOwned.py crawlingJS.txt regex.txt -o output.js
```

| Name | Regex |
| :---         |          ---: |
|    |     |    |
|     |       |      |
| google_api      | r'AIza[0-9A-Za-z-_]{35}'   | 
| google_captcha	| r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$' |
| google_oauth	| r'ya29\.[0-9A-Za-z\-_]+'	|
| amazon_aws_access_key_id	| r'A[SK]IA[0-9A-Z]{16}'	|
| amazon_mws_auth_token	| r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'|	
| amazon_aws_url	| r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com' |
| facebook_access_token	| r'EAACEdEose0cBA[0-9A-Za-z]+'|
| authorization_basic	| r'basic\s*[a-zA-Z0-9=:_\+\/-]+'|
| authorization_bearer	| r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+'|
| authorization_api	| r'api[key|\s*]+[a-zA-Z0-9_\-]+'|
| mailgun_api_key	| r'key-[0-9a-zA-Z]{32}'|
| twilio_api_key	| r'SK[0-9a-fA-F]{32}'|
| twilio_account_sid	| r'AC[a-zA-Z0-9_\-]{32}'|
| paypal_braintree_access_token	| r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'|
| square_oauth_secret	| r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}'|
| square_access_token	| r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}'|
| stripe_standard_api	| r'sk_live_[0-9a-zA-Z]{24}'|
| stripe_restricted_api	|r'rk_live_[0-9a-zA-Z]{24}'|
| github_access_token	| r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*'|
| rsa_private_key	| r'-----BEGIN RSA PRIVATE KEY-----'|
| ssh_dsa_private_key	| r'-----BEGIN DSA PRIVATE KEY-----'|
| ssh_dc_private_key	| r'-----BEGIN EC PRIVATE KEY-----'|
| pgp_private_block	| r'-----BEGIN PGP PRIVATE KEY BLOCK-----'|
| json_web_token	| r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'|
