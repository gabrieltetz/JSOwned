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

| Name | Type | Regex |
| :---         |     :---:      |          ---: |
|    |     |    |
|     |       |      |
| Twitter      | Access Token    | [1-9][ 0-9]+-[0-9a-zA-Z]{40}  |
| Twitter	| Access Token | [1-9][ 0-9]+-[0-9a-zA-Z]{40}|	
| Facebook	| Access Token	| EAACEdEose0cBA[0-9A-Za-z]+| 	
| Facebook	| OAuth 2.0	| [A-Za-z0-9]{125}| login/access-tokens/ |
| Instagram	| OAuth 2.0	| [0-9a-fA-F]{7}.[0-9a-fA-F]{32}| 
| Google	| OAuth 2.0 | API Key	| AIza[0-9A-Za-z-_]{35}	| 
| GitHub	| OAuth 2.0	| [0-9a-fA-F]{40}|
| Gmail	| OAuth 2.0	| [0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com| 	
| Foursquare	| Client Key	| [0-9a-zA-Z_][5,31]| 	
| Foursquare	| Secret Key	| R_[0-9a-f]{32}| 	
| Picatic	| API Key	| sk_live_[0-9a-z]{32}| 	
| Stripe	| Standard API Key	| sk_live_(0-9a-zA-Z]{24}| 	
| Stripe	| Restricted API Key	| sk_live_(0-9a-zA-Z]{24}| 	
| Finance	Square	| Access Token	| sqOatp-[0-9A-Za-z-_]{22}| 	
| Finance	Square	| OAuth Secret	| q0csp-[ 0-9A-Za-z-_]{43}| 	
| Finance	| Paypal / Braintree	| Access Token	| access_token,production$[0-9a-z]{161[0-9a,]{32}| 	
| AMS	| Auth Token	| amzn.mws]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}| 	
| Twilio	| API Key  | 55[0-9a-fA-F]{32}| 	
| MailGun	| API Key	| key-[0-9a-zA-Z]{32}| 
| MailChimp	| API Key	| [0-9a-f]{32}-us[0-9]{1,2}| 	
| Slack	| API Key	| xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}| 	
| Amazon Web Services	| Access Key ID	| AKIA[0-9A-Z]{16}| 	
| Amazon Web Services	| Secret Key	| [0-9a-zA-Z/+]{40}| 	
| Google Cloud Platform	| OAuth 2.0	| [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}| 	
| Google Cloud Platform	| API Key	| [A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}| 	
| Heroku	| API Key	| [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}| 	
| Heroku	| OAuth 2.0	| [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}| 
