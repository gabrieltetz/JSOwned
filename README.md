# JSOwned


## Using
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

