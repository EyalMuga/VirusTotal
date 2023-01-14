# VirusTotal program for scanning URL(s)
A command-line script for checking the reputation of one or more URLs using VirusTotal's API.

# Prerequisites
Python 3\
VirusTotal API key Get one from https://www.virustotal.com/
# Installing
Clone the repository
```bash
The script can be run using the following command:
python main.py url1 url2 ... -k YOUR_API_KEY -s -q -v -a AGE
where url1, url2, ... are one or more URLs to check, YOUR_API_KEY is your VirusTotal API key, -s, -q, -v, -a are optional arguments.
```

# Arguments
```bash
-k, --apikey : a required argument that accepts a custom VT API key.
-s, --scan : an optional argument that forces a scan of the provided URLs if set.
-q, --quota : an optional argument that enables verbose wait in case of quota insufficiency.
-v, --verbose : an optional argument that enables verbose prints throughout the process if set.
-a, --age : an optional argument that accepts a value for cache max age in days, default = 30.
  ```

# Deployment
This script can be integrated into other projects for URL reputation checking using VirusTotal's API.

# Built With
Python - Programming language\
VirusTotal API - URL Reputation Checking Service

# Acknowledgments
Inspiration from VirusTotal's API documentation\
**Please note that you need to get an API key from the VirusTotal website in order to use this script**

# Example from my Terminal
with Terminal open main.py
it should look like this:
```bash

MUGA@Mugas-MacBook-Pro VirusTotal % python3 Main.py https://amazon.com https://facebook.com https://edulabs.co.il -k 44365dc50db5719a5a1d0e**********04b05330ed135a52bb7a5563b9605ac7
Url 1: https://amazon.com has been analyzed on 08-01-2023, result: harmless, accuracy: 87.78%, source:cache
Url 2: https://facebook.com has been analyzed on 08-01-2023, result: harmless, accuracy: 88.89%, source:cache
Url 3: https://edulabs.co.il has been analyzed on 13-01-2023, result: harmless, accuracy: 85.56%, source:api

```
In this example I used one URL that hasnt been in the cache and two more URL's I already scanned.
As you can see the source of the analysis for the third Url is from the api and the first two url's from the cache.



