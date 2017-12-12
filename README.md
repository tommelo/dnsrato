# dnsrato
A DNS reconnaissance tool

![](https://media.giphy.com/media/xT0xelEsadw9RPhOJa/source.gif)

## About
**dnsrato** is a DNS reconnaissance tool that performs tasks such as:

* Whois Lookup;
* Sub-domain enumeration(brute force) based on a word list file.

This is a Python version(with some extra features) of the first version
written in C by Ricardo Longatto.
The C version can be found at: https://github.com/ricardolongatto/dnsrato

## Installation
```shell
git clone https://github.com/tommelo/dnsrato
cd dnsrato && sudo pip install -r requirements.txt
```

## Dependencies

* [colorama](https://pypi.python.org/pypi/colorama)
* [dicttoxml](https://pypi.python.org/pypi/dicttoxml)
* [futures](https://pypi.python.org/pypi/futures) (Python2.7)
* [socks5](https://pypi.python.org/pypi/socks5)
* [tqdm](https://pypi.python.org/pypi/tqdm)
* [tld](https://pypi.python.org/pypi/tld)
* [python-whois](https://pypi.python.org/pypi/python-whois)


## Usage
Short opt | Long opt | Default | Required | Description
--------- | -------- | ------- | -------- | -----------
-d        | --domain     | None        | Yes     | The domain url
-D        | --dictionary | rato.txt    | No      | The dictionary file
-f        | --format     | txt         | No      | The output format(xml, json or text)
-h        | --help       | None        | No      | Shows the help usage
-o        | --outuput    | stdout      | No      | The output file
-p        | --port       | 80          | No      | The host port
-s        | --sleep      | 0           | No      | The thread sleep time(seconds)
-w        | --workers    | 10          | No      | The number of thread workers
-t        | --timeout    | 4           | No      | The request timeout
-v        | --verbose    | False       | No      | Enables the verbose mode
N/A       | --proxy      | False       | No      | Use proxy
N/A       | --proxy-host | 127.0.0.1   | No      | Proxy host IP
N/A       | --proxy-port | 9150        | No      | Proxy host PORT
N/A       | --ssl        | False       | No      | Enables SSL
N/A       | --version    | None        | No      | Shows the current version

### -d, --domain
The domain url. The following urls are considered valid:
```
http://domain.com
http://www.domain.com
http://subdomain.domain.com
```
Running the script with the domain argument:
```shell
python dnsrato.py -d domain.com
```

### -D, --dictionary
A dictionary file can be used to perform the subdomain brute force recon. The file must contain a list of words with the following format:
```
subdomainone.
subdomaintwo.
```
Running the script with the dictionary argument:
```shell
python dnsrato.py -d domain.com -D /path/to/file.txt
```

### -f, --format
The enumeration result can be sent to the output with the follwing formats:
* text
* json
* xml

Running the script with the output format argument:
```shell
python dnsrato.py -d domain.com -f json > enumeration.json
```

The **text format** will produce the follwing result:
```
Domain: domain.com
Whois Lookup
key: value
...
Subdomain Lookup
subdomainone.domain.com
subdomaintwo.domain.com
...
```

The **json format** will produce the follwing result:
```
{
  "domain": "domain.com",
  "whois": {
    "key": "value"
  }
  "subdomains": [
    "subdomainone.domain.com"
    "subdomaintwo.domain.com"
  ]
}
```


The **xml format** will produce the follwing result:
```
<?xml version="1.0" ?>
<dns>
  <domain>domain.com</domain>
  <whois>
    <key>value</key>
    <key>
      <item>value1</item>
      <item>value2</item>
    </key>
  </whois>
  <subdomains>
    <item>subdomainone.domain.com</item>
    <item>subdomaintwo.domain.com</item>
  </subdomains>
</dns>
```

### -o, --output
The enumeration result can be saved to a file. The default output is the standard output(sys.stdout).


Running the script with the output file argument:
```shell
python dnsrato.py -d domain.com -f xml -o enumeration.xml
```

### -p, --port
The host port to connect. The default port is 80.

Running the script with the port argument:
```shell
python dnsrato.py -d domain.com -p 8080
```

### -s, --sleep
The thread sleep(in seconds). If you don't want to slam the server with too many concurrent requests you may consider using the sleep argument.

Running the script with the sleep argument:
```shell
python dnsrato.py -d domain.com -s 10
```

### -w, --workers
The number of thread workers. The default number of workers is 10.

Running the script with the workers argument:
```shell
python dnsrato.py -d domain.com -w 20
```

### -t, --timeout
The request timeout(in seconds). If you running the script using a proxy you may consider using the timeout argument to increase the request timeout.

Running the script with the timeout argument:
```shell
python dnsrato.py -d domain.com -t 10
```

### -v, --verbose
The verbose. You may consider using the verbose mode to check the working status of the application.

Running the script with the verbose argument:
```shell
python dnsrato.py -d domain.com -v
```

### --proxy
Enables the proxy mode.

Running the script with the proxy argument:
```shell
python dnsrato.py -d domain.com --proxy --proxy-host 127.0.0.1 --proxy-port 8080
```

### --proxy-host
The proxy host. The default proxy host is 127.0.0.1.

Running the script with the proxy host argument:
```shell
python dnsrato.py -d domain.com --proxy --proxy-host 127.0.0.1 --proxy-port 8080
```

### --proxy-port
The proxy port. The default proxy port is 9150.

Running the script with the proxy port argument:
```shell
python dnsrato.py -d domain.com --proxy --proxy-host 127.0.0.1 --proxy-port 8080
```

### --ssl
Enables the SSL mode.

Running the script with the ssl argument:
```shell
python dnsrato.py -d domain.com --ssl -p 443
```


### --version
Shows the current version of the application.

Running the script with the version argument:
```shell
python dnsrato.py --version
```

### -h, --help
Shows the help usage.

Running the script with the help argument:
```shell
python dnsrato.py -h
```

## Piped Input
Currently, only the domain url is accepted as piped input:
```shell
echo domain.com | python dnsrato.py
```

## Piped Output
The enumeration result can also be piped:
```shell
python dnsrato.py -d domain.com | cat
python dnsrato.py -d domain.com -f json > outfile.json
python dnsrato.py -d domain.com -f json | python -m json.tool
python dnsrato.py -d domain.com -f xml | xmllint --format -
```
**Note**: A piped output disables the verbose mode.

## License
This is an open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT).
