# Generator

HTTP traffic generator

## Summary

This is very simple HTTP traffic generator that can be used to request HTTP URL(s) at the specific rate, either directly or through an HTTP proxy server. The main part of this project is HTTPgen.py in Generator directory that does the actual job and dumps the statistics to a text file which can be then parsed by the simple JavaScript based HTML page to generate a nice graph (see WebStats section bellow).

It was originally written for FortiGate Explicit Proxy labs on Fortinet Xperts Academy 2018 conference.

## Features

* List of URLs to retrieve in random fashion.
* List of source IP addresses to randomly initiate connections from.
* Ability to reduce the number of source IPs after specific time.
* Ability to dedicate URL to be downloaded from one specific source IP address.
* Configure timeouts for successfull connection, partial and full response.
* Cache the DNS/IP mapping (for direct connections).
* Statistics (configured rate, successfull rate, timeouts, invalid responses and other errors) can be written to specific file as chosen interval.

## Not supported at this moment

* IPv6
* HTTPs (basically nothing else than simple HTTP requests is supported)

## Usage

```
$ ./HTTPgen.py -h
usage: HTTPgen.py [-h] [--urls URLS] [--ips IPS] [--proxy PROXY]
                  [--ctimeout CTIMEOUT] [--rtimeout RTIMEOUT]
                  [--stimeout STIMEOUT] --reqs REQS [--stats STATS]
                  [--reduce REDUCE] [--reserve RESERVE] [--cachedns] [--debug]

HTTP traffic generator

optional arguments:
  -h, --help           show this help message and exit
  --urls URLS          File with the URLs (default /etc/httpgen/urls)
  --ips IPS            File with the source IP addresses (default
                       /etc/httpgen/ips)
  --proxy PROXY        Proxy server in IP:port format
  --ctimeout CTIMEOUT  Connect timeout
  --rtimeout RTIMEOUT  Timeout for each read
  --stimeout STIMEOUT  Session timeout
  --reqs REQS          Requests per second
  --stats STATS        Statistics output in format filename:interval
  --reduce REDUCE      Reduce the number of source IPs, format seconds:count
  --reserve RESERVE    Reserve the IP address for specific URL, format IP:URL
  --cachedns           Remember IP for hostnames (no TTL check)
  --debug              Enable debugging (do not use for production)
```

## Examples

All examples expect following two files to exist and contain some data. You can change the location of these files is --urls and --ips parameters.

### /etc/httpgen/ips

Contains the source IP addresses to use. Those must already be configured on some interface.

```
10.29.0.11
10.29.0.12
10.29.0.13
10.29.0.14
10.29.0.15
10.29.0.16
```

### /etc/httpgen/urls

Contains the URLs to retrieve. If the --reserve feature is used, that URL must not be listed in this file.

Be careful when using 3rd party servers, because the program can add significant load to them. If you don't own these servers, please add a DNAT rule in your lab to redirect the traffic to a local HTTP server.

```
http://www.bbc.co.uk/
http://www.cnn.com/
http://www.fortinet.com/
```

### Examples

```
./HTTPgen.py --proxy 10.29.0.1:8080 --reqs 50 --stats /dev/stdout:5 --ctimeout 2 --rtimeout 2 --stimeout 3
```

This generates the requests at the rate of 50 per seconds. All URLs are retrieved through the HTTP proxy server listening at 10.29.0.1 and port 8080. Connection timeout is 2 seconds, expects some data to be recieved at list in 2 seconds interval and the whole site must be downloaded and closed in 3 seconds.

```
./HTTPgen.py --reqs 50 --stats /var/www/webstats/data.txt:5 --ctimeout 2 --rtimeout 2 --stimeout 3 --cachedns
```

This is similar to the one above but connecting directly to the remote hosts w/o any proxy. Also it writes the statistics to the data.txt file.

The --cachedns option is not mandatory, but without it the generator will use the system configured DNS resolver to translate the hostname to IP every time it makes a request, i.e. 50 times per second in this case, which may seriously harm the performance. With the --cachedns option the hostname is resolved only once and the IP is remembered for the whole time the generator is running (DNS TTL is not honored). 


# WebStats

## Summary

This is a simple JavaScript page using [ChartJS](http://www.chartjs.org/) and [jQuery](https://jquery.com/) libraries.

## Usage 

It should be stored in a directory accesible by your HTTP server. The script will periodically download the data.txt file located in the same directory and update the graph on screen. 

The Generator should be configured to dump the statistics to this file with the --stats parameter.
