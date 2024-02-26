# Public DNS Detector

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/eltorio/publicdns-detector/multiarch.yaml)
![GitHub last commit](https://img.shields.io/github/last-commit/eltorio/publicdns-detector)
![Docker Pulls](https://img.shields.io/docker/pulls/eltorio/publicdns-detector)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/eltorio/publicdns-detector)
![GitHub Release Date](https://img.shields.io/github/release-date/eltorio/publicdns-detector)

**Public DNS Detector** is a lightweight utility designed to identify the DNS servers used by clients visiting a website. It helps distinguish between major DNS providers (such as Cloudflare and Google) and other autonomous servers that directly emit resolution requests.

## How It Works

1. **DNS Query**: When a client's browser requests the object JSON from the URL `https://uuid.dnsdetector.zone.tld/dnsdetector`, the script initiates a DNS query for the subdomain `uuid.dnsdetector.zone.tld`.

2. **Server Response**:
    - On port 53 (DNS), the program responds to A or AAAA queries for `uuid.dnsdetector.zone.tld` with the IPv4 or IPv6 address of the Public DNS Detector server. The Time-to-Live (TTL) for this response is set to 60 seconds.
    - Simultaneously, the program records the IP address of the DNS client that made the request.

3. **JSON Object Retrieval**:
    - With the resolved IP address for `uuid.dnsdetector.zone.tld`, the client's browser can retrieve the JSON object from `https://uuid.dnsdetector.zone.tld/dnsdetector`.
    - The JSON object contains information about the DNS server used by the client, represented as: `{"server": "client DNS IP address"}`.

## Features

- Detects major DNS providers (e.g., Cloudflare, Google) vs. autonomous servers.
- Lightweight and efficient.
- Easy integration into web applications.

## Usage

1. Deploy the Public DNS Detector server (listening on ports 53 and 80 behind an HTTPS proxy).
2. Configure the DNS record for `dnsdetector.zone.tld` to point to your server's IP address.
3. Implement the client-side script to query `uuid.dnsdetector.zone.tld` and retrieve the JSON object.

## Configuration

You can configure the Public DNS Detector server using command line arguments or environment variables. If both are provided, the environment variables will take precedence.

Here are the options you can set:

- `serverAddr`: The default address for the DNS server. Set with `-serverAddr` or the `SERVER_ADDR` environment variable.
- `serverAddrIPv6`: The default IPv6 address for the DNS server. Set with `-serverAddrIPv6` or the `SERVER_ADDR_IPV6` environment variable.
- `ttl`: The default TTL for the DNS records. Set with `-ttl` or the `TTL` environment variable.
- `httpAddr`: The default address for the HTTP server. Set with `-httpAddr` or the `HTTP_ADDR` environment variable.
- `httpPort`: The default port for the HTTP server. Set with `-httpPort` or the `HTTP_PORT` environment variable.
- `dnsAddr`: The default address for the DNS server. Set with `-dnsAddr` or the `DNS_ADDR` environment variable.
- `dnsPort`: The default port for the DNS server. Set with `-dnsPort` or the `DNS_PORT` environment variable.
- `zone`: The default zone for the DNS server. Set with `-zone` or the `ZONE` environment variable.
- `templateLocation`: The default location for the templates. Set with `-templateLocation` or the `TEMPLATE_LOCATION` environment variable.
- `maxRequestsPerSecond`: The maximum number of requests per second. Set with `-maxRequestsPerSecond` or the `MAX_REQUESTS_PER_SECOND` environment variable.
- `burstSize`: The maximum number of requests in a burst. Set with `-burstSize` or the `BURST_SIZE` environment variable.
You can display the help message with the `-help` command line argument.

For example, to start the server with a custom HTTP port and TTL, you could use:

```bash
./public-dnsdetector -httpPort 8080 -ttl 300
```

## Installation

1. Clone this repository:

```bash
git clone https://github.com/eltorio/public-dnsdetector.git
```

2. Set up your server environment (ensure ports 53 and 80 are accessible).

3. Customize the configuration as needed.

## Metrics

Our application exposes two metrics for monitoring:

### publicdns_detector_unique_ips_total

`publicdns_detector_unique_ips_total` is a metric that counts the total number of unique IP addresses that have made requests to our application. This metric can be useful for monitoring the diversity of clients that are using our service.

### publicdns_detector_requests_total

`publicdns_detector_requests_total` is a metric that counts the total number of requests received by our application. This metric can be useful for monitoring the volume of traffic that our service is receiving.

## Using the Metrics

These metrics are exposed at the `/metrics` endpoint of our application and are in a format compatible with Prometheus. Therefore, you can use them with any monitoring tool that supports Prometheus.

For example, to scrape these metrics with Prometheus, you can add the following to your Prometheus configuration:

```yaml
scrape_configs:
    - job_name: 'publicdns_dector'
        static_configs:
            - targets: ['<publicdns_detector_host>:<publicdns_detector_port>']
```

## Docker Deployment

Our application is available as a Docker image hosted at `docker.io` with the tag `eltorio/publicdns-detector:latest`.

To run the Docker image, you need to have Docker installed on your machine. Once Docker is installed, you can use the following command to run the image:

```bash
docker run -p 53:53/udp -p 80:80 eltorio/publicdns-detector:latest
```

## License

This project is licensed under the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE.md) file for details.

---

Feel free to modify and expand upon this template to provide additional details specific to your project. Good luck with your **Public DNS Detector**! 🚀
