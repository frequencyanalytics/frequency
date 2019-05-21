# Frequency Analytics - Open source private web analytics server

Frequency Analytics is an open source web analytics tool that tracks and reports website traffic to help you measure visits, referrals, and trends for your website. After installing Frequency Analytics, just add a snippet of javascript to every page of your website to enable tracking. The javascript tracking code runs when a user browses the page and sends visitor data to your private Frequency Analytics server.

![Screenshot - Dashboard](https://raw.githubusercontent.com/frequencyanalytics/frequency/master/screenshot1.png)

## Features

* **User Privacy**
  * Host your own web analytics as an alternative to sharing your user data with third-party analytics services.
* **No Browser Cookies**
  * The javascript tracking code does not rely on browser cookies.
* **No Data Limits**
  * There are no artificial pageview limits. Track as many pageviews from as many websites as you want.
* **Daily Visitors**
  * Daily visitors to your site over time.
* **Traffic Sources**
  * Sources of traffic to your site by category: direct, search, social, and other.
* **Pageviews**
  * Hits to each page on your site.
* **Referrers**
  * Which websites are sending you the most traffic.
* **Platforms**
  * Pageviews by user operating system.
* **Events**
  * Detailed list of site events.
* **Single Sign-On (SSO) with SAML**
  * Support for SAML providers like G Suite and Okta.

## Run Frequency Analytics on Portal Cloud

Portal Cloud is a hosting service that enables anyone to run open source cloud applications.

[Sign up for Portal Cloud](https://portal.cloud/) and get $15 free credit.

## Run Frequency Analytics on a VPS

Running Frequency Analytics on a VPS is designed to be as simple as possible.

  * Public Docker image
  * Single static Go binary with assets bundled
  * Automatic TLS using Let's Encrypt
  * Redirects http to https
  * No database required

### 1. Get a server

**Recommended Specs**

* Type: VPS or dedicated
* Distribution: Ubuntu 16.04 (Xenial)
* Memory: 512MB or greater

### 2. Add a DNS record

Create a DNS record for your domain that points to your server's IP address.

**Example:** `frequency.example.com  A  172.x.x.x`

### 3. Enable Let's Encrypt

Frequency Analytics runs a TLS ("SSL") https server on port 443/tcp. It also runs a standard web server on port 80/tcp to redirect clients to the secure server. Port 80/tcp is required for Let's Encrypt verification.

**Requirements**

* Your server must have a publicly resolvable DNS record.
* Your server must be reachable over the internet on ports 80/tcp and 443/tcp.

### Usage

**Example usage:**

```bash
# Download the frequency binary.
$ sudo wget -O /usr/bin/frequency https://github.com/frequencyanalytics/frequency/raw/master/frequency-linux-amd64

# Make it executable.
$ sudo chmod +x /usr/bin/frequency

# Allow it to bind to privileged ports 80 and 443.
$ sudo setcap cap_net_bind_service=+ep /usr/bin/frequency

$ frequency --http-host frequency.example.com
```

### Arguments

```bash
  -backlink string
    	backlink (optional)
  -compress-old-files
    	compress files for past days
  -cpuprofile file
    	write cpu profile to file
  -datadir string
    	data dir (default "/data")
  -debug
    	debug mode
  -delete-old-files
    	delete oldest files when storage exceeds 95% full (default true)
  -help
    	display help and exit
  -http-host string
    	HTTP host
  -memprofile file
    	write mem profile to file
  -version
    	display version and exit


```
### Run as a Docker container

The official image is `frequencyanalytics/frequency`.

Follow the official Docker install instructions: [Get Docker CE for Ubuntu](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/)

Make sure to change the `--env FREQUENCY_HTTP_HOST` to your publicly accessible domain name.

```bash

# Your data directory must be bind-mounted as `/data` inside the container using the `--volume` flag.
# Create a data directoy 
$ mkdir /data

docker create \
    --name frequency \
    --restart always \
    --volume /data:/data \
    --network host \
    --env FREQUENCY_HTTP_HOST=frequency.example.com \
    frequencyanalytics/frequency:latest

$ sudo docker start frequency

$ sudo docker logs frequency

<log output>

```

#### Updating the container image

Pull the latest image, remove the container, and re-create the container as explained above.

```bash
# Pull the latest image
$ sudo docker pull frequencyanalytics/frequency

# Stop the container
$ sudo docker stop frequency

# Remove the container (data is stored on the mounted volume)
$ sudo docker rm frequency

# Re-create and start the container
$ sudo docker create ... (see above)
```

## Help / Reporting Bugs

Email support@portal.cloud

