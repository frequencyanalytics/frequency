#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Require variables.
if [ -z "${FREQUENCY_HTTP_HOST-}" ] ; then
    echo "Environment variable FREQUENCY_HTTP_HOST required. Exiting."
    exit 1
fi

# Allow optional variables.
if [ -z "${FREQUENCY_BACKLINK-}" ] ; then
    export FREQUENCY_BACKLINK=""
fi

if [ -z "${FREQUENCY_LETSENCRYPT-}" ] ; then
    export FREQUENCY_LETSENCRYPT="true"
fi

if [ -z "${FREQUENCY_HTTP_ADDR-}" ] ; then
    export FREQUENCY_HTTP_ADDR=":80"
fi

if [ -z "${FREQUENCY_HTTP_INSECURE-}" ] ; then
    export FREQUENCY_HTTP_INSECURE="false"
fi

# geoip service
if ! test -d /etc/sv/geoip ; then
    mkdir /etc/sv/geoip
    cat <<RUNIT >/etc/sv/geoip/run
#!/bin/bash
### set -o errexit
set -o nounset
set -o xtrace
set -o pipefail

cd /tmp

while true ; do
    curl --silent --output GeoLite2-Country.tar.gz https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
    tar xfz GeoLite2-Country.tar.gz
    cp GeoLite2-Country*/GeoLite2-Country.mmdb /data/geoip.tmp
    mv /data/geoip.tmp /data/GeoLite2-Country.mmdb
    rm -rf GeoLite2*

    if test -e /data/GeoLite2-Country.mmdb ; then
        sleep 30d # Update in ~1 month.
    else
        sleep 5m # failed, so try again in five.
    fi
done
RUNIT
    chmod +x /etc/sv/geoip/run

    # geoip service log
    mkdir /etc/sv/geoip/log
    mkdir /etc/sv/geoip/log/main
    cat <<RUNIT >/etc/sv/geoip/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/sv/geoip/log/run
    ln -s /etc/sv/geoip /etc/service/geoip
fi

# frequency service
if ! test -d /etc/sv/frequency ; then
    mkdir /etc/sv/frequency
    cat <<RUNIT >/etc/sv/frequency/run
#!/bin/sh
exec /usr/bin/frequency \
    "--http-host=${FREQUENCY_HTTP_HOST}" \
    "--http-addr=${FREQUENCY_HTTP_ADDR}" \
    "--http-insecure=${FREQUENCY_HTTP_INSECURE}" \
    "--backlink=${FREQUENCY_BACKLINK}" \
    "--letsencrypt=${FREQUENCY_LETSENCRYPT}"
RUNIT
    chmod +x /etc/sv/frequency/run

    # frequency service log
    mkdir /etc/sv/frequency/log
    mkdir /etc/sv/frequency/log/main
    cat <<RUNIT >/etc/sv/frequency/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/sv/frequency/log/run
    ln -s /etc/sv/frequency /etc/service/frequency
fi

exec $@
