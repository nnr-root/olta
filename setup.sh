#!/usr/bin/env bash

# make our output look nice...
script_name="olta setup"

function check_privs () {
    if [[ "$(whoami)" != root ]]; then
        print_error "You need root privileges to run this script."
        exit 1
    fi
}

function print_good () {
    echo -e "[${script_name}] \x1B[01;32m[+]\x1B[0m $1"
}

function print_error () {
    echo -e "[${script_name}] \x1B[01;31m[-]\x1B[0m $1"
}

function print_warning () {
    echo -e "[${script_name}] \x1B[01;33m[-]\x1B[0m $1"
}

function print_info () {
    echo -e "[${script_name}] \x1B[01;34m[*]\x1B[0m $1"
}

if [[ $# -ne 5 ]]; then
    print_error "Missing Parameters:"
    print_error "Usage:"
    print_error './setup <root domain> <subdomain(s)> <root domain bool> <feed bool> <rid replacement>'
    print_error " - root domain                     - the root domain to be used for the campaign"
	print_error " - subdomains                      - a space separated list of subdomains to proxy through Olta Proxy, can be one if only one"
	print_error " - root domain bool                - true or false to proxy the root domain through Olta Proxy"
    print_error " - feed bool                       - true or false if you plan to use the live feed"
    print_error " - rid replacement                 - replace the campaign default \"rid\" in phishing URLs with this value"
    print_error "Example:"
    print_error '  ./setup.sh example.com "accounts myaccount" false true user_id'

    exit 2
fi

# Set variables from parameters
root_domain="${1}"
olta_proxy_subs="${2}"
e_root_bool="${3}"
feed_bool="${4}"
rid_replacement="${5}"

# Install needed dependencies
function install_depends () {
    print_info "Installing dependencies with apt"
    apt-get update
    apt-get install build-essential letsencrypt certbot wget git net-tools tmux openssl jq -y
    print_good "Installed dependencies with apt!"
    print_info "Installing Go from source"
    v=$(curl -s https://go.dev/dl/?mode=json | jq -r '.[0].version')
    wget https://go.dev/dl/"${v}".linux-amd64.tar.gz
    tar -C /usr/local -xzf "${v}".linux-amd64.tar.gz
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm "${v}".linux-amd64.tar.gz
    print_good "Installed Go from source!"
}

# Configure and install Olta Proxy
function setup_olta_proxy () {
    # Prepare DNS for Olta Proxy
    olta_proxy_cstring=""
    for esub in ${olta_proxy_subs} ; do
        olta_proxy_cstring+=${esub}.${root_domain}
        olta_proxy_cstring+=" "
    done
    cp /etc/hosts /etc/hosts.bak
    sed -i "s|127.0.0.1.*|127.0.0.1 localhost ${olta_proxy_cstring}${root_domain}|g" /etc/hosts
    cp /etc/resolv.conf /etc/resolv.conf.bak
    rm /etc/resolv.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl stop systemd-resolved
    # Build Olta proxy
    go build -o cmd/olta-proxy/olta-proxy ./cmd/olta-proxy
    print_good "Configured Olta proxy service!"
}

# Configure and install Olta Campaign
function setup_olta_campaign () {
	print_info "Configuring Olta Campaign"
    # Setup live feed if selected
    if [[ $(echo "${feed_bool}" | grep -ci "true") -gt 0 ]]; then
        sed -i "s|\"feed_enabled\": false,|\"feed_enabled\": true,|g" cmd/olta-campaign/config.json
        go build -o cmd/olta-feed/olta-feed ./cmd/olta-feed
        print_good "Live feed configured! cd into cmd/olta-feed then launch binary with ./olta-feed to start!"
    fi
    # Replace rid with user input
    find . -type f -exec sed -i "s|client_id|${rid_replacement}|g" {} \;
    go build -o cmd/olta-campaign/olta-campaign ./cmd/olta-campaign
	print_good "Configured Olta Campaign!"
}

function main () {
    check_privs
    install_depends
    setup_olta_campaign
    setup_olta_proxy
    print_good "Installation complete!"
    print_info "It is recommended to run all servers inside a tmux session to avoid losing them over SSH!"
}

main
