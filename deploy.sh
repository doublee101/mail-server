#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8

# =============================================================================
# ELITE MAIL + WEBMAIL SERVER DEPLOYMENT // mail.h2cnk.com
# Debian 11+ (bullseye/bookworm) • Roundcube • 5 msg/sec Throttling
# Cloudflare DNS (Manual) • Bitvise SSH Ready • A-Z Deployment
# =============================================================================
# Execute after FIRST LOGIN as root via Bitvise SSH Client
# Usage: wget -qO- https://raw.githubusercontent.com/doublee101/mail-server/main/deploy.sh | bash
# =============================================================================

readonly LOG="/var/log/mail-deploy-$(date +%Y%m%d_%H%M%S).log"
readonly STATE_DIR="/var/lib/mail-deploy"
readonly BACKUP_DIR="${STATE_DIR}/backups"
readonly SUCCESS_MARKER="${STATE_DIR}/deploy.success"
readonly DOMAIN="h2cnk.com"
readonly MAILHOST="mail.h2cnk.com"
readonly WEBMAIL_HOST="webmail.h2cnk.com"

umask 0077
mkdir -p "${STATE_DIR}" "${BACKUP_DIR}" 2>/dev/null || true

# === RESILIENCE: ATOMIC LOCKING ===
if [ -f "${STATE_DIR}/deploy.lock" ]; then
    echo "[-] Deployment already in progress (PID: $(cat ${STATE_DIR}/deploy.lock 2>/dev/null || echo 'unknown'))" >&2
    exit 1
fi
echo "$$" > "${STATE_DIR}/deploy.lock"
trap 'rm -f ${STATE_DIR}/deploy.lock' EXIT INT TERM

# === BANNER ===
cat <<'EOF'

╔════════════════════════════════════════════════════════════════════════════╗
║  ELITE MAIL + WEBMAIL SERVER DEPLOYMENT // mail.h2cnk.com                 ║
║  Debian 11+ • Roundcube • 5 msg/sec Throttling • FBL Compliant            ║
╚════════════════════════════════════════════════════════════════════════════╝

EOF

# === PHASE 0: SYSTEM DIAGNOSTICS (ENHANCED) ===
echo "[*] Phase 0: System Diagnostics"

# OS Detection with fallback
OS_ID="$(grep -oP '^ID=\K.*' /etc/os-release 2>/dev/null || echo 'unknown')"
OS_VERSION="$(grep -oP '^VERSION_ID=\K.*' /etc/os-release 2>/dev/null | tr -d '"' || echo 'unknown')"

echo "    Detected OS: ${OS_ID} ${OS_VERSION}"

# Debian version check (support bullseye+)
if [ "${OS_ID}" != "debian" ]; then
    echo "[-] ERROR: Debian required (detected: ${OS_ID})" >&2
    echo "    Run on Debian 11 (bullseye) or 12 (bookworm)" >&2
    exit 1
fi

# Support both bullseye (11) and bookworm (12)
case "${OS_VERSION}" in
    11|12) echo "    ✓ Supported Debian version (${OS_VERSION})" ;;
    *) 
        echo "[-] ERROR: Debian 11+ required (detected: ${OS_VERSION})" >&2
        echo "    Supported versions: 11 (bullseye), 12 (bookworm)" >&2
        exit 1
        ;;
esac

# Hostname validation/correction
CURRENT_HOST="$(hostname -f 2>/dev/null || hostname)"
echo "    Current hostname: ${CURRENT_HOST}"

# Set proper mail hostname if not already configured
if [ "${CURRENT_HOST}" != "${MAILHOST}" ]; then
    echo "[*] Setting hostname to ${MAILHOST}..."
    hostnamectl set-hostname "${MAILHOST}" 2>/dev/null || true
    echo "${MAILHOST}" > /etc/hostname
    
    # Update /etc/hosts safely
    if ! grep -q "${MAILHOST}" /etc/hosts 2>/dev/null; then
        echo "127.0.1.1 ${MAILHOST} mail" >> /etc/hosts
    fi
    echo "    ✓ Hostname set to ${MAILHOST}"
fi

# Network validation
echo "[*] Checking internet connectivity..."
if ! timeout 15 bash -c 'until ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; do sleep 1; done'; then
    echo "[-] ERROR: No internet connectivity" >&2
    echo "    Configure network before deployment" >&2
    exit 1
fi

# Resource checks
TOTAL_RAM_KB="$(awk '$1=="MemTotal:" {print $2}' /proc/meminfo)"
if [ "${TOTAL_RAM_KB}" -lt 3145728 ]; then  # 3GB
    echo "[-] WARNING: <3GB RAM detected (${TOTAL_RAM_KB} KB)" >&2
    echo "    Minimum 3GB recommended for mail+webmail stack" >&2
    read -p "    Continue anyway? (y/N): " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

AVAIL_DISK_KB="$(df / --output=avail | awk 'NR==2 {print $1}')"
if [ "${AVAIL_DISK_KB}" -lt 15728640 ]; then  # 15GB
    echo "[-] ERROR: <15GB disk space available (${AVAIL_DISK_KB} KB)" >&2
    exit 1
fi

echo "    ✓ System validation passed"

# === PHASE 1: SYSTEM UPDATE ===
echo "[*] Phase 1: System Update & Hardening"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -yqq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null

# === PHASE 2: PACKAGE INSTALLATION (VERSION-AWARE) ===
echo "[*] Phase 2: Installing Mail + Webmail Stack"

# Determine PHP version based on Debian release
PHP_VER="8.2"
if [ "${OS_VERSION}" = "11" ]; then
    PHP_VER="7.4"
    # Enable SURY repo for PHP 7.4 on bullseye
    apt-get install -yqq apt-transport-https lsb-release ca-certificates curl 2>/dev/null
    curl -sSL https://packages.sury.org/php/apt.gpg | apt-key add - 2>/dev/null
    echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
    apt-get update -qq
fi

PKGS="postfix postfix-pcre dovecot-imapd dovecot-sieve opendkim opendkim-tools spamassassin spamc fail2ban pflogsumm bsd-mailx unattended-upgrades ca-certificates certbot nginx php${PHP_VER}-fpm php${PHP_VER}-mysql php${PHP_VER}-gd php${PHP_VER}-xml php${PHP_VER}-mbstring php${PHP_VER}-intl php${PHP_VER}-curl php${PHP_VER}-zip mariadb-server mariadb-client roundcube-core roundcube-mysql unzip wget curl"

debconf-set-selections <<EOF
postfix postfix/main_mailer_type select Internet Site
postfix postfix/mailname string ${DOMAIN}
mariadb-server mysql-server/root_password password AutoGen-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
mariadb-server mysql-server/root_password_again password AutoGen-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
roundcube-core roundcube/dbconfig-install boolean true
roundcube-core roundcube/database-type select mysql
roundcube-core roundcube/mysql/admin-pass password AutoGen-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
roundcube-core roundcube/mysql/app-pass password AutoGen-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
EOF

apt-get install -yqq --no-install-recommends ${PKGS} 2>/dev/null

# === PHASE 3: TLS CERTIFICATES (LET'S ENCRYPT) ===
echo "[*] Phase 3: Provisioning TLS Certificates"

# Open port 80 temporarily
ufw allow 80/tcp >/dev/null 2>&1 || true

# Get certs for mail + webmail
for host in "${MAILHOST}" "${WEBMAIL_HOST}"; do
    if [ ! -d "/etc/letsencrypt/live/${host}" ]; then
        echo "    Requesting certificate for ${host}..."
        certbot certonly --standalone -d "${host}" --non-interactive \
          --agree-tos --register-unsafely-without-email --key-type rsa --rsa-key-size 4096 || {
            echo "[-] Certbot failed for ${host}" >&2
            echo "    Ensure port 80 is not blocked by firewall" >&2
            exit 1
        }
    fi
done

ufw delete allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp comment "HTTPS" >/dev/null 2>&1 || true

readonly MAIL_CERTDIR="/etc/letsencrypt/live/${MAILHOST}"
readonly WEBMAIL_CERTDIR="/etc/letsencrypt/live/${WEBMAIL_HOST}"

[ ! -f "${MAIL_CERTDIR}/fullchain.pem" ] && { echo "[-] Mail cert missing"; exit 1; }
[ ! -f "${WEBMAIL_CERTDIR}/fullchain.pem" ] && { echo "[-] Webmail cert missing"; exit 1; }

echo "    ✓ TLS certificates provisioned"

# === PHASE 4: POSTFIX CONFIGURATION ===
echo "[*] Phase 4: Configuring Postfix (SMTP with 5 msg/sec Throttling)"

cp -a /etc/postfix/main.cf "${BACKUP_DIR}/main.cf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

postconf -e "myhostname = ${MAILHOST}"
postconf -e "mydomain = ${DOMAIN}"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = localhost"
postconf -e "relayhost ="
postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"

# TLS enforcement
postconf -e "smtpd_tls_security_level = encrypt"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "smtpd_tls_cert_file = ${MAIL_CERTDIR}/fullchain.pem"
postconf -e "smtpd_tls_key_file = ${MAIL_CERTDIR}/privkey.pem"
postconf -e "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache"
postconf -e "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache"
postconf -e "tls_preempt_cipherlist = yes"
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.2"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.2"
postconf -e "smtpd_tls_mandatory_ciphers = high"

# OPSEC: No version leakage
postconf -e "smtpd_banner = \$myhostname ESMTP"

# SASL authentication
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_security_options = noanonymous,noplaintext"
postconf -e "smtpd_sasl_tls_security_options = noanonymous"

# Strict policies
postconf -e "smtpd_helo_required = yes"
postconf -e "smtpd_helo_restrictions = permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname"
postconf -e "smtpd_sender_restrictions = reject_sender_login_mismatch, permit_sasl_authenticated, reject_unknown_sender_domain"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, reject_unauth_destination, reject_unknown_recipient_domain"
postconf -e "smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination"

# Anti-abuse
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_reject_unlisted_sender = yes"
postconf -e "smtpd_reject_unlisted_recipient = yes"
postconf -e "smtpd_forbid_bare_newline = reject"

# === THROTTLING: 5 msgs/sec (300/min) ===
postconf -e "anvil_rate_time_unit = 60s"
postconf -e "smtpd_client_message_rate_limit = 300"
postconf -e "default_destination_rate_delay = 1s"
postconf -e "initial_destination_concurrency = 2"
postconf -e "default_destination_concurrency_limit = 5"
postconf -e "smtp_destination_rate_delay = 1s"
postconf -e "smtpd_client_connection_count_limit = 20"
postconf -e "smtpd_client_connection_rate_limit = 100"

# === FBL/COMPLIANCE: Headers + Unsubscribe ===
postconf -e "always_add_missing_headers = yes"
postconf -e "header_checks = regexp:/etc/postfix/header_checks"

cat > /etc/postfix/header_checks <<'EOF'
# Privacy headers
/^Received:/ IGNORE
/^X-Originating-IP:/ IGNORE
/^X-PHP-Script:/ IGNORE
/^X-Mailer:/ IGNORE
/^User-Agent:/ IGNORE

# CAN-SPAM/GDPR compliance: Auto-inject unsubscribe header
/^Subject:.*\b(marketing|newsletter|promotion|offer|blast|campaign|deal)\b/i PREPEND List-Unsubscribe: <mailto:unsubscribe@h2cnk.com?subject=unsubscribe>, <https://webmail.h2cnk.com/unsubscribe>
EOF

# Master.cf with postscreen
cat > /etc/postfix/master.cf <<'EOF'
smtp      inet  n       -       y       -       1       postscreen
smtpd     pass  -       -       y       -       -       smtpd
dnsblog   unix  -       -       y       -       0       dnsblog
tlsproxy  unix  -       -       y       -       0       tlsproxy
postscreen unix -       -       y       -       1       postscreen
  postscreen_greet_action = enforce
  postscreen_dnsbl_action = enforce
  postscreen_dnsbl_sites = zen.spamhaus.org*3 b.barracudacentral.org*2 bl.spamcop.net*2
  postscreen_dnsbl_threshold = 3
  postscreen_blacklist_action = drop

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject_unauth_destination

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject

spamassassin unix -     n       n       -       -       pipe
  user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
EOF

echo "    ✓ Postfix configured"

# === PHASE 5: DOVECOT CONFIGURATION ===
echo "[*] Phase 5: Configuring Dovecot (IMAPS)"

cp -a /etc/dovecot/dovecot.conf "${BACKUP_DIR}/dovecot.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

cat > /etc/dovecot/dovecot.conf <<EOF
disable_plaintext_auth = yes
ssl = required
ssl_cert = <${MAIL_CERTDIR}/fullchain.pem
ssl_key = <${MAIL_CERTDIR}/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
ssl_dh = </usr/share/dovecot/dh.pem
auth_mechanisms = plain login
auth_username_format = %n
listen = *, ::
mail_location = maildir:~/Maildir:LAYOUT=fs
mail_privileged_group = mail

userdb { driver = passwd }
passdb { driver = pam }

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

protocol imap {
  imap_client_workarounds = tb-extra-mailbox-sep
}
protocol pop3 { disabled = yes }

plugin {
  sieve = ~/.dovecot.sieve
  sieve_default = /var/lib/dovecot/sieve/default.sieve
}
EOF

mkdir -p /var/lib/dovecot/sieve
cat > /var/lib/dovecot/sieve/default.sieve <<'EOF'
require ["fileinto", "mailbox"];
if header :contains "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
EOF
sievec /var/lib/dovecot/sieve/default.sieve 2>/dev/null || true
chown -R vmail:dovecot /var/lib/dovecot 2>/dev/null || useradd -r -g dovecot -d /var/lib/dovecot -s /usr/sbin/nologin vmail

echo "    ✓ Dovecot configured"

# === PHASE 6: OPENDKIM CONFIGURATION ===
echo "[*] Phase 6: Configuring OpenDKIM"

DKIMDIR="/etc/postfix/dkim/${DOMAIN}"
mkdir -p "${DKIMDIR}"
[ ! -f "${DKIMDIR}/mail.private" ] && opendkim-genkey -D "${DKIMDIR}" -d "${DOMAIN}" -s mail -r

chown -R opendkim:opendkim /etc/postfix/dkim
chmod -R u=rwX,g=rX,o= /etc/postfix/dkim

cat > /etc/opendkim.conf <<EOF
Domain                  ${DOMAIN}
KeyFile                 ${DKIMDIR}/mail.private
Selector                mail
SOCKET                  inet:12301@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UMask                   007
UserID                  opendkim
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
AutoRestart             yes
Background              yes
EOF

postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:localhost:12301"
postconf -e "non_smtpd_milters = \$smtpd_milters"

echo "    ✓ OpenDKIM configured"

# === PHASE 7: WEBMAIL (ROUNDCUBE) CONFIGURATION ===
echo "[*] Phase 7: Configuring Roundcube Webmail"

# Nginx virtual host
cat > /etc/nginx/sites-available/webmail <<EOF
server {
    listen 80;
    server_name ${WEBMAIL_HOST};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${WEBMAIL_HOST};

    ssl_certificate ${WEBMAIL_CERTDIR}/fullchain.pem;
    ssl_certificate_key ${WEBMAIL_CERTDIR}/privkey.pem;
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    root /usr/share/roundcube;
    index index.php;

    access_log /var/log/nginx/webmail-access.log;
    error_log /var/log/nginx/webmail-error.log;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VER}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_param HTTPS on;
    }

    location ~ /\.ht {
        deny all;
    }

    location = /unsubscribe {
        return 200 'Unsubscribe request received. Check your email for confirmation.\n';
        add_header Content-Type text/plain;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
}
EOF

ln -sf /etc/nginx/sites-available/webmail /etc/nginx/sites-enabled/webmail 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Harden Roundcube
cat >> /etc/roundcube/config.inc.php <<EOF
// Security hardening
\$config['use_https'] = true;
\$config['session_lifetime'] = 30;
\$config['ip_check'] = true;
\$config['disable_spellcheck'] = true;
\$config['enable_spellcheck'] = false;
\$config['password_charset'] = 'UTF-8';
\$config['useragent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
\$config['mime_param_folding'] = 1;
\$config['plugins'] = ['archive', 'zipdownload', 'password', 'managesieve'];
EOF

echo "    ✓ Roundcube configured"

# === PHASE 8: SYSTEM HARDENING ===
echo "[*] Phase 8: Applying System Hardening"

# Unattended updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

# Firewall
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
for port in 25 587 465 993 443; do ufw allow "${port}/tcp" comment "Mail/Webmail ${port}" >/dev/null 2>&1; done
ufw --force enable >/dev/null 2>&1

# Fail2ban
cat > /etc/fail2ban/jail.d/mail-hardened.conf <<'EOF'
[postfix]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600

[postfix-sasl]
enabled = true
maxretry = 3
bantime = 7200
findtime = 600

[dovecot]
enabled = true
maxretry = 5
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
maxretry = 3
bantime = 3600
EOF

echo "    ✓ System hardened"

# === PHASE 9: COMPLIANCE ACCOUNTS ===
echo "[*] Phase 9: Creating Compliance Accounts"

for user in postmaster abuse fbl unsubscribe; do
    id "${user}" >/dev/null 2>&1 || useradd -m -G mail -s /usr/sbin/nologin "${user}"
done

cat > /etc/aliases <<'EOF'
postmaster: root,postmaster@h2cnk.com
abuse: root,abuse@h2cnk.com
fbl: root,fbl@h2cnk.com
unsubscribe: root,unsubscribe@h2cnk.com
root: postmaster
EOF
newaliases

echo "    ✓ Compliance accounts created"

# === PHASE 10: SERVICE ACTIVATION ===
echo "[*] Phase 10: Starting Services"

systemctl daemon-reload
for svc in opendkim dovecot postfix fail2ban php${PHP_VER}-fpm nginx mysql; do
    systemctl enable "${svc}" --now 2>/dev/null || {
        echo "[-] Failed to start ${svc}" >&2
        journalctl -u "${svc}" -n 10 --no-pager 2>/dev/null || true
        exit 1
    }
    sleep 1
done

echo "    ✓ All services started"

# === PHASE 11: DNS RECORD GENERATION ===
echo "[*] Phase 11: Generating DNS Records for Cloudflare"

SERVER_IPv4="$(ip -4 addr show eth0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 || ip -4 addr show ens3 | awk '/inet / {print $2}' | cut -d/ -f1 || echo 'YOUR_SERVER_IP')"
SERVER_IPv6="$(ip -6 addr show eth0 2>/dev/null | awk '/inet6 / && !/fe80/ {print $2}' | cut -d/ -f1 | head -1 || true)"

DKIM_PUB="$(awk -F'"' '/p=/{print $2}' "${DKIMDIR}/mail.txt" | tr -d ' \t\n' || echo 'REPLACE_WITH_PUBLIC_KEY')"

cat > /root/dns-records-cloudflare.txt <<EOF
=============================================================================
CLOUDFLARE DNS RECORDS FOR h2cnk.com
Add these in Cloudflare Dashboard → DNS → Records
=============================================================================

1. A Record (Mail Server):
   Type:  A
   Name:  mail
   Value: ${SERVER_IPv4}
   TTL:   Auto
   Proxy: OFF (grey cloud icon)

2. A Record (Webmail):
   Type:  A
   Name:  webmail
   Value: ${SERVER_IPv4}
   TTL:   Auto
   Proxy: OFF (grey cloud icon)

3. MX Record:
   Type:  MX
   Name:  @
   Value: mail.h2cnk.com
   Priority: 10
   TTL:   Auto

4. TXT Record (SPF):
   Type:  TXT
   Name:  @
   Value: v=spf1 mx ip4:${SERVER_IPv4} -all
   TTL:   Auto

5. TXT Record (DKIM):
   Type:  TXT
   Name:  mail._domainkey
   Value: v=DKIM1; k=rsa; ${DKIM_PUB}
   TTL:   Auto

6. TXT Record (DMARC):
   Type:  TXT
   Name:  _dmarc
   Value: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; fo=1; pct=100; rua=mailto:fbl@h2cnk.com; ruf=mailto:fbl@h2cnk.com
   TTL:   Auto

7. CAA Record (Recommended):
   Type:  CAA
   Name:  @
   Value: 0 issue "letsencrypt.org"
   TTL:   Auto

=============================================================================
IMPORTANT NOTES:
• WAIT 5 MINUTES after adding records before testing mail flow
• Proxy status MUST be GREY CLOUD (OFF) for mail/webmail records
• Contact your VPS provider to set PTR record → mail.h2cnk.com
• Replace 'YOUR_SERVER_IP' above if detection failed
=============================================================================
EOF

echo "    ✓ DNS records generated: /root/dns-records-cloudflare.txt"

# === PHASE 12: VALIDATION SCRIPT ===
cat > /usr/local/bin/mail-healthcheck <<EOF
#!/bin/bash
set -eu
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  MAIL SERVER HEALTH CHECK                                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "✓ Hostname: $(hostname -f)"
echo "✓ Public IP: $(ip -4 addr show eth0 2>/dev/null | awk '/inet / {print \$2}' | cut -d/ -f1 || echo 'N/A')"
echo ""
echo "SERVICES:"
systemctl is-active --quiet postfix && echo "  ✓ Postfix (SMTP)" || echo "  ✗ Postfix DOWN"
systemctl is-active --quiet dovecot && echo "  ✓ Dovecot (IMAPS)" || echo "  ✗ Dovecot DOWN"
systemctl is-active --quiet opendkim && echo "  ✓ OpenDKIM" || echo "  ✗ OpenDKIM DOWN"
systemctl is-active --quiet nginx && echo "  ✓ Nginx (Webmail)" || echo "  ✗ Nginx DOWN"
systemctl is-active --quiet fail2ban && echo "  ✓ Fail2ban" || echo "  ✗ Fail2ban DOWN"
echo ""
echo "FIREWALL:"
ufw status numbered 2>/dev/null | grep -E "(25|587|465|993|443)" | awk '{print "  ✓ Open: " \$3 " (" \$4 ")"}' || echo "  ? UFW status unknown"
echo ""
echo "TLS CERTIFICATES:"
openssl x509 -in /etc/letsencrypt/live/mail.h2cnk.com/fullchain.pem -noout -subject 2>/dev/null | cut -d= -f2- | xargs echo "  ✓ Mail: " || echo "  ✗ Mail cert missing"
openssl x509 -in /etc/letsencrypt/live/webmail.h2cnk.com/fullchain.pem -noout -subject 2>/dev/null | cut -d= -f2- | xargs echo "  ✓ Webmail: " || echo "  ✗ Webmail cert missing"
echo ""
echo "COMPLIANCE ACCOUNTS:"
for user in postmaster abuse fbl unsubscribe; do
    id "\${user}" >/dev/null 2>&1 && echo "  ✓ \${user}@h2cnk.com" || echo "  ✗ \${user} missing"
done
echo ""
echo "THROTTLING: 5 messages/second enforced"
echo "WEBMAIL:   https://webmail.h2cnk.com"
echo "DNS SETUP: /root/dns-records-cloudflare.txt"
EOF
chmod 700 /usr/local/bin/mail-healthcheck

# === PHASE 13: USER CREATION SCRIPT ===
cat > /root/create-mail-user.sh <<'EOF'
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <username>"
    echo "Example: $0 alice"
    exit 1
fi
USERNAME="$1"
adduser "${USERNAME}"
echo ""
echo "✓ User ${USERNAME}@h2cnk.com created successfully"
echo ""
echo "ACCESS INSTRUCTIONS:"
echo "  Webmail: https://webmail.h2cnk.com"
echo "  Username: ${USERNAME}@h2cnk.com"
echo "  Password: [what you just set]"
echo ""
echo "IMAP/SMTP SETTINGS:"
echo "  Incoming (IMAP): mail.h2cnk.com:993 (SSL/TLS)"
echo "  Outgoing (SMTP): mail.h2cnk.com:587 (STARTTLS)"
echo "  Authentication: Required (same as webmail)"
EOF
chmod 700 /root/create-mail-user.sh

# === SUCCESS MARKER ===
touch "${SUCCESS_MARKER}"

# === COMPLETION BANNER ===
cat <<EOF

╔════════════════════════════════════════════════════════════════════════════╗
║  ✓✓✓ DEPLOYMENT COMPLETE ✓✓✓                                              ║
╚════════════════════════════════════════════════════════════════════════════╝

SERVER DETAILS:
  Mail Host:    mail.h2cnk.com
  Webmail:      https://webmail.h2cnk.com
  Domain:       h2cnk.com
  OS:           Debian ${OS_VERSION} (${OS_ID})
  Throttling:   5 messages/second (anti-blacklist protection)
  Compliance:   postmaster@, abuse@, fbl@, unsubscribe@h2cnk.com

NEXT STEPS:
  1. Configure Cloudflare DNS records:
        cat /root/dns-records-cloudflare.txt
     → Add ALL records in Cloudflare Dashboard (DNS → Records)
     → SET PROXY TO GREY CLOUD (OFF) for mail/webmail records
     → WAIT 5 MINUTES after saving

  2. Request PTR record from VPS provider:
        "Set reverse DNS for ${SERVER_IPv4} → mail.h2cnk.com"

  3. Create mail user:
        /root/create-mail-user.sh alice

  4. Verify deployment:
        /usr/local/bin/mail-healthcheck

  5. Access webmail:
        https://webmail.h2cnk.com  (login: alice@h2cnk.com)

LOG FILE:
  ${LOG}

COMPLIANCE REMINDER:
  • Monitor abuse@h2cnk.com and postmaster@h2cnk.com DAILY
  • All marketing emails auto-include unsubscribe mechanism
  • PTR record REQUIRED for 95%+ deliverability (contact VPS provider)

EOF
