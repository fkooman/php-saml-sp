# Installation

We assume you already have your web server configured properly, e.g. with 
working TLS and PHP(-FPM) running.

Download the latest "composer" release from 
`https://src.tuxed.net/php-saml-sp/`, e.g.:

    $ curl -O https://src.tuxed.net/php-saml-sp/php-saml-sp-0.5.6_composer.tar.xz

Verify the signature, highly recommended:

    $ curl -O https://src.tuxed.net/php-saml-sp/php-saml-sp-0.5.6_composer.tar.xz.minisig
    $ minisign -Vm php-saml-sp-0.5.6_composer.tar.xz -P RWSC3Lwn4f9mhG3XIwRUTEIqf7Ucu9+7/Rq+scUMxrjg5/kjskXKOJY/
    Signature and comment signature verified
    Trusted comment: timestamp:1598601647	file:php-saml-sp-0.5.6_composer.tar.xz

Install it:

    $ tar -xJf php-saml-sp-0.5.6_composer.tar.xz
    $ sudo mv php-saml-sp-0.5.6 /var/www
    $ sudo ln -s /var/www/php-saml-sp-0.5.6 /var/www/php-saml-sp

Use the example configuration:

    $ sudo cp /var/www/php-saml-sp/config/config.php.example /var/www/php-saml-sp/config/config.php

Generate the signing/encryption keys:
    
    $ cd /var/www/php-saml-sp/keys
    $ sudo ./generate_keys.sh
    $ sudo chmod 0640 *.crt *key
    $ sudo chown root.apache *.crt *.key     # (Fedora/CentOS)
    $ sudo chown root.www-data *.crt *.key   # (Debian/Ubuntu)
    
You may want to update `/var/www/php-saml-sp/config/config.php` and set 
`spPath`, e.g.:

    'spPath' => '/saml',

You need this information for the Apache configuration snippet though in the
`Alias` line and the `RewriteBase` line:

    Alias /saml /var/www/php-saml-sp/web

    <Directory /var/www/php-saml-sp/web>
        Require all granted
        #Require local

        RewriteEngine on
        RewriteBase /saml
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteCond %{REQUEST_FILENAME} !-d
        RewriteRule ^ index.php [L,QSA]

        # Security Headers
        Header always set Content-Security-Policy "default-src 'self'"
        Header always set X-Frame-Options "DENY"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set Referrer-Policy "same-origin"
    </Directory>

Add this file to `/etc/httpd/conf.d/php-saml-sp.conf` on CentOS/Fedora and in 
`/etc/apache2/conf-available/php-saml-sp.conf` on Debian/Ubuntu.

On Debian/Ubuntu you need to enable this configuration first:

    $ sudo a2enconf php-saml-sp
    
Now restart Apache:

    $ sudo systemctl restart httpd   # (Fedora/CentOS)
    $ sudo systemctl restart apache2 # (Debian/Ubuntu)

Now you can visit your site on `https://host.example.org/saml`. You should be
greeated by the main page.

You can add IdPs by putting their metadata XML files in 
`/var/www/php-saml-sp/config/metadata`.

# Dynamic Metadata

See [METADATA](METADATA.md). This document is written for when using the 
packages. Replace `/etc/php-saml-sp` with `/var/www/php-saml-sp/config` and
`/var/lib/php-saml-sp` with `/var/www/php-saml-sp/data`.

As for the `php-saml-sp.service` and `php-saml-sp.timer` files, you can use 
these:

`php-saml-sp.service`:

    [Unit]
    Description=Automatically retrieve SAML metadata from IdP(s) and/or federation(s)

    [Service]
    Type=oneshot
    User=www-data
    Group=www-data
    ExecStart=/usr/bin/php /var/www/php-saml-sp/bin/update-metadata.php
    
`php-saml-sp.timer`:

    [Unit]
    Description=Schedule automatically retrieving SAML metadata

    [Timer]
    OnCalendar=*-*-* *:00:00
    RandomizedDelaySec=900
    Persistent=true

    [Install]
    WantedBy=timers.target
    
Put them in `/etc/systemd/system` on your system.

# Software Update

Download the latest "composer" release from 
`https://src.tuxed.net/php-saml-sp/`, e.g.:

    $ curl -O https://src.tuxed.net/php-saml-sp/php-saml-sp-0.5.7_composer.tar.xz

Verify the signature, highly recommended:

    $ curl -O https://src.tuxed.net/php-saml-sp/php-saml-sp-0.5.7_composer.tar.xz.minisig
    $ minisign -Vm php-saml-sp-0.5.7_composer.tar.xz -P RWSC3Lwn4f9mhG3XIwRUTEIqf7Ucu9+7/Rq+scUMxrjg5/kjskXKOJY/
    Signature and comment signature verified
    Trusted comment: timestamp:1598601647	file:php-saml-sp-0.5.7_composer.tar.xz

Install it:

    $ tar -xJf php-saml-sp-0.5.7_composer.tar.xz
    $ sudo mv php-saml-sp-0.5.7 /var/www

Copy the configuration, IdP metadata and keys:

    $ sudo cp -a /var/www/php-saml-sp/config/config.php /var/www/php-saml-sp-0.5.7/config/config.php
    $ sudo cp -ra /var/www/php-saml-sp/config/metadata /var/www/php-saml-sp-0.5.7/config
    $ sudo cp -ra /var/www/php-saml-sp/keys /var/www/php-saml-sp-0.5.7/keys

Update the symlink:

    $ sudo rm /var/www/php-saml-sp
    $ sudo ln -s /var/www/php-saml-sp-0.5.7 /var/www/php-saml-sp
    
If everything works, you can remove the previous version folder:

    $ sudo rm -rf /var/www/php-saml-sp-0.5.6
