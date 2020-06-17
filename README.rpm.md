# Installation

If not yet done, install and enable Apache and php-fpm. On Fedora you use `dnf` 
instead of `yum`, the rest stays the same:

    $ sudo yum -y install php-fpm httpd
    $ sudo systemctl enable --now php-fpm
    $ sudo systemctl enable --now httpd

On CentOS 7 you may need some additional configuration for php-fpm, see 
[this](https://developers.redhat.com/blog/2017/10/25/php-configuration-tips/) 
Red Hat blog post, or my 
[post](https://www.tuxed.net/fkooman/blog/centos_apache_php_fpm.html).

Install php-saml-sp:

    $ sudo yum -y install php-saml-sp
    $ sudo systemctl restart httpd

Configure your web server to use a TLS certificate, how to do this is out of
scope here.

# Configuration

All configuration takes place in the `/etc/php-saml-sp` directory. You can 
modify `config.php` in that folder.

The default configuration template contains instructions on how to modify the
file.

The only thing you MUST change is the array `idpList` to contain the entity IDs
of the IdPs you want to give access.

## Metadata

You can place the metadata for the IdPs that have access to your SP in 
`/etc/php-saml-sp/metadata`. Create the folder if it does not yet exist.

## Example
    
    # mkdir /etc/php-saml-sp/metadata
    # cd /etc/php-saml-sp/metadata
    # curl -o x509idp.moonshot.utr.surfcloud.nl.xml https://x509idp.moonshot.utr.surfcloud.nl/metadata

Now modify `/etc/php-saml-sp/config.php` and add 
`https://x509idp.moonshot.utr.surfcloud.nl/metadata` to `idpList`.

Verify the configuration file for syntax errors:

    # php -l /etc/php-saml-sp/config.php

If all is fine you should now be able to test your SP by going to 
`https://sp.example.org/php-saml-sp`, where `sp.example.org` is the host name 
of your server and click the "Test" button to start the SAML login.
