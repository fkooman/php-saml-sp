# Metadata

We have two "types" of metadata handling in php-saml-sp:

1. Static in `/etc/php-saml-sp/metadata`
2. Dynamic in `/var/lib/php-saml-sp/metadata`

With the "static" type, the administrator is in full control. With the 
"dynamic" type the metadata will be refreshed automatically periodically and 
thus support IdP key rollovers. This is especially useful for identity 
federations.

## Static

All metadata files in `/etc/php-saml-sp/metadata` are considered valid, i.e. 
their XML schema and XML signature will NOT be checked, nor the `validUntil` 
or `cacheDuration` attributes. Here the administrator is fully responsible for
making sure the metadata files are kept up to date.

You can use the validation tooling part of php-saml-sp to make sure the 
metadata file you obtained is at least correct. This is RECOMMENDED, for 
example:

    $ curl -o SURFconext.xml https://metadata.surfconext.nl/idp-metadata.xml
    $ php-saml-sp-validate-metadata SURFconext.xml
    Verifying XML schema... OK!

If you also have the metadata signing key, you can use that to validate the 
signature as well:

    $ curl -O https://metadata.surfconext.nl/SURFconext-metadata-signer.pem
    $ php-saml-sp-validate-metadata SURFconext.xml SURFconext-metadata-signer.pem
    Verifying XML schema... OK!
    Verifying XML signature... OK!

After this, you can copy the file to e.g. 
`/etc/php-saml-sp/metadata/SURFconext.xml`. It will now be picked up by 
php-saml-sp.

All entities in this metadata file(s) under `/etc/php-saml-sp/metadata` will be 
allowed for authentication. You can restrict this by explicitly specifying the 
IdP entityIDs in `/etc/php-saml-sp/config.php` in the array `idpList`, for 
example:

    'idpList' => [
        'https://engine.surfconext.nl/authentication/idp/metadata',
    ],

## Dynamic

The dynamic type is more of a "configure once and forget" type of situation. 
It can be configured through `/etc/php-saml-sp/config.php` under 
`metadataList`. For example:

    'metadataList' => [
        'https://metadata.wayf.dk/wayf-metadata.xml' => ['wayf.dk.crt'],
    ],

This specifies the URL of the metadata, and the certificate that will be used
to verify the metadata XML schema and XML signature. The key with the name as 
specified MUST be placed under `/etc/php-saml-sp/metadata/keys`.

After configuring this, you can test the fetching:

    $ sudo systemctl start php-saml-sp

This should place the metadata file(s) in `/var/lib/php-saml-sp/metadata`. 
Base64UrlSafe encoding is used to convert the URL to a string that is safe to 
store on the file system. The `php-saml-sp` service is not a service that 
remains active, but is `Type=oneshot` which means it runs once and then stops. 
Using a timer we can periodically launch it, see below.

You can follow along what happens:

    $ journalctl -f -t php-saml-sp-update-metadata

    Jul 22 12:06:47 fralen-tuxed-net php-saml-sp-update-metadata[14666]: [https://metadata.wayf.dk/wayf-metadata.xml] attempting to update metadata
    Jul 22 12:06:47 fralen-tuxed-net php-saml-sp-update-metadata[14666]: [https://metadata.wayf.dk/wayf-metadata.xml] fetching metadata
    Jul 22 12:06:47 fralen-tuxed-net php-saml-sp-update-metadata[14666]: [https://metadata.wayf.dk/wayf-metadata.xml] validating metadata
    Jul 22 12:06:47 fralen-tuxed-net php-saml-sp-update-metadata[14666]: [https://metadata.wayf.dk/wayf-metadata.xml] OK

Any subsequent runs of `php-saml-sp-update-metadata` will result in a different
output:

    Jul 22 12:07:44 fralen-tuxed-net php-saml-sp-update-metadata[14705]: [https://metadata.wayf.dk/wayf-metadata.xml] attempting to update metadata
    Jul 22 12:07:44 fralen-tuxed-net php-saml-sp-update-metadata[14705]: [https://metadata.wayf.dk/wayf-metadata.xml] not time yet to refresh

The command will check the `cacheDuration` in the metadata file (if specified) 
and only update the metadata when it is about the expire. If no `cacheDuration` 
is specified, a default of 6 hours is used.

To automate this process, a systemd timer is included that can easily be 
enabled:

    $ sudo systemctl enable --now php-saml-sp.timer

### Force Update

If you want to _force_ the update of metadata you can either remove the files
from `/var/lib/php-saml-sp/metadata` or run the refresh command (manually). Use
`www-data` instead of `apache` on Debian:

    $ sudo -u apache php-saml-sp-update-metadata --force
