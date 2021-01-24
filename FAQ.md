# FAQ 

## Why do attributes my IdP send not show up in the SP?

The attribute is filtered because:

1. It is not in the `urn:oid` format, or not in the 
   [list](https://git.sr.ht/~fkooman/php-saml-sp/tree/main/item/src/attribute_mapping.php)
   of supported attributes;
2. The _scope_ of the attribute, for example the _realm_, is not listed in the 
   list of IdP's in the `<shibmd:Scope>` element of the IdP metadata.
