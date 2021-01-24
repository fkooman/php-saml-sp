# FAQ 

## Why do attributes my IdP sends not show up at the SP?

The attribute is filtered because:

1. It is not in the `urn:oid` format, or not in the 
   [list](https://git.sr.ht/~fkooman/php-saml-sp/tree/main/item/src/attribute_mapping.php)
   of supported attributes;
2. The _scope_ of the attribute, i.e. the part behind the `@` of an attribute 
   value, for example `eduPersonPrincipalName`, is not listed in the 
   `<shibmd:Scope>` element of the IdP metadata.
