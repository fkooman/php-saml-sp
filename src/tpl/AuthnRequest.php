<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="<?=$ID; ?>" Version="2.0" IssueInstant="<?=$IssueInstant; ?>" Destination="<?=$Destination; ?>" Consent="urn:oasis:names:tc:SAML:2.0:consent:current-implicit" ForceAuthn="false" IsPassive="false" AssertionConsumerServiceURL="<?=$AssertionConsumerServiceURL; ?>">
  <saml:Issuer><?=$Issuer; ?></saml:Issuer>
<?php if (0 !== \count($AuthnContextClassRef)): ?>
  <samlp:RequestedAuthnContext Comparison="exact">
<?php foreach ($AuthnContextClassRef as $v): ?>
    <saml:AuthnContextClassRef><?=$v; ?></saml:AuthnContextClassRef>
<?php endforeach; ?>
  </samlp:RequestedAuthnContext>
<?php endif; ?>
<?php if (0 !== \count($ScopingIdpList)): ?>
  <samlp:Scoping>
    <samlp:IDPList>
<?php foreach ($ScopingIdpList as $ScopingIdp): ?>
      <samlp:IDPEntry ProviderID="<?=$ScopingIdp; ?>"/>
<?php endforeach; ?>
    </samlp:IDPList>
  </samlp:Scoping>
<?php endif; ?>
</samlp:AuthnRequest>
