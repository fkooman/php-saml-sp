<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="<?=$spInfo->getEntityId(); ?>">
  <md:Extensions>
    <mdui:UIInfo>
<?php foreach ($spInfo->getDisplayNameList() as $langKey => $langText): ?>
      <mdui:DisplayName xml:lang="<?=$langKey; ?>"><?=$langText; ?></mdui:DisplayName>
<?php endforeach; ?>
    </mdui:UIInfo>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod MinKeySize="2048" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate><?=$spInfo->getCryptoKeys()->getSigningPublicKey()->toEncodedString(); ?></ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
<?php if (fkooman\SAML\SP\Crypto::hasDecryptionSupport()): ?>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate><?=$spInfo->getCryptoKeys()->getEncryptionPublicKey()->toEncodedString(); ?></ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    </md:KeyDescriptor>
<?php endif; ?>
<?php if (null !== $spInfo->getSloUrl()): ?>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="<?=$spInfo->getSloUrl(); ?>"/>
<?php endif; ?>
    <md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="<?=$spInfo->getAcsUrl(); ?>"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
