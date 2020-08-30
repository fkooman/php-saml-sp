<?php

/*
 * Copyright (c) 2019-2020 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\SAML\SP;

use DOMElement;
use fkooman\SAML\SP\Exception\CryptoException;
use ParagonIE\ConstantTime\Base64;

class Crypto
{
    const SIGN_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGN_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGN_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGN_HASH_ALGO = 'sha256';

    const ENCRYPT_KEY_DIGEST_ALGO = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const ENCRYPT_KEY_TRANSPORT_ALGO = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /**
     * @param array<PublicKey> $publicKeys
     *
     * @throws \fkooman\SAML\SP\Exception\CryptoException
     *
     * @return void
     */
    public static function verifyXml(XmlDocument $xmlDocument, array $publicKeys)
    {
        $rootElementId = $xmlDocument->requireOneDomAttrValue('self::node()/@ID');
        $referenceUri = $xmlDocument->requireOneDomAttrValue('self::node()/ds:Signature/ds:SignedInfo/ds:Reference/@URI');
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new CryptoException('reference URI does not point to document ID');
        }

        $digestMethod = $xmlDocument->requireOneDomAttrValue('self::node()/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm');
        if (self::SIGN_DIGEST_ALGO !== $digestMethod) {
            throw new CryptoException(\sprintf('only digest method "%s" is supported', self::SIGN_DIGEST_ALGO));
        }

        $signatureMethod = $xmlDocument->requireOneDomAttrValue('self::node()/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm');
        if (self::SIGN_ALGO !== $signatureMethod) {
            throw new CryptoException(\sprintf('only signature method "%s" is supported', self::SIGN_ALGO));
        }

        $signatureValue = self::removeWhiteSpace($xmlDocument->requireOneDomElementTextContent('self::node()/ds:Signature/ds:SignatureValue'));
        $digestValue = self::removeWhiteSpace($xmlDocument->requireOneDomElementTextContent('self::node()/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue'));

        $signedInfoElement = $xmlDocument->requireOneDomElement('self::node()/ds:Signature/ds:SignedInfo');
        $canonicalSignedInfo = $signedInfoElement->C14N(true, false);
        $signatureElement = $xmlDocument->requireOneDomElement('self::node()/ds:Signature');
        $rootElement = $xmlDocument->requireOneDomElement('self::node()');
        $rootElement->removeChild($signatureElement);
        $rootElementDigest = Base64::encode(
            \hash(
                self::SIGN_HASH_ALGO,
                self::canonicalizeElement($rootElement),
                true
            )
        );

        // compare the digest from the XML with the actual digest
        if (!\hash_equals($rootElementDigest, $digestValue)) {
            throw new CryptoException('unexpected digest');
        }

        self::verify($canonicalSignedInfo, Base64::decode($signatureValue), $publicKeys);
    }

    /**
     * @param string           $inStr
     * @param string           $inSig
     * @param array<PublicKey> $publicKeys
     *
     * @throws \fkooman\SAML\SP\Exception\CryptoException
     *
     * @return void
     */
    public static function verify($inStr, $inSig, array $publicKeys)
    {
        if (0 === \count($publicKeys)) {
            throw new CryptoException('no public key(s) provided');
        }

        foreach ($publicKeys as $publicKey) {
            if (1 === \openssl_verify($inStr, $inSig, $publicKey->raw(), self::SIGN_OPENSSL_ALGO)) {
                // signature verified
                return;
            }
        }

        throw new CryptoException('unable to verify signature');
    }

    /**
     * @throws \fkooman\SAML\SP\Exception\CryptoException
     *
     * @return string
     */
    public static function decryptXml(XmlDocument $xmlDocument, PrivateKey $privateKey)
    {
        if (!self::hasDecryptionSupport()) {
            throw new CryptoException('XML decryption is not supported on this system');
        }

        // make sure we support the key transport encryption algorithm
        $keyEncryptionMethod = $xmlDocument->requireOneDomAttrValue('/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm');
        if (self::ENCRYPT_KEY_TRANSPORT_ALGO !== $keyEncryptionMethod) {
            throw new CryptoException(\sprintf('only key transport algorithm "%s" is supported', self::ENCRYPT_KEY_TRANSPORT_ALGO));
        }

        // make sure we support the key transport encryption digest algorithm
        $keyEncryptionDigestMethod = $xmlDocument->requireOneDomAttrValue('/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm');
        if (self::ENCRYPT_KEY_DIGEST_ALGO !== $keyEncryptionDigestMethod) {
            throw new CryptoException(\sprintf('only key encryption digest "%s" is supported', self::ENCRYPT_KEY_DIGEST_ALGO));
        }

        // extract the session key
        $keyCipherValue = self::removeWhiteSpace($xmlDocument->requireOneDomElementTextContent('/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue'));

        // decrypt the session key
        if (false === \openssl_private_decrypt(Base64::decode($keyCipherValue), $symmetricEncryptionKey, $privateKey->raw(), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new CryptoException('unable to extract session key');
        }

        // find out which encryption algorithm was used for the EncryptedAssertion
        $encryptionMethod = $xmlDocument->requireOneDomAttrValue('/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm');

        // make sure the obtained key is the exact length we expect
        if (CryptoParameters::getKeyLength($encryptionMethod) !== \strlen($symmetricEncryptionKey)) {
            throw new CryptoException('session key has unexpected length');
        }

        // extract the encrypted Assertion
        $assertionCipherValue = Base64::decode(self::removeWhiteSpace($xmlDocument->requireOneDomElementTextContent('/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue')));

        // @see https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
        $messageIv = \substr($assertionCipherValue, 0, CryptoParameters::getIvLength($encryptionMethod)); // IV (first 96 bits)
        $messageTag = \substr($assertionCipherValue, \strlen($assertionCipherValue) - CryptoParameters::getTagLength($encryptionMethod)); // Tag (last 128 bits)
        $cipherText = \substr($assertionCipherValue, CryptoParameters::getIvLength($encryptionMethod), -CryptoParameters::getTagLength($encryptionMethod)); // CipherText (between IV and Tag)
        if (false === $decryptedAssertion = \openssl_decrypt($cipherText, CryptoParameters::getOpenSslAlgorithm($encryptionMethod), $symmetricEncryptionKey, OPENSSL_RAW_DATA, $messageIv, $messageTag)) {
            throw new CryptoException('unable to decrypt data');
        }

        return $decryptedAssertion;
    }

    /**
     * @param string $inStr
     *
     * @throws \fkooman\SAML\SP\Exception\CryptoException
     *
     * @return string
     */
    public static function sign($inStr, PrivateKey $privateKey)
    {
        if (false === \openssl_sign($inStr, $outSig, $privateKey->raw(), self::SIGN_OPENSSL_ALGO)) {
            throw new CryptoException('unable to create signature');
        }

        return $outSig;
    }

    /**
     * @return bool
     */
    public static function hasDecryptionSupport()
    {
        // ext-openssl MUST be loaded
        if (false === \extension_loaded('openssl')) {
            return false;
        }

        // we need PHP >= 7.1.0 for AEAD support in PHP/OpenSSL
        if (\version_compare(PHP_VERSION, '7.1.0') < 0) {
            return false;
        }

        // we need support for AES-GCM
        foreach (['aes-128-gcm', 'aes-256-gcm'] as $encryptionAlgorithm) {
            if (!\in_array($encryptionAlgorithm, \openssl_get_cipher_methods(), true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return string
     */
    private static function canonicalizeElement(DOMElement $domElement)
    {
        // canonicalizing a DOMElement can be *very* slow, however,
        // canonicalizing a *DOMDocument* is fast in PHP
        // @see https://groups.google.com/forum/#!msg/simplesamlphp/b6fTf53iq4w/uNhw_NBNzxkJ
        if (null !== $ownerDocument = $domElement->ownerDocument) {
            if ($domElement === $ownerDocument->documentElement) {
                return $ownerDocument->C14N(true, false);
            }
        }

        return $domElement->C14N(true, false);
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    private static function removeWhiteSpace($inputStr)
    {
        // https://www.w3.org/TR/xmlschema11-2/#base64Binary
        // https://www.w3.org/TR/xmlschema11-2/#rf-whiteSpace
        // we do NOT follow the exact rules for white space removal, because
        // they are insane...
        return \str_replace(["\x09", "\x0a", "\x0d", "\x20"], '', $inputStr);
    }
}
