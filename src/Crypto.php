<?php

/*
 * Copyright (c) 2019 François Kooman <fkooman@tuxed.net>
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
use ParagonIE\ConstantTime\Binary;
use RuntimeException;

class Crypto
{
    const SIGN_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGN_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGN_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGN_HASH_ALGO = 'sha256';

    const ENCRYPT_KEY_DIGEST_ALGO = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const ENCRYPT_KEY_TRANSPORT_ALGO = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    const ENCRYPT_OPENSSL_ALGO = 'aes-256-gcm';
    const ENCRYPT_IV_LENGTH = 12;
    const ENCRYPT_TAG_LENGTH = 16;
    const ENCRYPT_KEY_LENGTH = 32;

    /**
     * @param array<PublicKey> $publicKeys
     *
     * @throws \fkooman\SAML\SP\Exception\CryptoException
     *
     * @return void
     */
    public static function verifyXml(XmlDocument $xmlDocument, DOMElement $domElement, array $publicKeys)
    {
        $rootElementId = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(self::node()/@ID)', $domElement));
        $referenceUri = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/@URI)', $domElement));
        if (\sprintf('#%s', $rootElementId) !== $referenceUri) {
            throw new CryptoException('reference URI does not point to document ID');
        }

        $digestMethod = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm)', $domElement));
        if (self::SIGN_DIGEST_ALGO !== $digestMethod) {
            throw new CryptoException(\sprintf('only digest method "%s" is supported', self::SIGN_DIGEST_ALGO));
        }

        $signatureMethod = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm)', $domElement));
        if (self::SIGN_ALGO !== $signatureMethod) {
            throw new CryptoException(\sprintf('only signature method "%s" is supported', self::SIGN_ALGO));
        }

        $signatureValue = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignatureValue)', $domElement));
        $digestValue = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue)', $domElement));

        $signedInfoElement = XmlDocument::requireDomElement($xmlDocument->domXPath->query('ds:Signature/ds:SignedInfo', $domElement)->item(0));
        $canonicalSignedInfo = $signedInfoElement->C14N(true, false);
        $signatureElement = XmlDocument::requireDomElement($xmlDocument->domXPath->query('ds:Signature', $domElement)->item(0));
        $domElement->removeChild($signatureElement);

        $rootElementDigest = Base64::encode(
            \hash(
                self::SIGN_HASH_ALGO,
                $domElement->C14N(true, false),
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
    public static function decryptXml(XmlDocument $xmlDocument, DOMElement $domElement, PrivateKey $privateKey)
    {
        if (!self::hasDecryptionSupport()) {
            throw new RuntimeException('"EncryptedAssertion" is not supported on this system');
        }

        // make sure we support the encryption algorithm
        $encryptionMethod = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm)', $domElement));

        // make sure we support the key transport encryption algorithm
        $keyEncryptionMethod = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm)', $domElement));
        if (self::ENCRYPT_KEY_TRANSPORT_ALGO !== $keyEncryptionMethod) {
            throw new CryptoException(\sprintf('only key transport algorithm "%s" is supported', self::ENCRYPT_KEY_TRANSPORT_ALGO));
        }

        // make sure we support the key transport encryption digest algorithm
        $keyEncryptionDigestMethod = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod/@Algorithm)', $domElement));
        if (self::ENCRYPT_KEY_DIGEST_ALGO !== $keyEncryptionDigestMethod) {
            throw new CryptoException(\sprintf('only key encryption digest "%s" is supported', self::ENCRYPT_KEY_DIGEST_ALGO));
        }

        // extract the session key
        $keyCipherValue = XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue)', $domElement));

        // decrypt the session key
        if (false === \openssl_private_decrypt(Base64::decode($keyCipherValue), $symmetricEncryptionKey, $privateKey->raw(), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new CryptoException('unable to extract session key');
        }

        // make sure the obtained key is the exact length we expect
        if (self::ENCRYPT_KEY_LENGTH !== Binary::safeStrlen($symmetricEncryptionKey)) {
            throw new CryptoException('session key has unexpected length');
        }

        // extract the encrypted Assertion
        $assertionCipherValue = Base64::decode(XmlDocument::requireNonEmptyString($xmlDocument->domXPath->evaluate('string(xenc:EncryptedData/xenc:CipherData/xenc:CipherValue)', $domElement)));

        // @see https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
        $messageIv = Binary::safeSubstr($assertionCipherValue, 0, self::ENCRYPT_IV_LENGTH); // IV (first 96 bits)
        $messageTag = Binary::safeSubstr($assertionCipherValue, Binary::safeStrlen($assertionCipherValue) - self::ENCRYPT_TAG_LENGTH); // Tag (last 128 bits)
        $cipherText = Binary::safeSubstr($assertionCipherValue, self::ENCRYPT_IV_LENGTH, -self::ENCRYPT_TAG_LENGTH); // CipherText (between IV and Tag)
        if (false === $decryptedAssertion = \openssl_decrypt($cipherText, self::ENCRYPT_OPENSSL_ALGO, $symmetricEncryptionKey, OPENSSL_RAW_DATA, $messageIv, $messageTag)) {
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

        // we need support for AES-256-GCM
        if (!\in_array('aes-256-gcm', \openssl_get_cipher_methods(), true)) {
            return false;
        }

        return true;
    }
}
