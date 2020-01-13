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

class Crypto
{
    const SIGN_OPENSSL_ALGO = OPENSSL_ALGO_SHA256;
    const SIGN_ALGO = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const SIGN_DIGEST_ALGO = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SIGN_HASH_ALGO = 'sha256';

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
}
