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

class CryptoKeys
{
    /** @var PrivateKey */
    private $signingPrivateKey;

    /** @var PublicKey */
    private $signingPublicKey;

    /** @var PrivateKey */
    private $encryptionPrivateKey;

    /** @var PublicKey */
    private $encryptionPublicKey;

    public function __construct(PrivateKey $signingPrivateKey, PublicKey $signingPublicKey, PrivateKey $encryptionPrivateKey, PublicKey $encryptionPublicKey)
    {
        $this->signingPrivateKey = $signingPrivateKey;
        $this->signingPublicKey = $signingPublicKey;
        $this->encryptionPrivateKey = $encryptionPrivateKey;
        $this->encryptionPublicKey = $encryptionPublicKey;
    }

    /**
     * @return PrivateKey
     */
    public function getSigningPrivateKey()
    {
        return $this->signingPrivateKey;
    }

    /**
     * @return PublicKey
     */
    public function getSigningPublicKey()
    {
        return $this->signingPublicKey;
    }

    /**
     * @return PrivateKey
     */
    public function getEncryptionPrivateKey()
    {
        return $this->encryptionPrivateKey;
    }

    /**
     * @return PublicKey
     */
    public function getEncryptionPublicKey()
    {
        return $this->encryptionPublicKey;
    }

    /**
     * @param string      $privateKeyPath
     * @param string|null $publicKeyPath
     *
     * @return self
     */
    public static function load($privateKeyPath, $publicKeyPath = null)
    {
        if (null === $publicKeyPath) {
            $publicKeyPath = $privateKeyPath;
        }

        // support legacy "sp.key" and "sp.crt" for both singing and encryption
        // we can remove this when we no longer offer php-fkooman-saml-sp aka
        // fkooman/saml-sp as a library...
        if (\file_exists($privateKeyPath.'/sp.key')) {
            return new self(
                PrivateKey::fromFile($privateKeyPath.'/sp.key'),
                PublicKey::fromFile($publicKeyPath.'/sp.crt'),
                PrivateKey::fromFile($privateKeyPath.'/sp.key'),
                PublicKey::fromFile($publicKeyPath.'/sp.crt')
            );
        }

        return new self(
            PrivateKey::fromFile($privateKeyPath.'/signing.key'),
            PublicKey::fromFile($publicKeyPath.'/signing.crt'),
            PrivateKey::fromFile($privateKeyPath.'/encryption.key'),
            PublicKey::fromFile($publicKeyPath.'/encryption.crt')
        );
    }
}
