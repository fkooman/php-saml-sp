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

use fkooman\SAML\SP\Exception\KeyException;
use RuntimeException;

class PublicKey
{
    /** @var resource */
    private $publicKey;

    /** @var string */
    private $pemStr;

    /**
     * @param string $pemStr
     *
     * @throws \fkooman\SAML\SP\Exception\KeyException
     */
    public function __construct($pemStr)
    {
        if (false === $publicKey = \openssl_pkey_get_public($pemStr)) {
            throw new KeyException('not a public key');
        }
        /* @var false|array<string,int|array<string,string>> */
        if (false === $keyInfo = \openssl_pkey_get_details($publicKey)) {
            throw new KeyException('unable to get key information');
        }
        if (!\array_key_exists('type', $keyInfo) || OPENSSL_KEYTYPE_RSA !== $keyInfo['type']) {
            throw new KeyException('not an RSA key');
        }
        $this->publicKey = $publicKey;
        $this->pemStr = $pemStr;
    }

    /**
     * Create a new PublicKey object from file.
     *
     * @param string $fileName
     *
     * @throws \RuntimeException
     *
     * @return self
     */
    public static function fromFile($fileName)
    {
        if (false === $fileData = @\file_get_contents($fileName)) {
            throw new RuntimeException(\sprintf('unable to read key file "%s"', $fileName));
        }

        return new self($fileData);
    }

    /**
     * @param string $encodedString
     *
     * @return self
     */
    public static function fromEncodedString($encodedString)
    {
        $encodedString = \str_replace([' ', "\t", "\n", "\r", "\0", "\x0B"], '', $encodedString);

        return new self("-----BEGIN CERTIFICATE-----\n".\chunk_split($encodedString, 64, "\n").'-----END CERTIFICATE-----');
    }

    /**
     * @return string
     */
    public function toEncodedString()
    {
        $withoutHeaderFooter = \preg_replace(
            '/.*-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----.*/msU',
            '$1',
            $this->pemStr
        );

        if (null === $withoutHeaderFooter) {
            throw new RuntimeException('unable to strip header/footer from PEM certificate');
        }

        return \str_replace(
            [' ', "\t", "\n", "\r", "\0", "\x0B"],
            '',
            $withoutHeaderFooter
        );
    }

    /**
     * @return resource
     */
    public function raw()
    {
        return $this->publicKey;
    }
}
