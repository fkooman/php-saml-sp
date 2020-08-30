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

use fkooman\SAML\SP\Exception\CryptoException;

class CryptoParameters
{
    /**
     * @param string $encryptionMethod
     *
     * @return string
     */
    public static function getOpenSslAlgorithm($encryptionMethod)
    {
        switch ($encryptionMethod) {
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                return 'aes-128-gcm';
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                return 'aes-256-gcm';
            default:
                throw new CryptoException(\sprintf('algorithm "%s" not implemented', $encryptionMethod));
        }
    }

    /**
     * @param string $encryptionMethod
     *
     * @return int
     */
    public static function getIvLength($encryptionMethod)
    {
        switch ($encryptionMethod) {
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                return 12;
            default:
                throw new CryptoException(\sprintf('algorithm "%s" not implemented', $encryptionMethod));
        }
    }

    /**
     * @param string $encryptionMethod
     *
     * @return int
     */
    public static function getTagLength($encryptionMethod)
    {
        switch ($encryptionMethod) {
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                return 16;
            default:
                throw new CryptoException(\sprintf('algorithm "%s" not implemented', $encryptionMethod));
        }
    }

    /**
     * @param string $encryptionMethod
     *
     * @return int
     */
    public static function getKeyLength($encryptionMethod)
    {
        switch ($encryptionMethod) {
            case 'http://www.w3.org/2009/xmlenc11#aes128-gcm':
                return 16;
            case 'http://www.w3.org/2009/xmlenc11#aes256-gcm':
                return 32;
            default:
                throw new CryptoException(\sprintf('algorithm "%s" not implemented', $encryptionMethod));
        }
    }
}
