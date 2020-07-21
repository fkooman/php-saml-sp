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

use RangeException;
use RuntimeException;

class Utils
{
    /**
     * @param string $inputStr
     *
     * @return string
     */
    public static function encodeBase64($inputStr)
    {
        if (\function_exists('sodium_bin2base64')) {
            return \sodium_bin2base64($inputStr, SODIUM_BASE64_VARIANT_ORIGINAL);
        }

        return \base64_encode($inputStr);
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    public static function encodeBase64UrlSafe($inputStr)
    {
        if (\function_exists('sodium_bin2base64')) {
            return \sodium_bin2base64($inputStr, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        }

        return \rtrim(
            \str_replace(
                ['+', '/'],
                ['-', '_'],
                \base64_encode($inputStr)
            ),
            '='
        );
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    public static function decodeBase64($inputStr)
    {
        if (\function_exists('sodium_base642bin')) {
            return \sodium_base642bin($inputStr, SODIUM_BASE64_VARIANT_ORIGINAL);
        }

        if (false === $decodedStr = \base64_decode($inputStr, true)) {
            throw new RangeException('unable to decode Base64 string');
        }

        return $decodedStr;
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    public static function encodeHex($inputStr)
    {
        if (\function_exists('sodium_bin2hex')) {
            return \sodium_bin2hex($inputStr);
        }

        return \bin2hex($inputStr);
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    public static function decodeHex($inputStr)
    {
        if (\function_exists('sodium_hex2bin')) {
            return \sodium_hex2bin($inputStr);
        }

        if (false === $decodedStr = \hex2bin($inputStr)) {
            throw new RangeException('unable to decode Hex string');
        }

        return $decodedStr;
    }

    /**
     * @param string $inputStr
     *
     * @return int
     */
    public static function binaryStrlen($inputStr)
    {
        if (false === $strLen = \mb_strlen($inputStr, '8bit')) {
            throw new RuntimeException('unable to determine length of string');
        }

        return $strLen;
    }

    /**
     * @param string   $str
     * @param int      $start
     * @param int|null $length
     *
     * @return string
     */
    public static function binarySubstr($str, $start = 0, $length = null)
    {
        // on PHP >= 5.4.8 we don't have weird '' result when $length is null
        // @see https://github.com/php/php-src/pull/133
        if (false === $subStr = \mb_substr($str, $start, $length, '8bit')) {
            throw new RuntimeException('unable to extract part of string');
        }

        return $subStr;
    }
}
