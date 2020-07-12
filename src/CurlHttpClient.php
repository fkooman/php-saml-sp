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

use RuntimeException;

class CurlHttpClient
{
    /**
     * @param string $requestUrl
     *
     * @return string
     */
    public static function get($requestUrl)
    {
        if (false === $curlChannel = \curl_init()) {
            throw new RuntimeException('unable to create cURL channel');
        }

        $curlOptions = [
            CURLOPT_URL => $requestUrl,
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ];

        if (false === \curl_setopt_array($curlChannel, $curlOptions)) {
            throw new RuntimeException('unable to set cURL options');
        }

        $responseData = \curl_exec($curlChannel);
        if (!\is_string($responseData)) {
            throw new RuntimeException(\sprintf('failure performing the HTTP request: "%s"', \curl_error($curlChannel)));
        }

        \curl_close($curlChannel);

        return $responseData;
    }
}
