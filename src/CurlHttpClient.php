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

use fkooman\SAML\SP\Exception\HttpClientException;
use RuntimeException;

class CurlHttpClient implements HttpClientInterface
{
    /**
     * @param string        $requestUrl
     * @param array<string> $requestHeaders
     *
     * @return HttpClientResponse
     */
    public function get($requestUrl, array $requestHeaders)
    {
        if (false === $curlChannel = \curl_init()) {
            throw new RuntimeException('unable to create cURL channel');
        }

        $headerList = '';
        $curlOptions = [
            CURLOPT_URL => $requestUrl,
            CURLOPT_HTTPHEADER => $requestHeaders,
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true, // follow redirects
            CURLOPT_MAXREDIRS => 3,         // follow up to 3 redirects
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 90,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HEADERFUNCTION =>
            /**
             * @suppress PhanUnusedClosureParameter
             *
             * @param resource $curlChannel
             * @param string   $headerLine
             *
             * @return int
             */
            function ($curlChannel, $headerLine) use (&$headerList) {
                $headerList .= $headerLine;

                return \strlen($headerLine);
            },
        ];

        if (false === \curl_setopt_array($curlChannel, $curlOptions)) {
            throw new RuntimeException('unable to set cURL options');
        }

        $responseData = \curl_exec($curlChannel);
        if (!\is_string($responseData)) {
            throw new HttpClientException(\sprintf('failure performing the HTTP request: "%s"', \curl_error($curlChannel)));
        }

        $responseCode = (int) \curl_getinfo($curlChannel, CURLINFO_HTTP_CODE);
        \curl_close($curlChannel);

        return new HttpClientResponse(
            $responseCode,
            $headerList,
            $responseData
        );
    }
}
