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

namespace fkooman\SAML\SP\Tests;

use fkooman\SAML\SP\Exception\HttpClientException;
use fkooman\SAML\SP\HttpClientInterface;
use fkooman\SAML\SP\HttpClientResponse;

class TestHttpClient implements HttpClientInterface
{
    /** @var array<string,string> */
    private $urlFileMapping;

    public function __construct(array $urlFileMapping)
    {
        $this->urlFileMapping = $urlFileMapping;
    }

    /**
     * @param string        $requestUrl
     * @param array<string> $requestHeaders
     *
     * @return HttpClientResponse
     */
    public function get($requestUrl, array $requestHeaders)
    {
        if (\array_key_exists($requestUrl, $this->urlFileMapping)) {
            return new HttpClientResponse(
                200,
                "Last-Modified: Tue, 28 Jul 2020 20:26:55 GMT\r\n\r\n",
                $this->urlFileMapping[$requestUrl]
            );
        }

        throw new HttpClientException(\sprintf('URL "%s" not configured', $requestUrl));
    }
}
