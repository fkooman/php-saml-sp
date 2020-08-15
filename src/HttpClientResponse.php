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

class HttpClientResponse
{
    /** @var int */
    private $responseCode;

    /** @var array<string> */
    private $headerList;

    /** @var string */
    private $responseBody;

    /**
     * @param int           $responseCode
     * @param array<string> $headerList
     * @param string        $responseBody
     */
    public function __construct($responseCode, array $headerList, $responseBody)
    {
        $this->responseCode = $responseCode;
        $this->headerList = $headerList;
        $this->responseBody = $responseBody;
    }

    /**
     * @return int
     */
    public function getCode()
    {
        return $this->responseCode;
    }

    /**
     * We loop over all available headers and return the value of the first
     * matching header key. If multiple headers with the same name are present
     * the next ones are ignored!
     *
     * @param string $headerKey
     *
     * @return string|null
     */
    public function getHeader($headerKey)
    {
        foreach ($this->headerList as $headerLine) {
            if (false === \strpos($headerLine, ':')) {
                continue;
            }
            list($k, $v) = \explode(':', $headerLine, 2);
            if (\strtolower(\trim($headerKey)) === \strtolower(\trim($k))) {
                return \trim($v);
            }
        }

        return null;
    }

    /**
     * @return string
     */
    public function getBody()
    {
        return $this->responseBody;
    }
}
