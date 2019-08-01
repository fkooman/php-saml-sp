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

use fkooman\SAML\SP\Exception\QueryParametersException;

/**
 * Ability to handle "raw" HTTP query string.
 *
 * We need to use the *exact* values as used in the HTTP query string for
 * HTTP-Redirect signature verification before they are URL-decoded by PHP.
 * Some implementations, e.g. Microsoft use upper-case URL encoding instead of
 * the more typical lower case encoding which exposed a bug in the code that
 * assumed everyone would be using lower-case encoding. The specification is
 * quite clear about how to implement it. Doesn't make it a good specification
 * though!
 *
 * @see saml-bindings-2.0-os (3.4.4.1 DEFLATE Encoding)
 */
class QueryParameters
{
    /** @var array<string,string> */
    private $queryData = [];

    /**
     * @param string $queryString
     */
    public function __construct($queryString)
    {
        foreach (\explode('&', $queryString) as $queryElement) {
            if ('' !== $queryElement) {
                if (false === \strpos($queryElement, '=')) {
                    $this->queryData[$queryElement] = '';
                    continue;
                }
                list($k, $v) = \explode('=', $queryElement, 2);
                $this->queryData[$k] = $v;
            }
        }
    }

    /**
     * @param string $parameterName
     * @param bool   $rawValue
     *
     * @throws \fkooman\SAML\SP\Exception\QueryParametersException
     *
     * @return string
     */
    public function requireQueryParameter($parameterName, $rawValue = false)
    {
        if (null === $parameterValue = $this->optionalQueryParameter($parameterName, $rawValue)) {
            throw new QueryParametersException(\sprintf('query parameter "%s" missing', $parameterName));
        }

        return $parameterValue;
    }

    /**
     * @param string $parameterName
     * @param bool   $rawValue
     *
     * @return string|null
     */
    public function optionalQueryParameter($parameterName, $rawValue = false)
    {
        if (!\array_key_exists($parameterName, $this->queryData)) {
            return null;
        }

        return $rawValue ? $this->queryData[$parameterName] : \urldecode($this->queryData[$parameterName]);
    }
}
