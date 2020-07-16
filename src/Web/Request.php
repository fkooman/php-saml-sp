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

namespace fkooman\SAML\SP\Web;

use fkooman\SAML\SP\Web\Exception\HttpException;

class Request
{
    /** @var array<string,mixed> */
    private $serverData;

    /** @var array<string,string|array<string>> */
    private $getData;

    /** @var array<string,string|array<string>> */
    private $postData;

    /**
     * @param array<string,mixed>                $serverData
     * @param array<string,string|array<string>> $getData
     * @param array<string,string|array<string>> $postData
     */
    public function __construct(array $serverData, array $getData = [], array $postData = [])
    {
        $this->serverData = $serverData;
        $this->getData = $getData;
        $this->postData = $postData;
    }

    /**
     * @return string
     */
    public function getRequestMethod()
    {
        return $this->requireHeader('REQUEST_METHOD');
    }

    /**
     * @return string
     */
    public function getRootUri()
    {
        return \sprintf('%s://%s%s', $this->getScheme(), $this->getAuthority(), $this->getRoot());
    }

    /**
     * @return string
     */
    public function getUri()
    {
        return \sprintf('%s://%s%s', $this->getScheme(), $this->getAuthority(), $this->requireHeader('REQUEST_URI'));
    }

    /**
     * @return string
     */
    public function getOrigin()
    {
        return \sprintf('%s://%s', $this->getScheme(), $this->getAuthority());
    }

    /**
     * @return string
     */
    public function getPathInfo()
    {
        // remove the query string
        $requestUri = $this->requireHeader('REQUEST_URI');
        if (false !== $pos = \strpos($requestUri, '?')) {
            $requestUri = \substr($requestUri, 0, $pos);
        }

        // if requestUri === scriptName
        $scriptName = $this->requireHeader('SCRIPT_NAME');
        if ($requestUri === $scriptName) {
            return '/';
        }

        // remove script_name (if it is part of request_uri
        if (0 === \strpos($requestUri, $scriptName)) {
            if (false === $pathInfo = \substr($requestUri, \strlen($scriptName))) {
                throw new HttpException(500, 'unable to remove SCRIPT_NAME');
            }

            return $pathInfo;
        }

        // remove the root
        if ('/' !== $this->getRoot()) {
            if (false === $pathInfo = \substr($requestUri, \strlen($this->getRoot()) - 1)) {
                throw new HttpException(500, 'unable to remove root');
            }

            return $pathInfo;
        }

        return $requestUri;
    }

    /**
     * Return the "raw" query string.
     *
     * @return string
     */
    public function getQueryString()
    {
        if (null === $queryString = $this->optionalHeader('QUERY_STRING')) {
            return '';
        }

        return $queryString;
    }

    /**
     * @param string $queryKey
     *
     * @return string
     */
    public function requireQueryParameter($queryKey)
    {
        if (!\array_key_exists($queryKey, $this->getData)) {
            throw new HttpException(400, \sprintf('missing query parameter "%s"', $queryKey));
        }
        $queryValue = $this->getData[$queryKey];
        if (!\is_string($queryValue)) {
            throw new HttpException(400, \sprintf('value of query parameter "%s" MUST be string', $queryKey));
        }

        return $queryValue;
    }

    /**
     * @param string $queryKey
     *
     * @return string|null
     */
    public function optionalQueryParameter($queryKey)
    {
        if (!\array_key_exists($queryKey, $this->getData)) {
            return null;
        }

        return $this->requireQueryParameter($queryKey);
    }

    /**
     * @param string $postKey
     *
     * @return string
     */
    public function requirePostParameter($postKey)
    {
        if (!\array_key_exists($postKey, $this->postData)) {
            throw new HttpException(400, \sprintf('missing post parameter "%s"', $postKey));
        }
        $postValue = $this->postData[$postKey];
        if (!\is_string($postValue)) {
            throw new HttpException(400, \sprintf('value of post parameter "%s" MUST be string', $postKey));
        }

        return $postValue;
    }

    /**
     * @param string $postKey
     *
     * @return string|null
     */
    public function optionalPostParameter($postKey)
    {
        if (!\array_key_exists($postKey, $this->postData)) {
            return null;
        }

        return $this->requirePostParameter($postKey);
    }

    /**
     * @param string $headerKey
     *
     * @return string
     */
    public function requireHeader($headerKey)
    {
        if (!\array_key_exists($headerKey, $this->serverData)) {
            throw new HttpException(400, \sprintf('missing request header "%s"', $headerKey));
        }

        if (!\is_string($this->serverData[$headerKey])) {
            throw new HttpException(400, \sprintf('value of request header "%s" MUST be string', $headerKey));
        }

        return $this->serverData[$headerKey];
    }

    /**
     * @param string $headerKey
     *
     * @return string|null
     */
    public function optionalHeader($headerKey)
    {
        if (!\array_key_exists($headerKey, $this->serverData)) {
            return null;
        }

        return $this->requireHeader($headerKey);
    }

    /**
     * @return string
     */
    private function getScheme()
    {
        if (null === $requestScheme = $this->optionalHeader('REQUEST_SCHEME')) {
            $requestScheme = 'http';
        }

        if (!\in_array($requestScheme, ['http', 'https'], true)) {
            throw new HttpException(400, 'unsupported "REQUEST_SCHEME"');
        }

        return $requestScheme;
    }

    /**
     * URI = scheme:[//authority]path[?query][#fragment]
     * authority = [userinfo@]host[:port].
     *
     * @see https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Generic_syntax
     *
     * @return string
     */
    private function getAuthority()
    {
        // we do not care about "userinfo"...
        $requestScheme = $this->getScheme();
        $serverName = $this->requireHeader('SERVER_NAME');
        $serverPort = (int) $this->requireHeader('SERVER_PORT');

        $usePort = false;
        if ('https' === $requestScheme && 443 !== $serverPort) {
            $usePort = true;
        }
        if ('http' === $requestScheme && 80 !== $serverPort) {
            $usePort = true;
        }

        if ($usePort) {
            return \sprintf('%s:%d', $serverName, $serverPort);
        }

        return $serverName;
    }

    /**
     * @return string
     */
    private function getRoot()
    {
        $rootDir = \dirname($this->requireHeader('SCRIPT_NAME'));
        if ('/' !== $rootDir) {
            return \sprintf('%s/', $rootDir);
        }

        return $rootDir;
    }
}
