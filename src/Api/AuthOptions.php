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

namespace fkooman\SAML\SP\Api;

class AuthOptions
{
    /** @var array<string> */
    private $authnContextClassRef = [];

    /** @var string */
    private $returnTo;

    /**
     * @param string $returnTo
     */
    public function __construct($returnTo)
    {
        $this->returnTo = $returnTo;
    }

    /**
     * @param string $returnTo
     *
     * @return self
     */
    public static function init($returnTo)
    {
        return new self($returnTo);
    }

    /**
     * @param array<string> $authnContextClassRef
     *
     * @return self
     */
    public function setAuthnContextClassRef(array $authnContextClassRef)
    {
        $this->authnContextClassRef = $authnContextClassRef;

        return $this;
    }

    /**
     * @return array<string>
     */
    public function getAuthnContextClassRef()
    {
        return $this->authnContextClassRef;
    }

    /**
     * @return string
     */
    public function getReturnTo()
    {
        return $this->returnTo;
    }
}
