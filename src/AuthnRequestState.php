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

/**
 * Keep track of the state of the AuthnRequest.
 */
class AuthnRequestState
{
    /** @var string */
    private $requestId;

    /** @var string */
    private $idpEntityId;

    /** @var array<string> */
    private $authnContextClassRef;

    /** @var string */
    private $returnTo;

    /**
     * @param string        $requestId
     * @param string        $idpEntityId
     * @param array<string> $authnContextClassRef
     * @param string        $returnTo
     */
    public function __construct($requestId, $idpEntityId, array $authnContextClassRef, $returnTo)
    {
        $this->requestId = $requestId;
        $this->idpEntityId = $idpEntityId;
        $this->authnContextClassRef = $authnContextClassRef;
        $this->returnTo = $returnTo;
    }

    /**
     * @return string
     */
    public function getRequestId()
    {
        return $this->requestId;
    }

    /**
     * @return string
     */
    public function getIdpEntityId()
    {
        return $this->idpEntityId;
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
