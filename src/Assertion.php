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

use DateTime;

class Assertion
{
    /** @var string */
    private $issuer;

    /** @var NameId|null */
    private $nameId;

    /** @var \DateTime */
    private $authnInstant;

    /** @var \DateTime */
    private $sessionNotOnOrAfter;

    /** @var string */
    private $authnContext;

    /** @var string|null */
    private $authenticatingAuthority;

    /** @var array<string,array<string>> */
    private $attributeList;

    /**
     * @param string                      $issuer
     * @param string                      $authnContext
     * @param string|null                 $authenticatingAuthority
     * @param array<string,array<string>> $attributeList
     */
    public function __construct($issuer, DateTime $authnInstant, DateTime $sessionNotOnOrAfter, $authnContext, $authenticatingAuthority, array $attributeList)
    {
        $this->issuer = $issuer;
        $this->authnInstant = $authnInstant;
        $this->sessionNotOnOrAfter = $sessionNotOnOrAfter;
        $this->authnContext = $authnContext;
        $this->authenticatingAuthority = $authenticatingAuthority;
        $this->attributeList = $attributeList;
    }

    /**
     * @return string
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * @return void
     */
    public function setNameId(NameId $nameId)
    {
        $this->nameId = $nameId;
    }

    /**
     * @return NameId|null
     */
    public function getNameId()
    {
        return $this->nameId;
    }

    /**
     * @return \DateTime
     */
    public function getAuthnInstant()
    {
        return $this->authnInstant;
    }

    /**
     * @return \DateTime
     */
    public function getSessionNotOnOrAfter()
    {
        return $this->sessionNotOnOrAfter;
    }

    /**
     * @return string
     */
    public function getAuthnContext()
    {
        return $this->authnContext;
    }

    /**
     * @return string|null
     */
    public function getAuthenticatingAuthority()
    {
        return $this->authenticatingAuthority;
    }

    /**
     * @return array<string,array<string>>
     */
    public function getAttributes()
    {
        return $this->attributeList;
    }
}
