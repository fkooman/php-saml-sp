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

use DOMElement;
use fkooman\SAML\SP\Exception\NameIdException;

class NameId
{
    /** @var string */
    private $idpEntityId;

    /** @var string */
    private $spEntityId;

    /** @var string|null */
    private $nameIdFormat;

    /** @var string|null */
    private $nameQualifier;

    /** @var string|null */
    private $spNameQualifier;

    /** @var string */
    private $nameIdValue;

    /**
     * @param string $idpEntityId
     * @param string $spEntityId
     *
     * @throws \fkooman\SAML\SP\Exception\NameIdException
     */
    public function __construct($idpEntityId, $spEntityId, DOMElement $nameIdElement)
    {
        $nameQualifier = $nameIdElement->hasAttribute('NameQualifier') ? $nameIdElement->getAttribute('NameQualifier') : null;
        if (null !== $nameQualifier) {
            if ($idpEntityId !== $nameQualifier) {
                throw new NameIdException('"NameQualifier" does not match expected IdP entityID');
            }
        }

        $spNameQualifier = $nameIdElement->hasAttribute('SPNameQualifier') ? $nameIdElement->getAttribute('SPNameQualifier') : null;
        if (null !== $spNameQualifier) {
            if ($spEntityId !== $spNameQualifier) {
                throw new NameIdException('"SPNameQualifier" does not match expected SP entityID');
            }
        }

        $this->idpEntityId = $idpEntityId;
        $this->spEntityId = $spEntityId;
        $this->nameIdFormat = $nameIdElement->hasAttribute('Format') ? $nameIdElement->getAttribute('Format') : null;
        $this->nameQualifier = $nameQualifier;
        $this->spNameQualifier = $spNameQualifier;
        $this->nameIdValue = \trim($nameIdElement->textContent);
    }

    /**
     * Get NameID XML string. This SHOULD only be needed for logout (SLO).
     *
     * @return string
     */
    public function toXml()
    {
        $attributeList = [];
        if (null !== $this->nameQualifier) {
            $attributeList[] = \sprintf('NameQualifier="%s"', $this->nameQualifier);
        }
        if (null !== $this->spNameQualifier) {
            $attributeList[] = \sprintf('SPNameQualifier="%s"', $this->spNameQualifier);
        }
        if (null !== $this->nameIdFormat) {
            $attributeList[] = \sprintf('Format="%s"', $this->nameIdFormat);
        }

        return \sprintf(
            '<saml:NameID %s>%s</saml:NameID>',
            \implode(' ', $attributeList),
            $this->nameIdValue
        );
    }

    /**
     * Convert the NameID XML to string similar to Shibboleth SP. This SHOULD
     * only be used with "eduPersonTargetedID" attributes.
     *
     * @throws \fkooman\SAML\SP\Exception\NameIdException
     *
     * @return string
     */
    public function toUserId()
    {
        // this only makes sense when we have "persistent" NameID
        if ('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' !== $this->nameIdFormat) {
            // simpleSAMLphp has a bug where it does not (always) provide the
            // "NameFormat" attribute. The SAML specification says if it is not
            // specified it is
            // "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" which
            // is not a good when needing to determine the "persistent NameID".
            //
            // What we do here, is, if it is NOT specified (at all) we *assume*
            // it is meant to be persistent. If it *is* specified and it is NOT
            // persistent, we throw an error.
            //
            // @see https://github.com/simplesamlphp/simplesamlphp/issues/1135
            if (null !== $this->nameIdFormat) {
                throw new NameIdException('only NameID format "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" is supported for user identifiers');
            }
        }

        return \sprintf('%s!%s!%s', $this->idpEntityId, $this->spEntityId, $this->nameIdValue);
    }
}
