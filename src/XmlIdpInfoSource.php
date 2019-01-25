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

use DOMElement;
use fkooman\SAML\SP\Exception\XmlIdpInfoSourceException;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var XmlDocument */
    private $xmlDocument;

    /**
     * @param string $metadataFile
     */
    public function __construct($metadataFile)
    {
        // XXX make sure we can read the file
        $this->xmlDocument = XmlDocument::fromMetadata(
            \file_get_contents($metadataFile),
            // do NOT validate the schema
            false
        );
    }

    /**
     * @param string $entityId
     *
     * @return false|IdpInfo
     */
    public function get($entityId)
    {
        $xPathQuery = \sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor', $entityId);
        $domNodeList = $this->xmlDocument->domXPath->query($xPathQuery);
        if (0 === $domNodeList->length) {
            // IdP not found
            return false;
        }
        if (1 !== $domNodeList->length) {
            // IdP found more than once?
            throw new XmlIdpInfoSourceException(\sprintf('IdP "%s" found more than once', $entityId));
        }
        $domElement = $domNodeList->item(0);
        if (!($domElement instanceof DOMElement)) {
            throw new XmlIdpInfoSourceException(\sprintf('element "%s" is not an element', $xPathQuery));
        }

        return new IdpInfo(
            $entityId,
            $this->getSingleSignOnService($domElement),
            $this->getPublicKey($domElement)
        );
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return string
     */
    private function getSingleSignOnService(DOMElement $domElement)
    {
        // what happens if there is more than one element that matches this?
        return $this->xmlDocument->domXPath->evaluate('string(md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location)', $domElement);
    }

    /**
     * @param \DOMElement $domElement
     *
     * @return array<PublicKey>
     */
    private function getPublicKey(DOMElement $domElement)
    {
        $publicKeys = [];
        $domNodeList = $this->xmlDocument->domXPath->query('md:KeyDescriptor[not(@use) or @use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $domElement);
        if (0 === $domNodeList->length) {
            throw new XmlIdpInfoSourceException('entry MUST have at least one X509Certificate');
        }
        for ($i = 0; $i < $domNodeList->length; ++$i) {
            $certificateNode = $domNodeList->item($i);
            if (null !== $certificateNode) {
                $publicKeys[] = PublicKey::fromEncodedString($certificateNode->textContent);
            }
        }

        return $publicKeys;
    }
}
