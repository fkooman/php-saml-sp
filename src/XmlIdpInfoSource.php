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

use DOMDOcument;
use fkooman\SAML\SP\Exception\XmlIdpInfoException;
use RuntimeException;

class XmlIdpInfoSource implements IdpInfoSourceInterface
{
    /** @var array<XmlDocument> */
    private $xmlDocumentList = [];

    /**
     * @param array<string> $metadataFileList
     * @param bool          $validateSchema
     *
     * @throws \RuntimeException
     */
    public function __construct(array $metadataFileList, $validateSchema = true)
    {
        foreach ($metadataFileList as $metadataFile) {
            if (false === $xmlData = \file_get_contents($metadataFile)) {
                throw new RuntimeException(\sprintf('unable to read file "%s"', $metadataFile));
            }

            $this->xmlDocumentList[] = XmlDocument::fromMetadata($xmlData, $validateSchema);
        }
    }

    /**
     * Get XML of IdP.
     *
     * @param string $entityId
     *
     * @return string|null
     */
    public function getXml($entityId)
    {
        self::validateEntityId($entityId);
        foreach ($this->xmlDocumentList as $xmlDocument) {
            $entityDescriptorDomNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query(\sprintf('//md:EntityDescriptor[@entityID="%s"]', $entityId)));
            if (1 !== $entityDescriptorDomNodeList->length) {
                continue;
            }
            $entityDescriptorDomElement = XmlDocument::requireDomElement($entityDescriptorDomNodeList->item(0));
            // XXX this probably can be implemented in 1 query with parent() call or similar
            $idpEntityDescriptorDomElement = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('md:IDPSSODescriptor', $entityDescriptorDomElement));
            if (1 !== $idpEntityDescriptorDomElement->length) {
                continue;
            }

            // we want to create a self-contained XML document that references
            // all the namespaces. Doing this by directly calling saveXML does
            // not work in all cases
            $entityDocument = new DOMDocument('1.0', 'UTF-8');
            $entityDocument->appendChild($entityDocument->importNode($entityDescriptorDomElement, true));

            return $entityDocument->saveXML();
        }

        return null;
    }

    /**
     * Get IdP information for an IdP.
     *
     * @param string $entityId
     *
     * @return IdpInfo|null
     */
    public function get($entityId)
    {
        self::validateEntityId($entityId);
        if (null === $idpXml = $this->getXml($entityId)) {
            return null;
        }

        return IdpInfo::fromXml($entityId, $idpXml);
    }

    /**
     * @param string $entityId
     *
     * @return void
     */
    private static function validateEntityId($entityId)
    {
        // we took all IdP entityID entries from eduGAIN metadata and made sure
        // the filter accepts all of those... anything outside this range is
        // probably not a valid xsd:anyURI anyway... this may need tweaking in
        // the future...
        //
        // Maybe it is enough to allow everything, except DQUOTE (")?
        if (1 !== \preg_match('|^[0-9a-zA-Z-./:=_?]+$|', $entityId)) {
            throw new XmlIdpInfoException('invalid entityID');
        }
    }
}
