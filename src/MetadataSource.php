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
use fkooman\SAML\SP\Exception\MetadataSourceException;
use RuntimeException;

/**
 * This class parses (federation) SAML Metadata files and allows extracting the
 * XML for a particular entity.
 */
class MetadataSource implements SourceInterface
{
    /** @var array<string> */
    private $metadataDirList = [];

    /**
     * @param array<string> $metadataDirList
     */
    public function __construct(array $metadataDirList)
    {
        $this->metadataDirList = $metadataDirList;
    }

    /**
     * Get SAML metadata for all entities.
     *
     * @return array<string>
     */
    public function getAll()
    {
        $xmlStringList = [];
        foreach ($this->metadataDirList as $metadataDir) {
            if (!@\file_exists($metadataDir) || !@\is_dir($metadataDir)) {
                // do not exist, or is not a folder
                continue;
            }

            if (false === $metadataFileList = \glob($metadataDir.'/*.xml')) {
                throw new RuntimeException(\sprintf('unable to list files in directory "%s"', $metadataDir));
            }
            foreach ($metadataFileList as $metadataFile) {
                if (false === $xmlData = @\file_get_contents($metadataFile)) {
                    throw new RuntimeException(\sprintf('unable to read "%s"', $metadataFile));
                }

                $xmlDocument = XmlDocument::fromMetadata($xmlData, true);
                $entityDescriptorDomNodeList = XmlDocument::requireDomNodeList(
                    $xmlDocument->domXPath->query(
                        // we use "//" because "EntityDescriptor" could be in
                        // the root of the XML document, or inside a (nested)
                        // "EntitiesDescriptor"
                        '//md:EntityDescriptor'
                    )
                );

                foreach ($entityDescriptorDomNodeList as $entityDescriptorDomNode) {
                    $entityDescriptorDomElement = XmlDocument::requireDomElement($entityDescriptorDomNode);
                    $idpSsoDescriptorDomNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('md:IDPSSODescriptor', $entityDescriptorDomElement));
                    if (0 === $idpSsoDescriptorDomNodeList->length) {
                        // not an IdP
                        continue;
                    }

                    // we need to create a new document in order to take the
                    // namespaces with us. Simply doing saveXML() on
                    // $entityDescriptorDomElement will not retain (all)
                    // namespace declarations...
                    $entityDocument = new DOMDocument('1.0', 'UTF-8');
                    $entityDocument->appendChild($entityDocument->importNode($entityDescriptorDomElement, true));
                    $xmlStringList[] = $entityDocument->saveXML();
                }
            }
        }

        return $xmlStringList;
    }

    /**
     * Get SAML metadata.
     *
     * @param string $entityId
     *
     * @return string|null
     */
    public function get($entityId)
    {
        $entityXml = null;
        foreach ($this->metadataDirList as $metadataDir) {
            if (!@\file_exists($metadataDir) || !\is_dir($metadataDir)) {
                // do not exist, or is not a folder
                continue;
            }

            if (false === $metadataFileList = \glob($metadataDir.'/*.xml')) {
                throw new RuntimeException(\sprintf('unable to list files in directory "%s"', $metadataDir));
            }
            foreach ($metadataFileList as $metadataFile) {
                if (false === $xmlData = @\file_get_contents($metadataFile)) {
                    throw new RuntimeException(\sprintf('unable to read "%s"', $metadataFile));
                }

                $xmlDocument = XmlDocument::fromMetadata($xmlData, true);
                $entityDescriptorDomNodeList = XmlDocument::requireDomNodeList(
                    $xmlDocument->domXPath->query(
                        // we use "//" because "EntityDescriptor" could be in
                        // the root of the XML document, or inside a (nested)
                        // "EntitiesDescriptor"
                        \sprintf('//md:EntityDescriptor[@entityID="%s"]', $entityId)
                    )
                );

                if (0 === $entityDescriptorDomNodeList->length) {
                    // no EntityDescriptor found with this entityID
                    continue;
                }

                if (1 < $entityDescriptorDomNodeList->length) {
                    // more than one EntityDescriptor found with this entityID
                    throw new MetadataSourceException(\sprintf('found >= 1 EntityDescriptor with entityID "%s" in "%s"', $entityId, $metadataFile));
                }

                $entityDescriptorDomElement = XmlDocument::requireDomElement($entityDescriptorDomNodeList->item(0));
                $idpSsoDescriptorDomNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('md:IDPSSODescriptor', $entityDescriptorDomElement));
                if (0 === $idpSsoDescriptorDomNodeList->length) {
                    // not an IdP
                    continue;
                }

                if (null !== $entityXml) {
                    // we already found an EntityDescriptor with this entityID
                    // in one of the metadata files...
                    throw new MetadataSourceException(\sprintf('duplicate entityID "%s", contained in multiple metadata files', $entityId));
                }

                // we need to create a new document in order to take the
                // namespaces with us. Simply doing saveXML() on
                // EntityDescriptor DomElement will not take (all) namespace
                // declarations...
                $entityDocument = new DOMDocument('1.0', 'UTF-8');
                $entityDocument->appendChild($entityDocument->importNode($entityDescriptorDomElement, true));

                $entityXml = $entityDocument->saveXML();
            }
        }

        return $entityXml;
    }
}
