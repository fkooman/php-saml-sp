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
class MetadataSource implements IdpSourceInterface
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
     * @return array<IdpInfo>
     */
    public function getAll()
    {
        $idpInfoList = [];
        foreach ($this->metadataDirList as $metadataDir) {
            if (!@\file_exists($metadataDir) || !@\is_dir($metadataDir)) {
                // does not exist, or is not a folder
                continue;
            }

            if (false === $metadataFileList = \glob($metadataDir.'/*.xml')) {
                throw new RuntimeException(\sprintf('unable to list files in directory "%s"', $metadataDir));
            }
            foreach ($metadataFileList as $metadataFile) {
                if (false === $xmlData = @\file_get_contents($metadataFile)) {
                    throw new RuntimeException(\sprintf('unable to read "%s"', $metadataFile));
                }

                $xmlDocument = XmlDocument::fromMetadata($xmlData, false);
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
                    $idpInfoList[] = IdpInfo::fromXml($entityDocument->saveXML());
                }
            }
        }

        return $idpInfoList;
    }

    /**
     * @param string $entityId
     *
     * @return IdpInfo|null
     */
    public function get($entityId)
    {
        foreach ($this->metadataDirList as $metadataDir) {
            if (!@\file_exists($metadataDir) || !\is_dir($metadataDir)) {
                // does not exist, or is not a folder
                continue;
            }

            if (false === $metadataFileList = \glob($metadataDir.'/*.xml')) {
                throw new RuntimeException(\sprintf('unable to list files in directory "%s"', $metadataDir));
            }
            foreach ($metadataFileList as $metadataFile) {
                if (false === $xmlData = @\file_get_contents($metadataFile)) {
                    throw new RuntimeException(\sprintf('unable to read "%s"', $metadataFile));
                }

                $xmlDocument = XmlDocument::fromMetadata($xmlData, false);
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

                $entityDescriptorDomElement = XmlDocument::requireDomElement($entityDescriptorDomNodeList->item(0));
                $idpSsoDescriptorDomNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('md:IDPSSODescriptor', $entityDescriptorDomElement));
                if (0 === $idpSsoDescriptorDomNodeList->length) {
                    // not an IdP
                    continue;
                }

                // we need to create a new document in order to take the
                // namespaces with us. Simply doing saveXML() on
                // EntityDescriptor DomElement will not take (all) namespace
                // declarations...
                $entityDocument = new DOMDocument('1.0', 'UTF-8');
                $entityDocument->appendChild($entityDocument->importNode($entityDescriptorDomElement, true));

                return IdpInfo::fromXml($entityDocument->saveXML());
            }
        }

        return null;
    }

    /**
     * @param string           $metadataFile
     * @param array<PublicKey> $publicKeyList
     *
     * @return void
     */
    public static function validateMetadataFile($metadataFile, array $publicKeyList)
    {
        if (0 === \count($publicKeyList)) {
            throw new MetadataSourceException('need at least one PublicKey to verify metadata');
        }
        if (false === $metadataStr = @\file_get_contents($metadataFile)) {
            throw new MetadataSourceException(\sprintf('unable to read "%s"', $metadataFile));
        }

        // read metadata file and validate its XML schema
        $xmlDocument = XmlDocument::fromMetadata($metadataStr, true);
        // XXX make sure "/*" can only match either EntityDescriptor or
        // EntitiesDescriptor...
        $rootDomElement = XmlDocument::requireDomElement(
            XmlDocument::requireDomNodeList(
                $xmlDocument->domXPath->query('/*')
            )->item(0)
        );
        Crypto::verifyXml($xmlDocument, $rootDomElement, $publicKeyList);
    }
}
