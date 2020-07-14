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

use DateInterval;
use DateTime;
use DOMDocument;
use DOMElement;
use fkooman\SAML\SP\Exception\CryptoException;
use fkooman\SAML\SP\Exception\HttpClientException;
use RuntimeException;

/**
 * This class parses (federation) SAML Metadata files and allows extracting the
 * XML for a particular entity.
 */
class MetadataSource implements IdpSourceInterface
{
    /** @var \DateTime */
    protected $dateTime;

    /** @var string */
    private $staticDir;

    /** @var string */
    private $dynamicDir;

    /**
     * @param string $staticDir
     * @param string $dynamicDir
     */
    public function __construct($staticDir, $dynamicDir)
    {
        $this->dateTime = new DateTime();
        $this->staticDir = $staticDir;
        if (false === @\file_exists($dynamicDir)) {
            if (false === @\mkdir($dynamicDir, 0711, true)) {
                throw new RuntimeException(\sprintf('unable to create "%s"', $dynamicDir));
            }
        }
        $this->dynamicDir = $dynamicDir;
    }

    /**
     * @param string $entityId
     *
     * @return IdpInfo|null
     */
    public function get($entityId)
    {
        $idpInfoList = [];
        $this->foreachIdp(function (DOMElement $entityDescriptorDomElement) use (&$idpInfoList) {
            $entityDocument = new DOMDocument('1.0', 'UTF-8');
            $entityDocument->appendChild($entityDocument->importNode($entityDescriptorDomElement, true));
            $idpInfoList[] = IdpInfo::fromXml($entityDocument->saveXML());
        }, $entityId);

        // we expect there to be only 1 result, but even if there are more we
        // simply return the first one...
        if (0 === \count($idpInfoList)) {
            return null;
        }

        return $idpInfoList[0];
    }

    /**
     * @return array<string,IdpInfo>
     */
    public function getAll()
    {
        $idpInfoList = [];
        $this->foreachIdp(function (DOMElement $entityDescriptorDomElement) use (&$idpInfoList) {
            $entityDocument = new DOMDocument('1.0', 'UTF-8');
            $entityDocument->appendChild($entityDocument->importNode($entityDescriptorDomElement, true));
            $idpInfo = IdpInfo::fromXml($entityDocument->saveXML());
            $idpInfoList[$idpInfo->getEntityId()] = $idpInfo;
        }, null);

        return $idpInfoList;
    }

    /**
     * Fetch the SAML metadata if it is about to expire, verify it and write it
     * to the dynamic directory.
     *
     * @param array<string,array<string>> $metadataUrlKeyList
     *
     * @return void
     */
    public function importMetadata(HttpClientInterface $httpClient, array $metadataUrlKeyList)
    {
        // Algorithm, for each URL in metadataUrlKeyList
        // 1. do we have the metadata file already locally?
        //    1a: YES: go to 2
        //    1b: NO: go to 3
        // 2. is validUntil approaching?
        //    2a: YES: go to 3
        //    2b: NO: next URL
        // 3. fetch URL
        // 4. verify the XML schema
        // 5. verify the signature
        // 6. write to disk
        foreach ($metadataUrlKeyList as $metadataUrl => $publicKeyFileList) {
            try {
                $metadataFile = \sprintf('%s/%s.xml', $this->dynamicDir, \base64_encode($metadataUrl));
                if (false !== $metadataString = @\file_get_contents($metadataFile)) {
                    $xmlDocument = XmlDocument::fromMetadata($metadataString, false);
                    $rootDomElement = XmlDocument::requireDomElement(
                        XmlDocument::requireDomNodeList(
                            $xmlDocument->domXPath->query('/*')
                        )->item(0)
                    );
                    $validUntil = $rootDomElement->getAttribute('validUntil');
                    if ('' !== $validUntil) {
                        // XXX write a proper test for this!
                        $validUntilDateTime = new DateTime($validUntil);
                        $refreshThreshhold = \date_add(clone $this->dateTime, new DateInterval('PT4H'));
                        if ($refreshThreshhold->getTimestamp() < $validUntilDateTime->getTimestamp()) {
                            // still valid for a while, go to next URL
                            continue;
                        }
                    }
                }
                // either metadata does not yet exist, we didn't find validUntil,
                // or the metadata needs refreshing...
                $freshMetadataString = $httpClient->get($metadataUrl);
                $publicKeyList = [];
                foreach ($publicKeyFileList as $publicKeyFile) {
                    $publicKeyList[] = PublicKey::fromFile($this->staticDir.'/keys/'.$publicKeyFile);
                }

                self::validateMetadata($freshMetadataString, $publicKeyList);
                $tmpFile = \tempnam(\sys_get_temp_dir(), 'php-saml-sp');
                if (false === @\file_put_contents($tmpFile, $freshMetadataString)) {
                    throw new RuntimeException(\sprintf('unable to write "%s"', $tmpFile));
                }
                // write fresh metadata
                if (false === @\rename($tmpFile, $metadataFile)) {
                    throw new RuntimeException(\sprintf('unable to mvoe "%s" to "%s"', $tmpFile, $metadataFile));
                }
            } catch (CryptoException $e) {
                // unable to verify signature, go to next entry, but log it
                // XXX implement logging
            } catch (HttpClientException $e) {
                // unable to retrieve new metadata, go to next entry, but log
                // it
                // XXX implement logging
            }
        }
    }

    /**
     * @param string           $metadataString
     * @param array<PublicKey> $publicKeyList
     *
     * @return void
     */
    private static function validateMetadata($metadataString, array $publicKeyList)
    {
        // read metadata file and validate its XML schema
        $xmlDocument = XmlDocument::fromMetadata($metadataString, true);
        // XXX make sure "/*" can only match either EntityDescriptor or
        // EntitiesDescriptor...
        $rootDomElement = XmlDocument::requireDomElement(
            XmlDocument::requireDomNodeList(
                $xmlDocument->domXPath->query('/*')
            )->item(0)
        );
        Crypto::verifyXml($xmlDocument, $rootDomElement, $publicKeyList);
    }

    /**
     * @param string|null $entityId
     *
     * @return void
     */
    private function forEachIdP(callable $c, $entityId)
    {
        foreach ([$this->staticDir, $this->dynamicDir] as $metadataDir) {
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

                // we use "//" because "EntityDescriptor" could be in
                // the root of the XML document, or inside a (nested)
                // "EntitiesDescriptor"
                $xPathQuery = null === $entityId ? '//md:EntityDescriptor' : \sprintf('//md:EntityDescriptor[@entityID="%s"]', $entityId);

                $entityDescriptorDomNodeList = XmlDocument::requireDomNodeList(
                    $xmlDocument->domXPath->query($xPathQuery)
                );

                foreach ($entityDescriptorDomNodeList as $entityDescriptorDomNode) {
                    $entityDescriptorDomElement = XmlDocument::requireDomElement($entityDescriptorDomNode);
                    $idpSsoDescriptorDomNodeList = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('md:IDPSSODescriptor', $entityDescriptorDomElement));
                    if (0 === $idpSsoDescriptorDomNodeList->length) {
                        // not an IdP
                        continue;
                    }

                    $c($entityDescriptorDomElement);
                }
            }
        }
    }
}
