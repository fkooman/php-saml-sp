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
use DOMElement;
use fkooman\SAML\SP\Exception\CryptoException;
use fkooman\SAML\SP\Exception\HttpClientException;
use fkooman\SAML\SP\Exception\XmlDocumentException;
use fkooman\SAML\SP\Log\LoggerInterface;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

/**
 * This class parses (federation) SAML Metadata files and allows extracting the
 * XML for a particular entity.
 */
class MetadataSource implements IdpSourceInterface
{
    /** @var \DateTime */
    protected $dateTime;

    /** @var Log\LoggerInterface */
    private $logger;

    /** @var string */
    private $staticDir;

    /** @var string */
    private $dynamicDir;

    /**
     * @param string $staticDir
     * @param string $dynamicDir
     */
    public function __construct(LoggerInterface $logger, $staticDir, $dynamicDir)
    {
        $this->dateTime = new DateTime();
        $this->logger = $logger;
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
        // XXX we can remove this function now! as they do the same for both get and getAll cases!
        $this->foreachIdp(function (DOMElement $entityDescriptorDomElement) use (&$idpInfoList) {
            $idpInfoList[] = IdpInfo::fromXml(XmlDocument::domElementToString($entityDescriptorDomElement));
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
        // XXX we can remove this function now! as they do the same for both get and getAll cases!
        $this->foreachIdp(function (DOMElement $entityDescriptorDomElement) use (&$idpInfoList) {
            $idpInfo = IdpInfo::fromXml(XmlDocument::domElementToString($entityDescriptorDomElement));
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
    public function importAllMetadata(HttpClientInterface $httpClient, array $metadataUrlKeyList)
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
                $this->importMetadata($httpClient, $metadataUrl, $publicKeyFileList);
            } catch (CryptoException $e) {
                $this->logger->warning(\sprintf('unable to verify signature of metadata "%s": %s', $metadataUrl, $e->getMessage()));
            } catch (HttpClientException $e) {
                $this->logger->warning(\sprintf('unable to retrieve metadata from "%s": %s', $metadataUrl, $e->getMessage()));
            } catch (XmlDocumentException $e) {
                $this->logger->warning(\sprintf('unable to validate XML (schema) from "%s": %s', $metadataUrl, $e->getMessage()));
            }
        }
    }

    /**
     * @param string        $metadataUrl
     * @param array<string> $publicKeyFileList
     *
     * @return void
     */
    public function importMetadata(HttpClientInterface $httpClient, $metadataUrl, array $publicKeyFileList)
    {
        $metadataFile = \sprintf('%s/%s.xml', $this->dynamicDir, Base64UrlSafe::encode($metadataUrl));
        if (false !== $metadataString = @\file_get_contents($metadataFile)) {
            $metadataDocument = XmlDocument::fromMetadata($metadataString, false);
            if (null !== $validUntil = $metadataDocument->optionalOneDomAttrValue('self::node()/@validUntil')) {
                $validUntilDateTime = new DateTime($validUntil);
                $refreshThreshhold = clone $this->dateTime;
                $refreshThreshhold->add(new DateInterval('PT4H'));
                if ($refreshThreshhold->getTimestamp() < $validUntilDateTime->getTimestamp()) {
                    // still valid for a while, go to next URL
                    $this->logger->notice(\sprintf('metadata "%s" is recent enough', $metadataUrl));

                    return;
                }
            }
        }
        // either metadata does not yet exist, we didn't find validUntil,
        // or the metadata needs refreshing...
        $this->logger->notice(\sprintf('fetching metadata from "%s"', $metadataUrl));
        $freshMetadataString = $httpClient->get($metadataUrl);
        $publicKeyList = [];
        foreach ($publicKeyFileList as $publicKeyFile) {
            $publicKeyList[] = PublicKey::fromFile($this->staticDir.'/keys/'.$publicKeyFile);
        }

        self::validateMetadata($freshMetadataString, $publicKeyList);
        if (false === $tmpFile = \tempnam(\sys_get_temp_dir(), 'php-saml-sp')) {
            throw new RuntimeException('unable to generate a temporary file');
        }
        if (false === @\file_put_contents($tmpFile, $freshMetadataString)) {
            throw new RuntimeException(\sprintf('unable to write "%s"', $tmpFile));
        }
        // write fresh metadata
        if (false === @\rename($tmpFile, $metadataFile)) {
            throw new RuntimeException(\sprintf('unable to move "%s" to "%s"', $tmpFile, $metadataFile));
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
        Crypto::verifyXml($xmlDocument, $publicKeyList);
    }

    /**
     * @param string|null $entityId
     *
     * @return void
     */
    private function forEachIdP(callable $c, $entityId)
    {
        $dirList = [
            'static' => $this->staticDir,
            'dynamic' => $this->dynamicDir,
        ];

        foreach ($dirList as $dirType => $metadataDir) {
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

                $metadataDocument = XmlDocument::fromMetadata($xmlData, false);

                if ('dynamic' === $dirType) {
                    // for dynamic metadata ONLY, i.e. the one automatically
                    // periodically retrieved we check validUntil and make sure
                    // it is not in the past if it exists
                    if (null !== $validUntil = $metadataDocument->optionalOneDomAttrValue('self::node()/@validUntil')) {
                        $validUntilDateTime = new DateTime($validUntil);
                        if ($this->dateTime->getTimestamp() > $validUntilDateTime->getTimestamp()) {
                            $this->logger->warning(\sprintf('metadata file "%s" has "validUntil" in the past', $metadataFile));

                            continue;
                        }
                    }
                }

                // we use "//" because "EntityDescriptor" could be in
                // the root of the XML document, or inside a (nested)
                // "EntitiesDescriptor"
                $xPathQuery = null === $entityId ? '//md:EntityDescriptor/md:IDPSSODescriptor/parent::node()' : \sprintf('//md:EntityDescriptor[@entityID="%s"]/md:IDPSSODescriptor/parent::node()', $entityId);
                $domElementList = $metadataDocument->allDomElement($xPathQuery);
                foreach ($domElementList as $domElement) {
                    $c($domElement);
                }
            }
        }
    }
}
