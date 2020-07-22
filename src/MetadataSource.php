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
use fkooman\SAML\SP\Exception\CryptoException;
use fkooman\SAML\SP\Exception\HttpClientException;
use fkooman\SAML\SP\Exception\XmlDocumentException;
use fkooman\SAML\SP\Log\LoggerInterface;
use RuntimeException;

/**
 * This class parses (federation) SAML Metadata files and allows extracting the
 * XML for a particular entity.
 */
class MetadataSource implements IdpSourceInterface
{
    /** @var string */
    const CACHE_DURATION_MARGIN = 'PT1H15M'; // 1h15m

    /** @var string */
    const DEFAULT_CACHE_DURATION = 'PT6H';   // 6h

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
        $idpInfoList = $this->getAllIdpInfo($entityId);
        // make sure we got our IdP
        if (!\array_key_exists($entityId, $idpInfoList)) {
            return null;
        }

        return $idpInfoList[$entityId];
    }

    /**
     * @return array<string,IdpInfo>
     */
    public function getAll()
    {
        return $this->getAllIdpInfo(null);
    }

    /**
     * Fetch the SAML metadata if it is about to expire, verify it and write it
     * to the dynamic directory.
     *
     * @param array<string,array<string>> $metadataUrlKeyList
     * @param bool                        $forceDownload
     *
     * @return void
     */
    public function importAllMetadata(HttpClientInterface $httpClient, array $metadataUrlKeyList, $forceDownload)
    {
        foreach ($metadataUrlKeyList as $metadataUrl => $publicKeyFileList) {
            try {
                $this->importMetadata($httpClient, $metadataUrl, $publicKeyFileList, $forceDownload);
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
     * @return bool
     */
    protected static function needsRefresh(DateTime $currentDateTime, DateTime $fileModifiedDateTime, DateInterval $cacheDuration)
    {
        /*
         * refreshing SAML metadata is tricky. The SAML metadata specification
         * mentions cacheDuration and validUntil as if they were related. They
         * are NOT, as more clearly documented in the errata document.
         *
         * We have a systemd timer running every hour with a RandomizedDelaySec
         * of 900, i.e. 15 minutes. We MUST make sure we refresh the metadata
         * *at least* at the last run of the timer before the cacheDuration
         * expires. This means, when we run the timer and the cache is about
         * to expire in the next 1h15m we refresh it now...
         *
         * @see [4.3.1 Metadata Instance Caching] of
         *     https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
         * @see [E94: Discussion of metadata caching mixes in validity] of
         *     https://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.pdf
         */
        $refreshBefore = $fileModifiedDateTime->add($cacheDuration)->sub(new DateInterval(self::CACHE_DURATION_MARGIN));

        return self::dateTimeToTimestamp($currentDateTime) >= self::dateTimeToTimestamp($refreshBefore);
    }

    /**
     * @param string        $metadataUrl
     * @param array<string> $publicKeyFileList
     * @param bool          $forceDownload
     *
     * @return void
     */
    private function importMetadata(HttpClientInterface $httpClient, $metadataUrl, array $publicKeyFileList, $forceDownload)
    {
        $this->logger->notice(\sprintf('[%s] attempting to update metadata', $metadataUrl));
        $metadataFile = \sprintf('%s/%s.xml', $this->dynamicDir, Utils::encodeBase64UrlSafeNoPadding($metadataUrl));
        $requestHeaders = [];
        if (!$forceDownload) {
            if (false !== $metadataString = @\file_get_contents($metadataFile)) {
                // verify for existing metadata whether it requires a "refresh"
                $metadataDocument = XmlDocument::fromMetadata($metadataString, false);
                if (null === $cacheDuration = $metadataDocument->optionalOneDomAttrValue('self::node()/@cacheDuration')) {
                    $cacheDuration = self::DEFAULT_CACHE_DURATION;
                }
                if (false !== $filemTime = \filemtime($metadataFile)) {
                    $fileModifiedDateTime = new DateTime('@'.$filemTime);
                    if (!self::needsRefresh($this->dateTime, $fileModifiedDateTime, new DateInterval($cacheDuration))) {
                        // no need to refresh (yet)
                        $this->logger->notice(\sprintf('[%s] not time yet to refresh', $metadataUrl));

                        return;
                    }
                    // indicate the last time we tried to fetch the metadata
                    // through the If-Modified-Since header to avoid needless
                    // downloading and verification...
                    $requestHeaders[] = 'If-Modified-Since: '.$fileModifiedDateTime->format('D, d M Y H:i:s \G\M\T');
                }
            }
        }
        // either metadata does not yet exist, we forced new download, or the
        // metadata needs refreshing (cacheDuration)
        $this->logger->notice(\sprintf('[%s] fetching metadata', $metadataUrl));
        $httpClientResponse = $httpClient->get($metadataUrl, $requestHeaders);
        $responseCode = $httpClientResponse->getCode();
        if (304 === $responseCode) {
            // Not Modified
            $this->logger->notice(\sprintf('[%s] metadata not changed on the server, keeping current copy', $metadataUrl));
            // set filemTime to current time for future cacheDuration calculation
            \touch($metadataFile, self::dateTimeToTimestamp($this->dateTime));

            return;
        }

        if (200 !== $responseCode) {
            $this->logger->notice(\sprintf('[%s] unexpected HTTP response code "%d"', $metadataUrl, $responseCode));

            return;
        }
        $publicKeyList = [];
        foreach ($publicKeyFileList as $publicKeyFile) {
            $publicKeyList[] = PublicKey::fromFile($this->staticDir.'/keys/'.$publicKeyFile);
        }

        $this->logger->notice(\sprintf('[%s] validating metadata', $metadataUrl));
        self::validateMetadata($httpClientResponse->getBody(), $publicKeyList);
        if (false === $tmpFile = \tempnam(\sys_get_temp_dir(), 'php-saml-sp')) {
            throw new RuntimeException('unable to generate a temporary file');
        }
        if (false === @\file_put_contents($tmpFile, $httpClientResponse->getBody())) {
            throw new RuntimeException(\sprintf('unable to write "%s"', $tmpFile));
        }
        // write fresh metadata
        if (false === @\rename($tmpFile, $metadataFile)) {
            throw new RuntimeException(\sprintf('unable to move "%s" to "%s"', $tmpFile, $metadataFile));
        }

        // set filemTime to current time for future cacheDuration calculation
        \touch($metadataFile, self::dateTimeToTimestamp($this->dateTime));
        $this->logger->notice(\sprintf('[%s] OK, metadata written to "%s"', $metadataUrl, $metadataFile));
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
     * @return array<string,IdpInfo>
     */
    private function getAllIdpInfo($entityId)
    {
        $dirList = [
            'static' => $this->staticDir,
            'dynamic' => $this->dynamicDir,
        ];

        $idpInfoList = [];
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
                        if (self::dateTimeToTimestamp($this->dateTime) > self::dateTimeToTimestamp($validUntilDateTime)) {
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
                    $idpInfo = IdpInfo::fromXml(XmlDocument::domElementToString($domElement));
                    $idpInfoList[$idpInfo->getEntityId()] = $idpInfo;
                }
            }
        }

        return $idpInfoList;
    }

    /**
     * @return int
     */
    private static function dateTimeToTimestamp(DateTime $dateTime)
    {
        if (false === $timestamp = $dateTime->getTimestamp()) {
            return 0;
        }

        return $timestamp;
    }
}
