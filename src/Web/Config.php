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

namespace fkooman\SAML\SP\Web;

use RuntimeException;

class Config
{
    /** @var string */
    const DEFAULT_SERVICE_NAME = 'SAML SP';

    /** @var string */
    const DEFAULT_LANGUAGE = 'en-US';

    /** @var array */
    private $configData;

    public function __construct(array $configData)
    {
        $this->configData = $configData;
    }

    /**
     * @return string
     */
    public function getDefaultLanguage()
    {
        if (null === $defaultLanguage = $this->get('defaultLanguage')) {
            return 'en-US';
        }

        return $defaultLanguage;
    }

    /**
     * @return array<string>
     */
    public function getEnabledLanguages()
    {
        if (null === $enabledLanguages = $this->get('enabledLanguages')) {
            return ['en-US'];
        }

        return $enabledLanguages;
    }

    /**
     * @return string|null
     */
    public function getEntityId()
    {
        return $this->get('entityId');
    }

    /**
     * @return bool
     */
    public function getRequireEncryption()
    {
        if (null === $requireEncryption = $this->get('requireEncryption')) {
            return false;
        }

        return $requireEncryption;
    }

    /**
     * @param string $configFile
     *
     * @return self
     */
    public static function fromFile($configFile)
    {
        if (!\file_exists($configFile) || !\is_readable($configFile)) {
            throw new RuntimeException('unable to read configuration file');
        }
        $configData = include $configFile;
        if (!\is_array($configData)) {
            throw new RuntimeException('invalid configuration file format');
        }

        return new self($configData);
    }

    /**
     * @return string|null
     */
    public function getDiscoUrl()
    {
        return $this->get('discoUrl');
    }

    /**
     * @return string|null
     */
    public function getStyleName()
    {
        return $this->get('styleName');
    }

    /**
     * @return array<string>
     */
    public function getIdpList()
    {
        if (null === $idpList = $this->get('idpList')) {
            return [];
        }

        return $idpList;
    }

    /**
     * @return bool
     */
    public function getSecureCookie()
    {
        if (null === $secureCookie = $this->get('secureCookie')) {
            return true;
        }

        return $secureCookie;
    }

    /**
     * @return string
     */
    public function getSpPath()
    {
        if (null === $spPath = $this->get('spPath')) {
            $spPath = '/php-saml-sp';
        }
        // remove trailing slash(es) from spPath iff necessary
        return \rtrim($spPath, '/');
    }

    /**
     * @param string|null $uiLanguage
     *
     * @return string
     */
    public function getServiceName($uiLanguage)
    {
        if (null === $serviceNameList = $this->get('serviceName')) {
            return self::DEFAULT_SERVICE_NAME;
        }

        if (null === $uiLanguage) {
            if (null === $uiLanguage = $this->get('defaultLanguage')) {
                return $this->getServiceName(self::DEFAULT_LANGUAGE);
            }
        }

        if (\array_key_exists($uiLanguage, $serviceNameList)) {
            return $serviceNameList[$uiLanguage];
        }

        return self::DEFAULT_LANGUAGE === $uiLanguage ? self::DEFAULT_SERVICE_NAME : $this->getServiceName(self::DEFAULT_LANGUAGE);
    }

    /**
     * @return array<string,string>
     */
    public function getServiceNames()
    {
        if (null === $serviceNameList = $this->get('serviceName')) {
            return [self::DEFAULT_LANGUAGE => self::DEFAULT_SERVICE_NAME];
        }

        return $serviceNameList;
    }

    /**
     * @return array<string,array<string>>
     */
    public function getMetadataList()
    {
        if (null === $metadataList = $this->get('metadataList')) {
            return [];
        }

        return $metadataList;
    }

    /**
     * @param string $k
     *
     * @return mixed
     */
    private function get($k)
    {
        if (!\array_key_exists($k, $this->configData)) {
            return null;
        }

        return $this->configData[$k];
    }
}
