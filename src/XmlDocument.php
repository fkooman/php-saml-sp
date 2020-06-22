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

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use fkooman\SAML\SP\Exception\XmlDocumentException;

class XmlDocument
{
    /** @var \DOMDocument */
    public $domDocument;

    /** @var \DOMXPath */
    public $domXPath;

    private function __construct(DOMDocument $domDocument)
    {
        $this->domDocument = $domDocument;
        $this->domXPath = new DOMXPath($domDocument);
        $this->domXPath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $this->domXPath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $this->domXPath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $this->domXPath->registerNamespace('mdui', 'urn:oasis:names:tc:SAML:metadata:ui');
        $this->domXPath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $this->domXPath->registerNameSpace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $this->domXPath->registerNameSpace('shibmd', 'urn:mace:shibboleth:metadata:1.0');
        // specifically for ADFS metadata
        //$this->domXPath->registerNameSpace('xs', 'http://www.w3.org/2001/XMLSchema');
        //$this->domXPath->registerNameSpace('xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        //$this->domXPath->registerNameSpace('fed', 'http:docs.oasis-open.org/wsfed/federation/200706');
        //$this->domXPath->registerNameSpace('auth', 'http://docs.oasis-open.org/wsfed/authorization/200706');
        //$this->domXPath->registerNameSpace('wsx', 'http://schemas.xmlsoap.org/ws/2004/09/mex');
    }

    /**
     * @param string $protocolMessageStr
     *
     * @return self
     */
    public static function fromProtocolMessage($protocolMessageStr)
    {
        return self::loadStr($protocolMessageStr, ['saml-schema-protocol-2.0.xsd']);
    }

    /**
     * @param string $metadataStr
     * @param bool   $validateSchema
     *
     * @return self
     */
    public static function fromMetadata($metadataStr, $validateSchema)
    {
        return self::loadStr(
            $metadataStr,
            $validateSchema ? ['ws-federation.xsd'] : []
        );
    }

    /**
     * @param mixed $inputVar
     *
     * @throws \fkooman\SAML\SP\Exception\XmlDocumentException
     *
     * @return \DOMElement
     */
    public static function requireDomElement($inputVar)
    {
        if (!($inputVar instanceof DOMElement)) {
            throw new XmlDocumentException('expected "DOMElement"');
        }

        return $inputVar;
    }

    /**
     * @param mixed $inputVar
     *
     * @throws \fkooman\SAML\SP\Exception\XmlDocumentException
     *
     * @return \DOMNodeList
     */
    public static function requireDomNodeList($inputVar)
    {
        if (!($inputVar instanceof DOMNodeList)) {
            throw new XmlDocumentException('expected "DOMNodeList"');
        }

        return $inputVar;
    }

    /**
     * @param mixed $inputVar
     *
     * @throws \fkooman\SAML\SP\Exception\XmlDocumentException
     *
     * @return string
     */
    public static function requireString($inputVar)
    {
        if (!\is_string($inputVar)) {
            throw new XmlDocumentException('expected "string"');
        }

        return $inputVar;
    }

    /**
     * @param mixed $inputVar
     *
     * @throws \fkooman\SAML\SP\Exception\XmlDocumentException
     *
     * @return string
     */
    public static function requireNonEmptyString($inputVar)
    {
        if (!\is_string($inputVar)) {
            throw new XmlDocumentException('expected "string"');
        }

        if ('' === $inputVar) {
            throw new XmlDocumentException('expected non-empty "string"');
        }

        return $inputVar;
    }

    /**
     * @param string        $xmlStr
     * @param array<string> $schemaFiles
     *
     * @throws \fkooman\SAML\SP\Exception\XmlDocumentException
     *
     * @return self
     */
    private static function loadStr($xmlStr, array $schemaFiles)
    {
        $domDocument = new DOMDocument();
        $entityLoader = \libxml_disable_entity_loader(true);
        $loadResult = $domDocument->loadXML($xmlStr, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_COMPACT);
        \libxml_disable_entity_loader($entityLoader);
        if (false === $loadResult) {
            throw new XmlDocumentException('unable to load XML document');
        }
        foreach ($schemaFiles as $schemaFile) {
            $schemaFilePath = __DIR__.'/schema/'.$schemaFile;
            $entityLoader = \libxml_disable_entity_loader(false);
            $validateResult = $domDocument->schemaValidate($schemaFilePath);
            \libxml_disable_entity_loader($entityLoader);
            if (false === $validateResult) {
                throw new XmlDocumentException(\sprintf('schema validation against "%s" failed', $schemaFile));
            }
        }

        return new self($domDocument);
    }
}
