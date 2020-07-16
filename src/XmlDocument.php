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

use DOMAttr;
use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use fkooman\SAML\SP\Exception\XmlDocumentException;

class XmlDocument
{
    /** @var \DOMDocument */
    private $domDocument;

    /** @var \DOMXPath */
    private $domXPath;

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
            $validateSchema ? ['__metadata.xsd'] : []
        );
    }

    /**
     * @param string $xPathQuery
     *
     * @return \DOMElement
     */
    public function requireOneDomElement($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        if (1 !== $domNodeList->length) {
            throw new XmlDocumentException(\sprintf('Q: "%s": expected exactly 1 DOMElement, got %d', $xPathQuery, $domNodeList->length));
        }

        return self::requireDomElement($domNodeList->item(0));
    }

    /**
     * @param string $xPathQuery
     *
     * @return \DOMElement|null
     */
    public function optionalOneDomElement($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        if (1 !== $domNodeList->length) {
            return null;
        }

        return $this->requireOneDomElement($xPathQuery);
    }

    /**
     * @param string $xPathQuery
     *
     * @return string
     */
    public function requireOneDomAttrValue($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        if (1 !== $domNodeList->length) {
            throw new XmlDocumentException(\sprintf('Q: "%s": expected exactly 1 DOMElement, got %d', $xPathQuery, $domNodeList->length));
        }

        // XXX do we need to trim the value?
        return self::requireNonEmptyString(self::requireDomAttr($domNodeList->item(0))->value);
    }

    /**
     * @param string $xPathQuery
     *
     * @return array<\DOMElement>
     */
    public function allDomElement($xPathQuery)
    {
        $domElementList = [];
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        foreach ($domNodeList as $domNode) {
            $domElementList[] = self::requireDomElement($domNode);
        }

        return $domElementList;
    }

    /**
     * @param string $xPathQuery
     *
     * @return array<string>
     */
    public function allDomAttrValue($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        $attributeValueList = [];
        foreach ($domNodeList as $domNode) {
            // XXX do we need to trim the value?
            $attributeValueList[] = self::requireNonEmptyString(self::requireDomAttr($domNode)->value);
        }

        return $attributeValueList;
    }

    /**
     * @param string $xPathQuery
     *
     * @return array<string>
     */
    public function allDomElementTextContent($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        $textValueList = [];
        foreach ($domNodeList as $domNode) {
            // XXX do we need to trim the value?
            $textValueList[] = self::requireNonEmptyString($domNode->textContent);
        }

        return $textValueList;
    }

    /**
     * @param string $xPathQuery
     *
     * @return string|null
     */
    public function optionalOneDomAttrValue($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($this->domXPath->query($xPathQuery));
        if (1 !== $domNodeList->length) {
            return null;
        }

        return $this->requireOneDomAttrValue($xPathQuery);
    }

    /**
     * @param string $xPathQuery
     *
     * @return string
     */
    public function requireOneDomElementTextContent($xPathQuery)
    {
        $domElement = $this->requireOneDomElement($xPathQuery);

        return self::requireNonEmptyString($domElement->textContent);
    }

    /**
     * @param string $xPathQuery
     *
     * @return string|null
     */
    public function optionalOneDomElementTextContent($xPathQuery)
    {
        if (null === $domElement = $this->optionalOneDomElement($xPathQuery)) {
            return null;
        }

        return $this->requireOneDomElementTextContent($xPathQuery);
    }

    /**
     * @param mixed $inputVar
     *
     * @throws \fkooman\SAML\SP\Exception\XmlDocumentException
     *
     * @return \DOMElement
     */
    private static function requireDomElement($inputVar)
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
     * @return \DOMAttr
     */
    private static function requireDomAttr($inputVar)
    {
        if (!($inputVar instanceof DOMAttr)) {
            throw new XmlDocumentException('expected "DOMAttr"');
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
    private static function requireDomNodeList($inputVar)
    {
        if (!($inputVar instanceof DOMNodeList)) {
            throw new XmlDocumentException(\sprintf('expected "DOMNodeList", got "%s"', \get_class($inputVar)));
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
    private static function requireString($inputVar)
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
    private static function requireNonEmptyString($inputVar)
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
        $loadResult = @$domDocument->loadXML($xmlStr, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_COMPACT);
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
