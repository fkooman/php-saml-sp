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
    /** @var \DOMXPath */
    private $domXPath;

    private function __construct(DOMDocument $domDocument)
    {
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
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
        if (1 !== $domNodeList->length) {
            throw new XmlDocumentException(\sprintf('Q: "%s": expected exactly 1 DOMElement, got %d', $xPathQuery, $domNodeList->length));
        }

        return self::requireDomElement($xPathQuery, $domNodeList->item(0));
    }

    /**
     * @param string $xPathQuery
     *
     * @return \DOMElement|null
     */
    public function optionalOneDomElement($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
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
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
        if (1 !== $domNodeList->length) {
            throw new XmlDocumentException(\sprintf('Q: "%s": expected exactly 1 DOMElement, got %d', $xPathQuery, $domNodeList->length));
        }

        return self::requireNonEmptyString($xPathQuery, self::requireDomAttr($xPathQuery, $domNodeList->item(0))->value);
    }

    /**
     * @param string $xPathQuery
     *
     * @return array<\DOMElement>
     */
    public function allDomElement($xPathQuery)
    {
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
        $domElementList = [];
        foreach ($domNodeList as $domNode) {
            $domElementList[] = self::requireDomElement($xPathQuery, $domNode);
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
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
        $attributeValueList = [];
        foreach ($domNodeList as $domNode) {
            $attributeValueList[] = self::requireNonEmptyString($xPathQuery, self::requireDomAttr($xPathQuery, $domNode)->value);
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
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
        $textValueList = [];
        foreach ($domNodeList as $domNode) {
            $textValueList[] = self::requireNonEmptyString($xPathQuery, $domNode->textContent);
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
        $domNodeList = self::requireDomNodeList($xPathQuery, $this->domXPath->query($xPathQuery));
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

        return self::requireNonEmptyString($xPathQuery, $domElement->textContent);
    }

    /**
     * @param string $xPathQuery
     *
     * @return string|null
     */
    public function optionalOneDomElementTextContent($xPathQuery)
    {
        if (null === $this->optionalOneDomElement($xPathQuery)) {
            return null;
        }

        return $this->requireOneDomElementTextContent($xPathQuery);
    }

    /**
     * @return string
     */
    public static function domElementToString(DOMElement $domElement)
    {
        // we create a new document here in order to make sure we retain all
        // namespaces. Simply calling DOMElement::saveXML() will not retain
        // the namespaces declared on parent documents and thus result in
        // a broken document...
        $domDocument = new DOMDocument('1.0', 'UTF-8');
        $domDocument->appendChild($domDocument->importNode($domElement, true));
        if (false === $xmlString = $domDocument->saveXML()) {
            throw new XmlDocumentException('unable to convert XML to string');
        }

        return $xmlString;
    }

    /**
     * @param string $xPathQuery
     * @param mixed  $inputVar
     *
     * @return \DOMElement
     */
    private static function requireDomElement($xPathQuery, $inputVar)
    {
        if (!($inputVar instanceof DOMElement)) {
            throw new XmlDocumentException(\sprintf('[%s] expected "DOMElement"', $xPathQuery));
        }

        return $inputVar;
    }

    /**
     * @param string $xPathQuery
     * @param mixed  $inputVar
     *
     * @return \DOMAttr
     */
    private static function requireDomAttr($xPathQuery, $inputVar)
    {
        if (!($inputVar instanceof DOMAttr)) {
            throw new XmlDocumentException(\sprintf('[%s] expected "DOMAttr"', $xPathQuery));
        }

        return $inputVar;
    }

    /**
     * @param string $xPathQuery
     * @param mixed  $inputVar
     *
     * @return \DOMNodeList
     */
    private static function requireDomNodeList($xPathQuery, $inputVar)
    {
        if (!($inputVar instanceof DOMNodeList)) {
            throw new XmlDocumentException(\sprintf('[%s] expected "DOMNodeList"', $xPathQuery));
        }

        return $inputVar;
    }

    /**
     * @param string $xPathQuery
     * @param mixed  $inputVar
     *
     * @return string
     */
    private static function requireNonEmptyString($xPathQuery, $inputVar)
    {
        if (!\is_string($inputVar)) {
            throw new XmlDocumentException(\sprintf('[%s] expected "string"', $xPathQuery));
        }

        $trimmedString = \trim($inputVar);

        if ('' === $trimmedString) {
            throw new XmlDocumentException(\sprintf('[%s] expected non-empty "string"', $xPathQuery));
        }

        return $trimmedString;
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
