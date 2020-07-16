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
use fkooman\SAML\SP\Exception\ResponseException;

class Response
{
    /** @var \DateTime */
    private $dateTime;

    public function __construct(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param string        $samlResponse
     * @param string        $expectedInResponseTo
     * @param array<string> $authnContext
     * @param array<string> $scopingIdpList
     *
     * @throws \fkooman\SAML\SP\Exception\ResponseException
     *
     * @return Assertion
     */
    public function verify(SpInfo $spInfo, IdpInfo $idpInfo, $samlResponse, $expectedInResponseTo, array $authnContext, array $scopingIdpList)
    {
        $responseSigned = false;
        $assertionSigned = false;
        $assertionEncrypted = false;

        $responseDocument = XmlDocument::fromProtocolMessage($samlResponse);
        if (null !== $responseDocument->optionalOneDomElement('/samlp:Response/ds:Signature')) {
            // samlp:Response is signed
            Crypto::verifyXml($responseDocument, $idpInfo->getPublicKeys());
            $responseSigned = true;
        }

        // handle samlp:Status
        $statusCode = $responseDocument->requireOneDomAttrValue('/samlp:Response/samlp:Status/samlp:StatusCode/@Value');
        if ('urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode) {
            $exceptionMessage = $statusCode;
            // check whether there is an additional status code
            if (null !== $additionalStatusCode = $responseDocument->optionalOneDomAttrValue('/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value')) {
                $exceptionMessage = \sprintf('%s (%s)', $statusCode, $additionalStatusCode);
            }

            throw new ResponseException($exceptionMessage);
        }

        $assertionEncrypted = false;
        $assertionDocument = self::getAssertionDocument($responseDocument, $spInfo, $assertionEncrypted);

        if ($spInfo->getRequireEncryption() && !$assertionEncrypted) {
            throw new ResponseException('assertion was not encrypted, but encryption is enforced');
        }

        if (null !== $assertionDocument->optionalOneDomElement('/saml:Assertion/ds:Signature')) {
            // saml:Assertion is signed
            Crypto::verifyXml($assertionDocument, $idpInfo->getPublicKeys());
            $assertionSigned = true;
        }

        if (!$responseSigned && !$assertionSigned) {
            throw new ResponseException('samlp:Response and/or saml:Assertion MUST be signed');
        }

        // the saml:Assertion Issuer MUST be IdP entityId
        $assertionIssuer = $assertionDocument->requireOneDomElementTextContent('/saml:Assertion/saml:Issuer');
        if ($assertionIssuer !== $idpInfo->getEntityId()) {
            throw new ResponseException(\sprintf('expected saml:Issuer "%s", got "%s"', $idpInfo->getEntityId(), $assertionIssuer));
        }

        // the saml:Conditions/saml:AudienceRestriction MUST be us
        $assertionAudience = $assertionDocument->requireOneDomElementTextContent('/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience');
        if ($assertionAudience !== $spInfo->getEntityId()) {
            throw new ResponseException(\sprintf('expected saml:Audience "%s", got "%s"', $spInfo->getEntityId(), $assertionAudience));
        }

        $assertionNotOnOrAfter = new DateTime($assertionDocument->requireOneDomAttrValue('/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter'));
        if (DateTimeValidator::isOnOrAfter($this->dateTime, $assertionNotOnOrAfter)) {
            throw new ResponseException('saml:Assertion no longer valid');
        }

        $assertionRecipient = $assertionDocument->requireOneDomAttrValue('/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient');
        if ($assertionRecipient !== $spInfo->getAcsUrl()) {
            throw new ResponseException(\sprintf('expected Recipient "%s", got "%s"', $spInfo->getAcsUrl(), $assertionRecipient));
        }

        $assertionInResponseTo = $assertionDocument->requireOneDomAttrValue('/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo');
        if ($assertionInResponseTo !== $expectedInResponseTo) {
            throw new ResponseException(\sprintf('expected InResponseTo "%s", got "%s"', $expectedInResponseTo, $assertionInResponseTo));
        }

        // notBefore
        $assertionNotBefore = new DateTime($assertionDocument->requireOneDomAttrValue('/saml:Assertion/saml:Conditions/@NotBefore'));
        if (DateTimeValidator::isBefore($this->dateTime, $assertionNotBefore)) {
            throw new ResponseException('saml:Assertion is not yet valid');
        }

        $assertionAuthnInstant = new DateTime($assertionDocument->requireOneDomAttrValue('/saml:Assertion/saml:AuthnStatement/@AuthnInstant'));

        // SessionNotOnOrAfter (Optional)
        $sessionNotOnOrAfter = \date_add(clone $this->dateTime, new DateInterval('PT8H'));
        if (null !== $assertionSessionNotOnOrAfter = $assertionDocument->optionalOneDomAttrValue('/saml:Assertion/saml:AuthnStatement/@SessionNotOnOrAfter')) {
            $sessionNotOnOrAfter = new DateTime($assertionSessionNotOnOrAfter);
        }

        $assertionAuthnContextClassRef = $assertionDocument->requireOneDomElementTextContent('/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef');
        if (0 !== \count($authnContext)) {
            // we requested a particular AuthnContext, make sure we got it
            if (!\in_array($assertionAuthnContextClassRef, $authnContext, true)) {
                throw new ResponseException(\sprintf('expected AuthnContext containing any of [%s], got "%s"', \implode(',', $authnContext), $assertionAuthnContextClassRef));
            }
        }

        // AuthenticatingAuthority (Optional)
        $assertionAuthenticatingAuthority = $assertionDocument->optionalOneDomElementTextContent('/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority');
        if (0 !== \count($scopingIdpList)) {
            // we requested a particular AuthenticatingAuthority, make sure we got it
            if (null === $assertionAuthenticatingAuthority) {
                throw new ResponseException(\sprintf('expected AuthenticatingAuthority containing any of [%s], got none', \implode(',', $scopingIdpList)));
            }
            if (!\in_array($assertionAuthenticatingAuthority, $scopingIdpList, true)) {
                throw new ResponseException(\sprintf('expected AuthenticatingAuthority containing any of [%s], got "%s"', \implode(',', $scopingIdpList), $assertionAuthenticatingAuthority));
            }
        }

        $attributeList = self::extractAttributes($assertionDocument, $idpInfo, $spInfo);
        $samlAssertion = new Assertion($idpInfo->getEntityId(), $assertionAuthnInstant, $sessionNotOnOrAfter, $assertionAuthnContextClassRef, $assertionAuthenticatingAuthority, $attributeList);

        // NameID
        if (null !== $assertionNameIdDomElement = $assertionDocument->optionalOneDomElement('/saml:Assertion/saml:Subject/saml:NameID')) {
            $nameId = new NameId($idpInfo->getEntityId(), $spInfo->getEntityId(), $assertionNameIdDomElement);
            $samlAssertion->setNameId($nameId);
        }

        return $samlAssertion;
    }

    /**
     * @param bool $assertionEncrypted
     *
     * @return XmlDocument
     */
    private static function getAssertionDocument(XmlDocument $responseDocument, SpInfo $spInfo, &$assertionEncrypted)
    {
        if (null !== $responseDocument->optionalOneDomElement('/samlp:Response/saml:EncryptedAssertion')) {
            $decryptedAssertion = Crypto::decryptXml($responseDocument, $spInfo->getCryptoKeys()->getEncryptionPrivateKey());
            $assertionEncrypted = true;

            // create and validate new document for Assertion
            return XmlDocument::fromProtocolMessage($decryptedAssertion);
        }

        $assertionElement = $responseDocument->requireOneDomElement('/samlp:Response/saml:Assertion');

        // we need to create a new document first to keep the namespacing intact
        // XXX move this to XmlDocument?
        $assertionDocument = new DOMDocument('1.0', 'UTF-8');
        $assertionDocument->appendChild($assertionDocument->importNode($assertionElement, true));

        return XmlDocument::fromProtocolMessage($assertionDocument->saveXML());
    }

    /**
     * @return array<string,array<string>>
     */
    private static function extractAttributes(XmlDocument $assertionDocument, IdpInfo $idpInfo, SpInfo $spInfo)
    {
        /** @var array<string,string> */
        $attributeMapping = include __DIR__.'/attribute_mapping.php';

        /** @var array<string,array<string>> */
        $attributeList = [];
        foreach ($assertionDocument->allDomAttrValue('/saml:Assertion/saml:AttributeStatement/saml:Attribute/@Name') as $attributeName) {
            if (!\array_key_exists($attributeName, $attributeMapping)) {
                // we only process attributes in urn:oid syntax we know about,
                // the rest we ignore...
                continue;
            }

            $attributeValueList = $assertionDocument->allDomElementTextContent(
                \sprintf('/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue', $attributeName)
            );

            foreach ($attributeValueList as $attributeValue) {
                if (null !== $processedAttributeValue = self::processAttributeValue($assertionDocument, $attributeName, $attributeValue, $idpInfo, $spInfo)) {
                    if (!\array_key_exists($attributeName, $attributeList)) {
                        $attributeList[$attributeName] = [];
                        $attributeList[$attributeMapping[$attributeName]] = [];
                    }
                    $attributeList[$attributeName][] = $processedAttributeValue;
                    $attributeList[$attributeMapping[$attributeName]][] = $processedAttributeValue;
                }
            }
        }

        return $attributeList;
    }

    /**
     * @param string $attributeName
     * @param string $attributeValue
     *
     * @return string|null
     */
    private static function processAttributeValue(XmlDocument $assertionDocument, $attributeName, $attributeValue, IdpInfo $idpInfo, SpInfo $spInfo)
    {
        // eduPersonTargetedID (ePTID)
        if ('urn:oid:1.3.6.1.4.1.5923.1.1.1.10' === $attributeName) {
            // ePTID is a special case as it wraps a saml:NameID construct and
            // not a simple string value...
            $nameIdDomElement = $assertionDocument->requireOneDomElement('/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"]/saml:AttributeValue/saml:NameID');
            $nameId = new NameId($idpInfo->getEntityId(), $spInfo->getEntityId(), $nameIdDomElement);

            return $nameId->toUserId();
        }

        // filter "scoped" attributes
        // @see https://spaces.at.internet2.edu/display/InCFederation/2016/05/08/Scoped+User+Identifiers
        $idpScopeList = $idpInfo->getScopeList();
        if (0 !== \count($idpScopeList)) {
            $scopedAttributeNameList = [
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',  // eduPersonPrincipalName
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.9',  // eduPersonScopedAffiliation
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.13', // eduPersonUniqueId
                // SAML V2.0 Subject Identifier Attributes Profile Version 1.0
                // [SAML-SubjectID-v1.0]
                'urn:oasis:names:tc:SAML:attribute:pairwise-id',
                'urn:oasis:names:tc:SAML:attribute:subject-id',
            ];

            if (\in_array($attributeName, $scopedAttributeNameList, true)) {
                // make sure we have exactly one "@" in the attribute value
                $identifierScopeArray = \explode('@', $attributeValue, 2);
                if (2 !== \count($identifierScopeArray)) {
                    return null;
                }
                // try to match with all IdP supported scopes
                foreach ($idpScopeList as $idpScope) {
                    if ($idpScope === $identifierScopeArray[1]) {
                        return $attributeValue;
                    }
                }

                return null;
            }

            // schacHomeOrganization
            if ('urn:oid:1.3.6.1.4.1.25178.1.2.9' === $attributeName) {
                // make sure the mentioned domain matches the value(s) of
                // shibmd:Scope *exactly*
                if (!\in_array($attributeValue, $idpScopeList, true)) {
                    return null;
                }

                return $attributeValue;
            }
        }

        return $attributeValue;
    }
}
