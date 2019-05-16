<?php

/*
 * Copyright (c) 2019 François Kooman <fkooman@tuxed.net>
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

/**
 * List of OID attributes and their "friendly name".
 *
 * @see https://wiki.refeds.org/display/STAN/SCHAC+Releases
 * @see https://wiki.refeds.org/display/STAN/eduPerson
 */
return [
  'urn:oid:0.9.2342.19200300.100.1.1' => 'uid',
  'urn:oid:0.9.2342.19200300.100.1.3' => 'mail',
  'urn:oid:0.9.2342.19200300.100.1.10' => 'manager',
  'urn:oid:0.9.2342.19200300.100.1.20' => 'homePhone',
  'urn:oid:0.9.2342.19200300.100.1.39' => 'homePostalAddress',
  'urn:oid:0.9.2342.19200300.100.1.41' => 'mobile',
  'urn:oid:0.9.2342.19200300.100.1.42' => 'pager',
  'urn:oid:0.9.2342.19200300.100.1.44' => 'uniqueIdentifier',
  'urn:oid:0.9.2342.19200300.100.1.55' => 'audio',
  'urn:oid:0.9.2342.19200300.100.1.60' => 'jpegPhoto',
  'urn:oid:1.3.6.1.4.1.250.1.57' => 'labeledURI',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.1' => 'eduPersonAffiliation',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.2' => 'eduPersonNickname',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.3' => 'eduPersonOrgDN',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.4' => 'eduPersonOrgUnitDN',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.5' => 'eduPersonPrimaryAffiliation',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => 'eduPersonPrincipalName',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.7' => 'eduPersonEntitlement',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.8' => 'eduPersonPrimaryOrgUnitDN',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.9' => 'eduPersonScopedAffiliation',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.10' => 'eduPersonTargetedID',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.11' => 'eduPersonAssurance',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.12' => 'eduPersonPrincipalNamePrior',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.13' => 'eduPersonUniqueId',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.16' => 'eduPersonOrcid',
  'urn:oid:1.3.6.1.4.1.25178.1.0.2.3' => 'schacYearOfBirth',
  'urn:oid:1.3.6.1.4.1.25178.1.2.1' => 'schacMotherTongue',
  'urn:oid:1.3.6.1.4.1.25178.1.2.2' => 'schacGender',
  'urn:oid:1.3.6.1.4.1.25178.1.2.3' => 'schacDateOfBirth',
  'urn:oid:1.3.6.1.4.1.25178.1.2.4' => 'schacPlaceOfBirth',
  'urn:oid:1.3.6.1.4.1.25178.1.2.5' => 'schacCountryOfCitizenship',
  'urn:oid:1.3.6.1.4.1.25178.1.2.6' => 'schacSn1',
  'urn:oid:1.3.6.1.4.1.25178.1.2.7' => 'schacSn2',
  'urn:oid:1.3.6.1.4.1.25178.1.2.8' => 'schacPersonalTitle',
  'urn:oid:1.3.6.1.4.1.25178.1.2.9' => 'schacHomeOrganization',
  'urn:oid:1.3.6.1.4.1.25178.1.2.10' => 'schacHomeOrganizationType',
  'urn:oid:1.3.6.1.4.1.25178.1.2.11' => 'schacCountryOfResidence',
  'urn:oid:1.3.6.1.4.1.25178.1.2.12' => 'schacUserPresenceID',
  'urn:oid:1.3.6.1.4.1.25178.1.2.13' => 'schacPersonalPosition',
  'urn:oid:1.3.6.1.4.1.25178.1.2.14' => 'schacPersonalUniqueCode',
  'urn:oid:1.3.6.1.4.1.25178.1.2.15' => 'schacPersonalUniqueID',
  'urn:oid:1.3.6.1.4.1.25178.1.2.17' => 'schacExpiryDate',
  'urn:oid:1.3.6.1.4.1.25178.1.2.18' => 'schacUserPrivateAttribute',
  'urn:oid:1.3.6.1.4.1.25178.1.2.19' => 'schacUserStatus',
  'urn:oid:1.3.6.1.4.1.25178.1.2.20' => 'schacProjectMembership',
  'urn:oid:1.3.6.1.4.1.25178.1.2.21' => 'schacProjectSpecificRole',
  'urn:oid:2.5.4.3' => 'cn',
  'urn:oid:2.5.4.4' => 'sn',
  'urn:oid:2.5.4.7' => 'l',
  'urn:oid:2.5.4.8' => 'st',
  'urn:oid:2.5.4.10' => 'o',
  'urn:oid:2.5.4.11' => 'ou',
  'urn:oid:2.5.4.12' => 'title',
  'urn:oid:2.5.4.13' => 'description',
  'urn:oid:2.5.4.16' => 'postalAddress',
  'urn:oid:2.5.4.17' => 'postalCode',
  'urn:oid:2.5.4.18' => 'postOfficeBox',
  'urn:oid:2.5.4.20' => 'telephoneNumber',
  'urn:oid:2.5.4.23' => 'facsimileTelephoneNumber(defined',
  'urn:oid:2.5.4.34' => 'seeAlso',
  'urn:oid:2.5.4.35' => 'userPassword',
  'urn:oid:2.5.4.36' => 'userCertificate',
  'urn:oid:2.5.4.42' => 'givenName',
  'urn:oid:2.5.4.43' => 'initials',
  'urn:oid:2.5.4.45' => 'x500uniqueIdentifier',
  'urn:oid:2.16.840.1.113730.3.1.39' => 'preferredLanguage',
  'urn:oid:2.16.840.1.113730.3.1.40' => 'userSMIMECertificate',
  'urn:oid:2.16.840.1.113730.3.1.241' => 'displayName',
  'urn:oid::2.5.4.9' => 'street',
];
