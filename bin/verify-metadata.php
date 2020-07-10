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

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\SAML\SP\Crypto;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\XmlDocument;

if ($argc < 3) {
    echo 'SYNTAX: '.$argv[0].' [https://host/]metadata.xml metadata.crt'.PHP_EOL;
    exit(1);
}

$metadataUrl = $argv[1];
$publicKeyFile = $argv[2];

try {
    $publicKey = PublicKey::fromFile($publicKeyFile);
    $xmlDocument = XmlDocument::fromMetadata(\file_get_contents($metadataUrl), true);
    // XXX make sure "/*" can only match the root element...
    $documentRoot = XmlDocument::requireDomNodeList($xmlDocument->domXPath->query('/*'));
    $rootElement = XmlDocument::requireDomElement($documentRoot->item(0));
    Crypto::verifyXml($xmlDocument, $rootElement, [$publicKey]);
    echo 'OK'.PHP_EOL;
} catch (Exception $e) {
    echo 'ERROR: '.$e->getMessage().PHP_EOL;
    exit(1);
}
