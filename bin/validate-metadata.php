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

try {
    if ($argc < 2) {
        echo 'Validate XML schema and optionally XML signature over SAML metadata files.'.PHP_EOL.PHP_EOL;
        echo "\tSYNTAX: ".$argv[0].' metadata.xml [certificate.pem]'.PHP_EOL;
        exit(1);
    }

    $publicKey = null;
    if ($argc > 2) {
        // Show Public Key information
        $publicKey = PublicKey::fromFile($argv[2]);
        echo '################################# Public Key #################################'.PHP_EOL;
        foreach ($publicKey->getFingerprint() as $hashAlgo => $rawFingerprint) {
            echo $hashAlgo.PHP_EOL."\t".\implode(':', \str_split(\bin2hex($rawFingerprint), 2)).PHP_EOL;
        }
        echo '################################# Public Key #################################'.PHP_EOL;
    }

    echo 'Verifying XML schema...';
    if (false === $fileContent = @\file_get_contents($argv[1])) {
        throw new RuntimeException(\sprintf('unable to read "%s"', $argv[1]));
    }
    $xmlDocument = XmlDocument::fromMetadata($fileContent, true);
    echo ' OK!'.PHP_EOL;
    if (null !== $publicKey) {
        echo 'Verifying XML signature...';
        Crypto::verifyXml($xmlDocument, [$publicKey]);
        echo ' OK!'.PHP_EOL;
    }
} catch (Exception $e) {
    $logMessage = 'ERROR: ['.\get_class($e).'] '.$e->getMessage();
    echo $logMessage.PHP_EOL;
    exit(1);
}
