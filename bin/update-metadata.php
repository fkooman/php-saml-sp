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

use fkooman\SAML\SP\CurlHttpClient;
use fkooman\SAML\SP\MetadataSource;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\Web\Config;

$baseDir = \dirname(__DIR__);
$dataDir = $baseDir.'/data';
$configDir = $baseDir.'/config';
$keyDir = $configDir.'/metadata/keys/';
$verifiedMetadataDir = $dataDir.'/metadata/verified';
$metadataDir = $dataDir.'/metadata';

try {
    $config = Config::fromFile($configDir.'/config.php');
    if (!@\file_exists($metadataDir)) {
        if (false === @\mkdir($metadataDir, 0755, true)) {
            throw new RuntimeException(\sprintf('unable to create directory "%s"', $metadataDir));
        }
    }
    if (!@\file_exists($verifiedMetadataDir)) {
        if (false === @\mkdir($verifiedMetadataDir, 0755, true)) {
            throw new RuntimeException(\sprintf('unable to create directory "%s"', $verifiedMetadataDir));
        }
    }

    foreach ($config->getMetadataList() as $metadataUrl => $publicKeyFileList) {
        // get the metadata
        $metadataString = CurlHttpClient::get($metadataUrl);
        $metadataFile = $metadataDir.'/'.\base64_encode($metadataUrl).'.xml';
        $verifiedFile = $verifiedMetadataDir.'/'.\base64_encode($metadataUrl).'.xml';
        if (false === @\file_put_contents($metadataFile, $metadataString)) {
            throw new RuntimeException(\sprintf('unable to write "%s"', $metadataFile));
        }
        $publicKeyList = [];
        foreach ($publicKeyFileList as $publicKeyFile) {
            $publicKeyList[] = PublicKey::fromFile($keyDir.'/'.$publicKeyFile);
        }
        MetadataSource::validateMetadataFile($metadataFile, $publicKeyList);
        if (false === @\rename($metadataFile, $verifiedFile)) {
            throw new RuntimeException(\sprintf('unable to mvoe "%s" to "%s"', $metadataFile, $verifiedFile));
        }
    }
} catch (Exception $e) {
    echo 'ERROR: ['.\get_class($e).'] '.$e->getMessage().PHP_EOL;
    exit(1);
}
