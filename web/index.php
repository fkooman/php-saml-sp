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

require_once \dirname(__DIR__).'/vendor/autoload.php';

use fkooman\SAML\SP\PrivateKey;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\SeSession;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;
use fkooman\SAML\SP\Web\Config;
use fkooman\SAML\SP\Web\Request;
use fkooman\SAML\SP\Web\Response;
use fkooman\SAML\SP\Web\Service;
use fkooman\SAML\SP\Web\Tpl;
use fkooman\SAML\SP\XmlIdpInfoSource;

$baseDir = \dirname(__DIR__);

try {
    $config = Config::fromFile($baseDir.'/config/config.php');
    if (null === $secureCookie = $config->requireKey('secureCookie')) {
        $secureCookie = true;
    }
    $session = new SeSession($secureCookie);
    $tpl = new Tpl([$baseDir.'/views']);
    $tpl->addDefault(
        [
            'secureCookie' => $secureCookie,
        ]
    );
    $metadataFileList = \glob($baseDir.'/config/metadata/*.xml');
    $idpInfoSource = new XmlIdpInfoSource($metadataFileList);
    $request = new Request($_SERVER, $_GET, $_POST);

    // have a default entityID, but allow overriding from config
    if (null === $spEntityId = $config->requireKey('entityId')) {
        $spEntityId = $request->getRootUri().'metadata';
    }

    if (null === $requireEncryption = $config->requireKey('requireEncryption')) {
        $requireEncryption = false;
    }

    // configure the SP
    $spInfo = new SpInfo(
        $spEntityId,
        // AuthnRequest / LogoutRequest / Decryption <EncryptedAssertion>
        PrivateKey::fromFile($baseDir.'/config/sp.key'),
        PublicKey::fromFile($baseDir.'/config/sp.crt'),
        $request->getRootUri().'acs',
        $requireEncryption
    );
    $spInfo->setSloUrl($request->getRootUri().'slo');
    $sp = new SP($spInfo, $idpInfoSource, $session);
    $service = new Service($config, $tpl, $sp);
    $request = new Request($_SERVER, $_GET, $_POST);
    $service->run($request)->send();
} catch (Exception $e) {
    $response = new Response(500, [], 'Error: '.$e->getMessage());
    $response->send();
}
