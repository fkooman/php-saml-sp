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

use fkooman\SAML\SP\PrivateKey;
use fkooman\SAML\SP\PublicKey;
use fkooman\SAML\SP\SeSession;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\SpInfo;
use fkooman\SAML\SP\Web\Config;
use fkooman\SAML\SP\Web\Request;
use fkooman\SAML\SP\Web\Response;
use fkooman\SAML\SP\Web\SeCookie;
use fkooman\SAML\SP\Web\Service;
use fkooman\SAML\SP\Web\Tpl;
use fkooman\SAML\SP\XmlIdpInfoSource;

$baseDir = \dirname(__DIR__);

try {
    $config = Config::fromFile($baseDir.'/config/config.php');
    $secureCookie = $config->getSecureCookie();

    $seCookie = new SeCookie($secureCookie);
    $seSession = new SeSession($secureCookie);

    // determine whether we want to use a different style
    $templateDirs = [$baseDir.'/views'];
    $translationDirs = [$baseDir.'/locale'];
    if (null !== $styleName = $config->getStyleName()) {
        $templateDirs[] = $baseDir.'/views/'.$styleName;
        $translationDirs[] = $baseDir.'/locale/'.$styleName;
    }
    // determine whether or not we want to use another language for the UI
    if (null === $uiLanguage = $seCookie->get('L')) {
        $uiLanguage = $config->getDefaultLanguage();
    }
    $tpl = new Tpl($templateDirs, $translationDirs);
    $tpl->setLanguage($uiLanguage);
    $tpl->addDefault(['secureCookie' => $secureCookie, 'enabledLanguages' => $config->getEnabledLanguages(), 'serviceName' => $config->getServiceName($uiLanguage)]);
    $metadataFileList = \glob($baseDir.'/config/metadata/*.xml');
    $idpInfoSource = new XmlIdpInfoSource($metadataFileList);
    $request = new Request($_SERVER, $_GET, $_POST);

    // have a default entityID, but allow overriding from config
    if (null === $spEntityId = $config->getEntityId()) {
        $spEntityId = $request->getRootUri().'metadata';
    }

    // configure the SP
    $spInfo = new SpInfo(
        $spEntityId,
        // AuthnRequest / LogoutRequest / Decryption <EncryptedAssertion>
        PrivateKey::fromFile($baseDir.'/config/sp.key'),
        PublicKey::fromFile($baseDir.'/config/sp.crt'),
        $request->getRootUri().'acs',
        $config->getRequireEncryption(),
        $config->getServiceNames()
    );
    $spInfo->setSloUrl($request->getRootUri().'slo');
    $sp = new SP($spInfo, $idpInfoSource, $seSession);
    $service = new Service($config, $tpl, $sp, $seCookie, $seSession);
    $request = new Request($_SERVER, $_GET, $_POST);
    $service->run($request)->send();
} catch (Exception $e) {
    $response = new Response(500, [], 'Error: '.$e->getMessage());
    $response->send();
}
