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

namespace fkooman\SAML\SP\Web;

use fkooman\SAML\SP\Api\SamlAuth;
use fkooman\SAML\SP\Crypto;
use fkooman\SAML\SP\Exception\SamlException;
use fkooman\SAML\SP\IdpInfo;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\Web\Exception\HttpException;

class Service
{
    /** @var string */
    const LAST_CHOSEN_COOKIE_NAME = 'IDP';

    /** @var Config */
    private $config;

    /** @var Tpl */
    private $tpl;

    /** @var \fkooman\SAML\SP\SP */
    private $sp;

    /** @var CookieInterface */
    private $cookie;

    public function __construct(Config $config, Tpl $tpl, SP $sp, CookieInterface $cookie)
    {
        $this->config = $config;
        $this->tpl = $tpl;
        $this->sp = $sp;
        $this->cookie = $cookie;
    }

    /**
     * @return Response
     */
    public function run(Request $request)
    {
        try {
            try {
                switch ($request->getRequestMethod()) {
                    case 'HEAD':
                    case 'GET':
                        return $this->runGet($request);
                    case 'POST':
                        return $this->runPost($request);
                    default:
                        throw new HttpException(405, 'Only GET,HEAD,POST allowed', ['Allow' => 'GET,HEAD,POST']);
                }
            } catch (SamlException $e) {
                // catch all SAML related exceptions
                throw new HttpException(500, $e->getMessage(), [], $e);
            }
        } catch (HttpException $e) {
            return new HtmlResponse(
                $this->tpl->render(
                    'error',
                    [
                        'e' => $e,
                    ]
                ),
                (int) $e->getCode()
            );
        }
    }

    /**
     * @return Response
     */
    private function runGet(Request $request)
    {
        switch ($request->getPathInfo()) {
            // landing page
            case '/':
                return new HtmlResponse(
                    $this->tpl->render(
                        'index',
                        [
                            'metadataUrl' => $request->getRootUri().'metadata',
                            'samlMetadata' => $this->sp->metadata(),
                            'decryptionSupport' => Crypto::hasDecryptionSupport(),
                        ]
                    )
                );
            case '/info':
                $samlAuth = new SamlAuth();
                if (!$samlAuth->isAuthenticated()) {
                    return new RedirectResponse($samlAuth->getLoginURL());
                }

                return new HtmlResponse(
                    $this->tpl->render(
                        'info',
                        [
                            'logoutReturnTo' => $request->getRootUri(),
                            'samlAssertion' => $samlAuth->getAssertion(),
                        ]
                    )
                );
            case '/login':
                // get the list of IdPs that can be used
                $availableIdpList = $this->config->getIdpList();
                if (0 === \count($availableIdpList)) {
                    throw new HttpException(500, 'no IdP(s) available');
                }

                $returnTo = self::verifyReturnToOrigin($request->getOrigin(), $request->requireQueryParameter('ReturnTo'));
                $authnContextClassRef = self::verifyAuthnContextClassRef($request->optionalQueryParameter('AuthnContextClassRef'));
                $scopingIdpList = self::verifyScopingIdpList($request->optionalQueryParameter('ScopingIdpList'));
                if (1 === \count($availableIdpList)) {
                    // we only have 1 IdP, so use that
                    return new RedirectResponse($this->sp->login($availableIdpList[0], $returnTo, $authnContextClassRef, $scopingIdpList));
                }

                if (null !== $idpEntityId = $request->optionalQueryParameter('IdP')) {
                    // an IdP entity ID is provided as a query parameter
                    return new RedirectResponse($this->sp->login($idpEntityId, $returnTo, $authnContextClassRef, $scopingIdpList));
                }

                if (null !== $discoUrl = $this->config->getDiscoUrl()) {
                    // use external discovery service
                    $discoQuery = \http_build_query(
                        [
                            'entityID' => $this->sp->getSpInfo()->getEntityId(),
                            'returnIDParam' => 'IdP',
                            'return' => $request->getUri(),
                        ]
                    );

                    return new RedirectResponse(
                        \sprintf(
                            '%s%s%s',
                            $discoUrl,
                            false === \strpos($discoUrl, '?') ? '?' : '&',
                            $discoQuery
                        )
                    );
                }

                // use our own discovery service
                $idpInfoList = [];
                foreach ($availableIdpList as $availableIdp) {
                    if ($this->sp->getIdpInfoSource()->has($availableIdp)) {
                        $idpInfoList[$availableIdp] = $this->sp->getIdpInfoSource()->get($availableIdp);
                    }
                }

                // sort the IdPs by display name
                \uasort($idpInfoList, function (IdpInfo $a, IdpInfo $b) {
                    return \strcasecmp($a->getDisplayName(), $b->getDisplayName());
                });

                $lastChosenIdpInfo = null;
                if (null !== $lastChosenIdp = $this->cookie->get(self::LAST_CHOSEN_COOKIE_NAME)) {
                    // make sure IdP (still) exists
                    if (\array_key_exists($lastChosenIdp, $idpInfoList)) {
                        $lastChosenIdpInfo = $idpInfoList[$lastChosenIdp];
                        unset($idpInfoList[$lastChosenIdp]);
                    }
                }

                return new HtmlResponse(
                    $this->tpl->render(
                        'wayf',
                        [
                            'lastChosenIdpInfo' => $lastChosenIdpInfo,
                            'idpInfoList' => $idpInfoList,
                        ]
                    )
                );
            // user triggered logout
            case '/logout':
                $returnTo = self::verifyReturnToOrigin($request->getOrigin(), $request->requireQueryParameter('ReturnTo'));

                return new RedirectResponse($this->sp->logout($returnTo));
            // exposes the SP metadata for IdP consumption
            case '/metadata':
                return new Response(200, ['Content-Type' => 'application/samlmetadata+xml'], $this->sp->metadata());
            // callback from IdP containing the "LogoutResponse"
            case '/slo':
                // we need the "raw" query string to be able to verify the
                // signatures...
                $returnTo = $this->sp->handleLogoutResponse($request->getQueryString());

                return new RedirectResponse($returnTo);
            default:
                throw new HttpException(404, 'URL not found: '.$request->getPathInfo());
        }
    }

    /**
     * @return Response
     */
    private function runPost(Request $request)
    {
        switch ($request->getPathInfo()) {
            // callback from IdP containing the "SAMLResponse"
            case '/acs':
                $returnTo = $this->sp->handleResponse($request->requirePostParameter('SAMLResponse'), $request->requirePostParameter('RelayState'));

                return new RedirectResponse($returnTo);
            case '/login':
                $idpEntityId = $request->requirePostParameter('IdP');
                // we don't care what the value of the cookie becomes, it will
                // be checked before using it anyway...
                $this->cookie->set(self::LAST_CHOSEN_COOKIE_NAME, $idpEntityId);
                $returnTo = self::verifyReturnToOrigin($request->getOrigin(), $request->getUri());

                return new RedirectResponse($returnTo.'&'.\http_build_query(['IdP' => $idpEntityId]));
            case '/setLanguage':
                // we don't care what uiLanguage is, it can be anything, it
                // will be verified by Tpl::setLanguage. User can provide any
                // cookie value anyway!
                $this->cookie->set('L', $request->requirePostParameter('uiLanguage'));
                $returnTo = self::verifyReturnToOrigin($request->getOrigin(), $request->requireHeader('HTTP_REFERER'));

                return new RedirectResponse($returnTo);
            default:
                throw new HttpException(404, 'URL not found: '.$request->getPathInfo());
        }
    }

    /**
     * @param string $expectedOrigin
     * @param string $returnTo
     *
     * @return string
     */
    private static function verifyReturnToOrigin($expectedOrigin, $returnTo)
    {
        // Origin is scheme://host[:port]
        if (false === \filter_var($returnTo, FILTER_VALIDATE_URL)) {
            throw new HttpException(400, 'invalid "ReturnTo" provided');
        }
        if (false === $parsedUrl = \parse_url($returnTo)) {
            throw new HttpException(400, 'invalid "ReturnTo" provided');
        }

        // the filter_var FILTER_VALIDATE_URL make sure scheme and host are
        // there, but just to make absolutely sure...
        if (!\array_key_exists('scheme', $parsedUrl) || !\array_key_exists('host', $parsedUrl)) {
            throw new HttpException(400, 'invalid "ReturnTo" provided');
        }
        $urlConstruction = $parsedUrl['scheme'].'://'.$parsedUrl['host'];
        if (\array_key_exists('port', $parsedUrl)) {
            $urlConstruction .= ':'.(string) $parsedUrl['port'];
        }

        if ($expectedOrigin !== $urlConstruction) {
            throw new HttpException(400, 'invalid "ReturnTo" provided');
        }

        return $returnTo;
    }

    /**
     * @param string|null $authnContextClassRef
     *
     * @return array<string>
     */
    private static function verifyAuthnContextClassRef($authnContextClassRef)
    {
        if (null === $authnContextClassRef) {
            return [];
        }

        return \explode(' ', $authnContextClassRef);
    }

    /**
     * @param string|null $scopingIdpList
     *
     * @return array<string>
     */
    private static function verifyScopingIdpList($scopingIdpList)
    {
        if (null === $scopingIdpList) {
            return [];
        }

        return \explode(' ', $scopingIdpList);
    }
}
