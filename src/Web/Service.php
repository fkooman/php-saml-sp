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
     * @param string $httpOrigin
     * @param string $urlToMatch
     *
     * @return string
     */
    public static function verifyMatchesOrigin($httpOrigin, $urlToMatch)
    {
        $urlScheme = \parse_url($urlToMatch, PHP_URL_SCHEME);
        if ('https' !== $urlScheme && 'http' !== $urlScheme) {
            throw new HttpException(400, 'URL scheme not supported');
        }
        if (null !== \parse_url($urlToMatch, PHP_URL_USER)) {
            // URL MUST NOT contain authentication information (DEC-01-001 WP1)
            throw new HttpException(400, 'URL must not contain authentication information');
        }
        $urlHost = \parse_url($urlToMatch, PHP_URL_HOST);
        if (!\is_string($urlHost)) {
            throw new HttpException(400, 'malformed URL host');
        }
        $constructedUrl = $urlScheme.'://'.$urlHost;
        if (null !== $urlPort = \parse_url($urlToMatch, PHP_URL_PORT)) {
            $constructedUrl .= ':'.(string) $urlPort;
        }

        if ($httpOrigin !== $constructedUrl) {
            throw new HttpException(400, 'URL does not match Origin');
        }

        return $urlToMatch;
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
                $availableIdpInfoList = $this->getAvailableIdpInfoList();
                $returnTo = self::verifyMatchesOrigin($request->getOrigin(), $request->requireQueryParameter('ReturnTo'));
                $authnContextClassRef = self::verifyAuthnContextClassRef($request->optionalQueryParameter('AuthnContextClassRef'));
                $scopingIdpList = self::verifyScopingIdpList($request->optionalQueryParameter('ScopingIdpList'));
                if (1 === \count($availableIdpInfoList)) {
                    // we only have 1 IdP, so use that
                    $idpEntityId = \array_keys($availableIdpInfoList)[0];

                    return new RedirectResponse($this->sp->login($idpEntityId, $returnTo, $authnContextClassRef, $scopingIdpList));
                }

                if (null !== $idpEntityId = $request->optionalQueryParameter('IdP')) {
                    $idpEntityId = self::verifyEntityId($idpEntityId);
                    // an IdP entity ID is provided as a query parameter, make
                    // sure it is allowed...
                    if (!\array_key_exists($idpEntityId, $availableIdpInfoList)) {
                        throw new HttpException(400, \sprintf('IdP "%s" is not available', $idpEntityId));
                    }

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
                // sort the IdPs by display name
                \uasort($availableIdpInfoList, function (IdpInfo $a, IdpInfo $b) {
                    return \strcasecmp($a->getDisplayName(), $b->getDisplayName());
                });

                $lastChosenIdpInfo = null;
                if (null !== $lastChosenIdp = $this->cookie->get(self::LAST_CHOSEN_COOKIE_NAME)) {
                    // make sure IdP (still) exists
                    if (\array_key_exists($lastChosenIdp, $availableIdpInfoList)) {
                        $lastChosenIdpInfo = $availableIdpInfoList[$lastChosenIdp];
                        unset($availableIdpInfoList[$lastChosenIdp]);
                    }
                }

                return new HtmlResponse(
                    $this->tpl->render(
                        'wayf',
                        [
                            'lastChosenIdpInfo' => $lastChosenIdpInfo,
                            'idpInfoList' => $availableIdpInfoList,
                        ]
                    )
                );
            // exposes the SP metadata for IdP consumption
            case '/metadata':
                // add new line to end of output
                $metadataStr = $this->sp->metadata().PHP_EOL;

                return new Response(200, ['Content-Type' => 'application/samlmetadata+xml'], $metadataStr);
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
                // we do NOT require CSRF protection here
                $returnTo = $this->sp->handleResponse($request->requirePostParameter('SAMLResponse'), $request->requirePostParameter('RelayState'));

                return new RedirectResponse($returnTo);
            case '/login':
                self::verifyMatchesOrigin($request->getOrigin(), $request->requireHeader('HTTP_REFERER'));
                $returnTo = self::verifyMatchesOrigin($request->getOrigin(), $request->getUri());
                $idpEntityId = self::verifyEntityId($request->requirePostParameter('IdP'));
                // we do not have to make sure the IdP is actually available
                // in the metadata (or allowed) as the GET to /login where this
                // POST will redirect to will take care of this...
                $this->cookie->set(self::LAST_CHOSEN_COOKIE_NAME, $idpEntityId);

                return new RedirectResponse($returnTo.'&'.\http_build_query(['IdP' => $idpEntityId]));
            // user triggered logout
            case '/logout':
                self::verifyMatchesOrigin($request->getOrigin(), $request->requireHeader('HTTP_REFERER'));
                $returnTo = self::verifyMatchesOrigin($request->getOrigin(), $request->requirePostParameter('ReturnTo'));

                return new RedirectResponse($this->sp->logout($returnTo));
            case '/setLanguage':
                $returnTo = self::verifyMatchesOrigin($request->getOrigin(), $request->requireHeader('HTTP_REFERER'));
                // we don't care what uiLanguage is, it can be anything, it
                // will be verified by Tpl::setLanguage. User can provide any
                // cookie value anyway!
                $this->cookie->set('L', $request->requirePostParameter('uiLanguage'));

                return new RedirectResponse($returnTo);
            default:
                throw new HttpException(404, 'URL not found: '.$request->getPathInfo());
        }
    }

    /**
     * @return array<string,IdpInfo>
     */
    private function getAvailableIdpInfoList()
    {
        if (null === $configIdpList = $this->config->getIdpList()) {
            // the "idpList" entry is NOT specified, so all IdPs are allowed
            // that can be found through available SAML metadata
            return $this->sp->getIdpSource()->getAll();
        }

        // only a subset of IdPs can be used for authentication
        $availableIdpInfoList = [];
        foreach ($configIdpList as $entityId) {
            if (null === $idpInfo = $this->sp->getIdpSource()->get($entityId)) {
                throw new HttpException(500, \sprintf('no metadata for IdP "%s" available', $entityId));
            }
            $availableIdpInfoList[$entityId] = $idpInfo;
        }

        return $availableIdpInfoList;
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

    /**
     * @param string $entityId
     *
     * @return string
     */
    private static function verifyEntityId($entityId)
    {
        // we took all IdP entityID entries from eduGAIN metadata and made sure
        // the filter accepts all of those... anything outside this range is
        // probably not a valid xsd:anyURI anyway... this may need tweaking!
        //
        // Maybe it is enough to allow everything, except DQUOTE (")?
        if (1 !== \preg_match('|^[0-9a-zA-Z-./:=_?]+$|', $entityId)) {
            throw new HttpException(400, 'invalid entityID');
        }

        return $entityId;
    }
}
