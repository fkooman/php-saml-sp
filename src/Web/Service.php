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

use fkooman\SAML\SP\Crypto;
use fkooman\SAML\SP\Exception\SamlException;
use fkooman\SAML\SP\IdpInfo;
use fkooman\SAML\SP\SP;
use fkooman\SAML\SP\Web\Exception\HttpException;

class Service
{
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
                            'returnTo' => $request->getRootUri().'info',
                            'metadataUrl' => $request->getRootUri().'metadata',
                            'samlMetadata' => $this->sp->metadata(),
                            'decryptionSupport' => Crypto::hasDecryptionSupport(),
                        ]
                    )
                );
            case '/info':
                if (!$this->sp->hasAssertion()) {
                    return new RedirectResponse($request->getRootUri().'wayf?ReturnTo='.$request->getUri());
                }

                return new HtmlResponse(
                    $this->tpl->render(
                        'info',
                        [
                            'returnTo' => $request->getRootUri(),
                            'samlAssertion' => $this->sp->getAssertion(),
                        ]
                    )
                );
            case '/wayf':
                // get the list of IdPs that can be used
                if (null === $availableIdpList = $this->config->get('idpList')) {
                    $availableIdpList = [];
                }

                if (null === $idpEntityId = $request->optionalQueryParameter('IdP')) {
                    // check whether we have exactly 1 configured IdP, then use
                    // that one!
                    if (1 === \count($availableIdpList)) {
                        $idpEntityId = $availableIdpList[0];
                    }
                }

                $returnTo = self::verifyReturnToOrigin($request->getOrigin(), $request->requireQueryParameter('ReturnTo'));

                $discoUrl = $this->config->get('discoUrl');
                if (null === $idpEntityId) {
                    // we don't know the IdP (yet)
                    if (null !== $discoUrl) {
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

                    // we we use our own built-in simple "WAYF"
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
                    if (null !== $lastChosenIdp = $this->cookie->get('lastChosenIdp')) {
                        $lastChosenIdpInfo = $idpInfoList[$lastChosenIdp];
                    }

                    return new HtmlResponse(
                        $this->tpl->render(
                            'wayf',
                            [
                                'lastChosenIdpInfo' => $lastChosenIdpInfo,
                                'returnTo' => $returnTo,
                                'idpInfoList' => $idpInfoList,
                            ]
                        )
                    );
                }

                // make sure the provided IdP exists
                // XXX does sp->login take care of this as well?!
                if (!\in_array($idpEntityId, $availableIdpList, true)) {
                    throw new HttpException(400, 'IdP does not exist');
                }

                if (1 < \count($availableIdpList) && null === $discoUrl) {
                    // store the chosen IdP in case >= 1 is available and we
                    // use our own discovery
                    $this->cookie->set('lastChosenIdp', $idpEntityId);
                }

                // we know which IdP to go to!
                return new RedirectResponse($this->sp->login($idpEntityId, $returnTo));
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
        // there...
        $urlConstruction = $parsedUrl['scheme'].'://'.$parsedUrl['host'];
        if (\array_key_exists('port', $parsedUrl)) {
            $urlConstruction .= ':'.(string) $parsedUrl['port'];
        }

        if ($expectedOrigin !== $urlConstruction) {
            throw new HttpException(400, 'invalid "ReturnTo" provided');
        }

        return $returnTo;
    }
}
