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

namespace fkooman\SAML\SP\Web;

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

    public function __construct(Config $config, Tpl $tpl, SP $sp)
    {
        $this->config = $config;
        $this->tpl = $tpl;
        $this->sp = $sp;
    }

    /**
     * @return Response
     */
    public function run(Request $request)
    {
        try {
            switch ($request->getRequestMethod()) {
                case 'HEAD':
                case 'GET':
                    return $this->runGet($request);
                case 'POST':
                    return $this->runPost($request);
                default:
                    throw new HttpException(405, 'Only HTTP POST allowed', ['Allow' => 'GET,HEAD,POST']);
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
    public function runGet(Request $request)
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
                if (null === $availableIdpList = $this->config->requireKey('idpList')) {
                    $availableIdpList = [];
                }

                if (null === $idpEntityId = $request->optionalQueryParameter('IdP')) {
                    // check whether we have exactly 1 configured IdP, then use
                    // that one!
                    if (1 === \count($availableIdpList)) {
                        $idpEntityId = $availableIdpList[0];
                    }
                }

                // XXX validate ReturnTo... should it at least match Origin?!
                $returnTo = $request->requireQueryParameter('ReturnTo');

                if (null === $idpEntityId) {
                    // we don't know the IdP (yet)
                    if (null !== $discoUrl = $this->config->requireKey('discoUrl')) {
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
                            $idpInfoList[] = $this->sp->getIdpInfoSource()->get($availableIdp);
                        }
                    }

                    return new HtmlResponse(
                        $this->tpl->render(
                            'wayf',
                            [
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

                // we know which IdP to go to!
                return new RedirectResponse($this->sp->login($idpEntityId, $returnTo));
            // user triggered logout
            case '/logout':
                // XXX validate ReturnTo... should it at least match Origin?!
                $returnTo = $request->requireQueryParameter('ReturnTo');

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
    public function runPost(Request $request)
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
}
