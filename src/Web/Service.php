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
                    // we still don't know which IdP to choose, so allow user
                    // to choose

//                    // if a discovery service is specified, use that one
//                    if (null !== $discoUrl = $this->config->requireKey('discoUrl')) {
//                        // XXX maybe we should make ReturnTo required? now this is a bit crazy...
//                        $returnUrl = \sprintf('%s?%s', $request->getRootUri().'login', \http_build_query(['ReturnTo' => $returnTo]));
//                        $discoQuery = \http_build_query(
//                            [
//                                'entityID' => $this->sp->getSpInfo()->getEntityId(),
//                                'returnIDParam' => 'IdP',
//                                'return' => $returnUrl,
//                            ]
//                        );

//                        $querySeparator = false === \strpos($discoUrl, '?') ? '?' : '&';

//                        return new RedirectResponse(
//                            \sprintf(
//                                '%s%s%s',
//                                $discoUrl,
//                                $querySeparator,
//                                $discoQuery
//                            )
//                        );
//                    }

                    // otherwise, show them a simple "WAYF"
                    return new HtmlResponse(
                        $this->tpl->render(
                            'wayf',
                            [
                                'returnTo' => $returnTo,
                                'availableIdpList' => $availableIdpList,
                            ]
                        )
                    );
                }

                // make sure the provided IdP exists
                // XXX does sp->login take care of this as well?!
                if (!\in_array($idpEntityId, $availableIdpList, true)) {
                    throw new HttpException('IdP does not exist', 400);
                }

                // we know which IdP to go to!
                return new RedirectResponse($this->sp->login($idpEntityId, $returnTo));

            // user triggered logout
            case '/logout':
                return new RedirectResponse($this->sp->logout($request->getRootUri()));

            // callback from IdP containing the "SAMLResponse"
            case '/acs':
                if ('POST' === $request->getRequestMethod()) {
                    // listen only for POST HTTP request
                    $returnTo = $this->sp->handleResponse($request->requirePostParameter('SAMLResponse'), $request->requirePostParameter('RelayState'));

                    return new RedirectResponse($returnTo);
                }

                return new Response(405, [], '[405] only POST allowed on ACS');

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
                return new Response(404, [], '[404] page not found');
        }
    }
}
