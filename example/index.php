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

// manual install in /var/www/html/php-saml-sp
//require_once '/var/www/html/php-saml-sp/vendor/autoload.php';

// when using Debian/Fedora/CentOS/RHEL package
//require_once '/usr/share/php/fkooman/SAML/SP/autoload.php';

use fkooman\SAML\SP\Api\SamlAuth;

$samlAuth = new SamlAuth();
$authInfo = $samlAuth->requireAuth();
if (\is_string($authInfo)) {
    // ugly API, we need to come up with something better!
    \header('Location: '.$authInfo);
    exit(0);
}

echo \htmlentities($authInfo->getIssuer()).'<br>';
echo \htmlentities($authInfo->getNameId()->toXml()).'<br>';
