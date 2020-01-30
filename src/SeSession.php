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

namespace fkooman\SAML\SP;

use fkooman\SeCookie\CookieOptions;
use fkooman\SeCookie\Session;
use fkooman\SeCookie\SessionOptions;

class SeSession implements SessionInterface
{
    /** @var \fkooman\SeCookie\Session */
    private $session;

    /**
     * @param bool $secureCookie
     */
    public function __construct($secureCookie)
    {
        $this->session = new Session(
            SessionOptions::init()->setName('PSSSID'),
            CookieOptions::init()->setSecure($secureCookie)->setPath('/')->setSameSite('None')
        );
    }

    /**
     * @return void
     */
    public function regenerate()
    {
        $this->session->start();
        $this->session->regenerate();
    }

    /**
     * @param string $key
     *
     * @return string|null
     */
    public function get($key)
    {
        $this->session->start();

        return $this->session->get($key);
    }

    /**
     * @param string $key
     *
     * @return string|null
     */
    public function take($key)
    {
        $this->session->start();
        $sessionValue = $this->session->get($key);
        $this->session->remove($key);

        return $sessionValue;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return void
     */
    public function set($key, $value)
    {
        $this->session->start();
        $this->session->set($key, $value);
    }

    /**
     * @param string $key
     *
     * @return void
     */
    public function remove($key)
    {
        $this->session->start();
        $this->session->remove($key);
    }
}
