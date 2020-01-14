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

namespace fkooman\SAML\SP;

use fkooman\SAML\SP\Exception\SessionException;

class PhpSession implements SessionInterface
{
    /**
     * @param string $sessionName
     * @param bool   $secureCookie
     *
     * @return void
     */
    public function start($sessionName, $secureCookie)
    {
        if (PHP_SESSION_ACTIVE === \session_status()) {
            throw new SessionException('session already active');
        }
        \session_name($sessionName);
        // use ugly hack for old (<= 7.3) versions of PHP to support
        // "SameSite" (idea taken from simpleSAMLphp)
        \session_set_cookie_params(0, '/; SameSite=None', null, $secureCookie, true);
        \session_start();
    }

    /**
     * @return void
     */
    public function regenerate()
    {
        self::requireSession();
        \session_regenerate_id(true);
    }

    /**
     * @param string $key
     *
     * @return string|null
     */
    public function get($key)
    {
        self::requireSession();
        if (!\array_key_exists($key, $_SESSION)) {
            return null;
        }

        return $_SESSION[$key];
    }

    /**
     * @param string $key
     *
     * @return string|null
     */
    public function take($key)
    {
        $sessionValue = $this->get($key);
        $this->delete($key);

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
        self::requireSession();
        $_SESSION[$key] = $value;
    }

    /**
     * @param string $key
     *
     * @return void
     */
    public function delete($key)
    {
        self::requireSession();
        unset($_SESSION[$key]);
    }

    /**
     * @return void
     */
    private static function requireSession()
    {
        if (PHP_SESSION_ACTIVE !== \session_status()) {
            // we MUST have an active session
            throw new SessionException('no active session');
        }
    }
}
