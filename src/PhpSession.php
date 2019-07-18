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
     * @param string $key
     *
     * @return bool
     */
    public function has($key)
    {
        self::requireSession();

        return \array_key_exists($key, $_SESSION);
    }

    /**
     * Return the value of the session key.
     *
     * @param string $key
     *
     * @return string
     */
    public function get($key)
    {
        self::requireSession();
        if (!$this->has($key)) {
            throw new SessionException(\sprintf('key "%s" not found in session', $key));
        }

        return $_SESSION[$key];
    }

    /**
     * Return the value of the session key and delete the key.
     *
     * @param string $key
     *
     * @return string
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
     * @throws \fkooman\SAML\SP\Exception\SessionException
     *
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
