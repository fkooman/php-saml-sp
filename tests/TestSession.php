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

namespace fkooman\SAML\SP\Tests;

use fkooman\SAML\SP\Exception\SessionException;
use fkooman\SAML\SP\SessionInterface;

class TestSession implements SessionInterface
{
    private $sessionData = [];

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has($key)
    {
        return \array_key_exists($key, $this->sessionData);
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
        if (!$this->has($key)) {
            throw new SessionException(\sprintf('key "%s" not found in session', $key));
        }

        return $this->sessionData[$key];
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
        $this->sessionData[$key] = $value;
    }

    /**
     * @param string $key
     *
     * @return void
     */
    public function delete($key)
    {
        unset($this->sessionData[$key]);
    }
}
