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

use RuntimeException;

class Config
{
    /** @var array */
    private $configData;

    public function __construct(array $configData)
    {
        $this->configData = $configData;
    }

    /**
     * @param string $k
     *
     * @return mixed
     */
    public function requireKey($k)
    {
        if (!\array_key_exists($k, $this->configData)) {
            return null;
        }

        return $this->configData[$k];
    }

    /**
     * @param string $s
     *
     * @return self|null
     */
    public function requireSection($s)
    {
        if (!\array_key_exists($s, $this->configData)) {
            return null;
        }

        if (!\is_array($this->configData[$s])) {
            return null;
        }

        return new self($this->configData[$s]);
    }

    /**
     * @param string $configFile
     *
     * @return self
     */
    public static function fromFile($configFile)
    {
        $configData = include $configFile;
        if (!\is_array($configData)) {
            throw new RuntimeException('invalid configuration file format');
        }

        return new self($configData);
    }
}
