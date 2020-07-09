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

class IdpInfoSource
{
    /** @var array<SourceInterface> */
    private $sourceList = [];

    /**
     * @param array<SourceInterface> $sourceList */
    public function __construct(array $sourceList)
    {
        $this->sourceList = $sourceList;
    }

    /**
     * @return array<IdpInfo>
     */
    public function getAll()
    {
        $idpInfoList = [];
        foreach ($this->sourceList as $source) {
            $xmlStringList = $source->getAll();
            if (0 === \count($xmlStringList)) {
                // this source does not have any, continue at next source
                // XXX this is NOT great if the set is not exactly the same...
                continue;
            }
            foreach ($xmlStringList as $xmlString) {
                $idpInfoList[] = IdpInfo::fromXml($xmlString);
            }
        }

        return $idpInfoList;
    }

    /**
     * @param string $entityId
     *
     * @return IdpInfo|null
     */
    public function get($entityId)
    {
        foreach ($this->sourceList as $source) {
            if (null !== $xmlString = $source->get($entityId)) {
                return IdpInfo::fromXml($xmlString);
            }
        }

        return null;
    }
}
