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

use fkooman\SAML\SP\QueryParameters;
use PHPUnit\Framework\TestCase;

class QueryParametersTest extends TestCase
{
    public function testSimple()
    {
        $qp = new QueryParameters('foo=bar&bar=foo');
        $this->assertSame('bar', $qp->requireQueryParameter('foo'));
        $this->assertSame('foo', $qp->requireQueryParameter('bar'));
        $this->assertNull($qp->optionalQueryParameter('baz'));
    }

    public function testRaw()
    {
        $qp = new QueryParameters('foo=bar%2e&bar=foo');
        $this->assertSame('bar.', $qp->requireQueryParameter('foo'));
        $this->assertSame('bar%2e', $qp->requireQueryParameter('foo', true));
    }

    public function testDuplicate()
    {
        $qp = new QueryParameters('foo=bar&foo=baz');
        $this->assertSame('baz', $qp->requireQueryParameter('foo'));
    }

    public function testEmptyValue()
    {
        $qp = new QueryParameters('foo');
        $this->assertSame('', $qp->requireQueryParameter('foo'));
    }

    public function testMultiEmpty()
    {
        $qp = new QueryParameters('foo===');
        $this->assertSame('==', $qp->requireQueryParameter('foo'));
    }
}
