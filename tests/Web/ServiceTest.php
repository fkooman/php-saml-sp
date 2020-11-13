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

namespace fkooman\SAML\SP\Tests\Web;

use fkooman\SAML\SP\Web\Exception\HttpException;
use fkooman\SAML\SP\Web\Service;
use PHPUnit\Framework\TestCase;

class ServiceTest extends TestCase
{
    public function testVerifyReturnToOrigin()
    {
        $this->assertSame(
            'https://www.example.org/foo?a=b',
            Service::verifyMatchesOrigin('https://www.example.org', 'https://www.example.org/foo?a=b')
        );
    }

    public function testInvalidReturnToOrigin()
    {
        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('URL does not match Origin');
        Service::verifyMatchesOrigin('https://www.example.org', 'https://www.example.com/foo?a=b');
    }

    public function testInvalidReturnToOriginUser()
    {
        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('URL must not contain authentication information');
        Service::verifyMatchesOrigin('https://www.example.org', 'https://a\@www.example.org/foo?a=b');
    }
}
