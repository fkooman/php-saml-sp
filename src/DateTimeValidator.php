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

use DateInterval;
use DateTime;

class DateTimeValidator
{
    /**
     * @param \DateTime $currentDateTime
     * @param \DateTime $dateTime
     *
     * @return bool
     */
    public static function isBefore(DateTime $currentDateTime, DateTime $dateTime)
    {
        $lowerLimit = \date_sub(clone $dateTime, new DateInterval('PT180S'));

        return $currentDateTime < $lowerLimit;
    }

    /**
     * @param \DateTime $currentDateTime
     * @param \DateTime $dateTime
     *
     * @return bool
     */
    public static function isOnOrAfter(DateTime $currentDateTime, DateTime $dateTime)
    {
        $upperLimit = \date_add(clone $dateTime, new DateInterval('PT180S'));

        return $currentDateTime >= $upperLimit;
    }
}
