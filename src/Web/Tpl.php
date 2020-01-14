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

use DateTime;
use DateTimeZone;
use fkooman\SAML\SP\Web\Exception\TplException;

class Tpl
{
    /** @var array<string> */
    private $templateFolderList;

    /** @var array<string> */
    private $translationFileList;

    /** @var string|null */
    private $activeSectionName = null;

    /** @var array<string,string> */
    private $sectionList = [];

    /** @var array<string,array> */
    private $layoutList = [];

    /** @var array<string,mixed> */
    private $templateVariables = [];

    /** @var array<string,callable> */
    private $callbackList = [];

    /**
     * @param array<string> $templateFolderList
     * @param array<string> $translationFileList
     */
    public function __construct(array $templateFolderList, array $translationFileList = [])
    {
        $this->templateFolderList = $templateFolderList;
        $this->translationFileList = $translationFileList;
    }

    /**
     * @param array<string,mixed> $templateVariables
     *
     * @return void
     */
    public function addDefault(array $templateVariables)
    {
        $this->templateVariables = \array_merge($this->templateVariables, $templateVariables);
    }

    /**
     * @param string $callbackName
     *
     * @return void
     */
    public function addCallback($callbackName, callable $cb)
    {
        $this->callbackList[$callbackName] = $cb;
    }

    /**
     * @param string              $templateName
     * @param array<string,mixed> $templateVariables
     *
     * @return string
     */
    public function render($templateName, array $templateVariables = [])
    {
        $this->templateVariables = \array_merge($this->templateVariables, $templateVariables);
        \extract($this->templateVariables);
        \ob_start();
        /** @psalm-suppress UnresolvableInclude */
        include $this->templatePath($templateName);
        $templateStr = \ob_get_clean();
        if (0 === \count($this->layoutList)) {
            // we have no layout defined, so simple template...
            return $templateStr;
        }

        foreach ($this->layoutList as $templateName => $templateVariables) {
            unset($this->layoutList[$templateName]);
            $templateStr .= $this->render($templateName, $templateVariables);
        }

        return $templateStr;
    }

    /**
     * @param string              $templateName
     * @param array<string,mixed> $templateVariables
     *
     * @return string
     */
    private function insert($templateName, array $templateVariables = [])
    {
        return $this->render($templateName, $templateVariables);
    }

    /**
     * @param string $sectionName
     *
     * @return void
     */
    private function start($sectionName)
    {
        if (null !== $this->activeSectionName) {
            throw new TplException(\sprintf('section "%s" already started', $this->activeSectionName));
        }

        $this->activeSectionName = $sectionName;
        \ob_start();
    }

    /**
     * @param string $sectionName
     *
     * @return void
     */
    private function stop($sectionName)
    {
        if (null === $this->activeSectionName) {
            throw new TplException('no section started');
        }

        if ($sectionName !== $this->activeSectionName) {
            throw new TplException(\sprintf('attempted to end section "%s" but current section is "%s"', $sectionName, $this->activeSectionName));
        }

        $this->sectionList[$this->activeSectionName] = \ob_get_clean();
        $this->activeSectionName = null;
    }

    /**
     * @param string              $layoutName
     * @param array<string,mixed> $templateVariables
     *
     * @return void
     */
    private function layout($layoutName, array $templateVariables = [])
    {
        $this->layoutList[$layoutName] = $templateVariables;
    }

    /**
     * @param string $sectionName
     *
     * @return string
     */
    private function section($sectionName)
    {
        if (!\array_key_exists($sectionName, $this->sectionList)) {
            throw new TplException(\sprintf('section "%s" does not exist', $sectionName));
        }

        return $this->sectionList[$sectionName];
    }

    /**
     * @param string      $v
     * @param string|null $cb
     *
     * @return string
     */
    private function e($v, $cb = null)
    {
        if (null !== $cb) {
            $v = $this->batch($v, $cb);
        }

        return \htmlentities($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * @param string $v
     * @param string $cb
     *
     * @return string
     */
    private function batch($v, $cb)
    {
        $functionList = \explode('|', $cb);
        foreach ($functionList as $f) {
            if ('escape' === $f) {
                $v = $this->e($v);
                continue;
            }
            if (\array_key_exists($f, $this->callbackList)) {
                $f = $this->callbackList[$f];
            } else {
                if (!\function_exists($f)) {
                    throw new TplException(\sprintf('function "%s" does not exist', $f));
                }
            }
            $v = \call_user_func($f, $v);
        }

        return $v;
    }

    /**
     * Format a date.
     *
     * @param string $dateString
     * @param string $dateFormat
     *
     * @return string
     */
    private function d($dateString, $dateFormat = 'Y-m-d H:i:s')
    {
        $dateTime = new DateTime($dateString);
        $dateTime->setTimeZone(new DateTimeZone(\date_default_timezone_get()));

        return $this->e(\date_format($dateTime, $dateFormat));
    }

    /**
     * @param string $v
     *
     * @return string
     */
    private function t($v)
    {
        // use original, unless it is found in any of the translation files...
        $translatedText = $v;
        foreach ($this->translationFileList as $translationFile) {
            // XXX should we make sure the file exists?
            /** @psalm-suppress UnresolvableInclude */
            $translationData = include $translationFile;
            if (\array_key_exists($v, $translationData)) {
                // translation found!
                $translatedText = $translationData[$v];
                // XXX do we want to loop over all of them?! take the first,
                // or the last?
                break;
            }
        }

        // find all string values, wrap the key, and escape the variable
        $escapedVars = [];
        foreach ($this->templateVariables as $k => $v) {
            if (\is_string($v)) {
                $escapedVars['%'.$k.'%'] = $this->e($v);
            }
        }

        return \str_replace(\array_keys($escapedVars), \array_values($escapedVars), $translatedText);
    }

    /**
     * @param string $templateName
     *
     * @return bool
     */
    private function exists($templateName)
    {
        foreach ($this->templateFolderList as $templateFolder) {
            $templatePath = \sprintf('%s/%s.php', $templateFolder, $templateName);
            if (\file_exists($templatePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $templateName
     *
     * @return string
     */
    private function templatePath($templateName)
    {
        foreach (\array_reverse($this->templateFolderList) as $templateFolder) {
            $templatePath = \sprintf('%s/%s.php', $templateFolder, $templateName);
            if (\file_exists($templatePath)) {
                return $templatePath;
            }
        }

        throw new TplException(\sprintf('template "%s" does not exist', $templateName));
    }
}