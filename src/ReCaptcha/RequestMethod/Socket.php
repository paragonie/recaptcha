<?php
/**
 * This is a PHP library that handles calling reCAPTCHA.
 *
 * @copyright Copyright (c) 2015, Google Inc.
 * @link      http://www.google.com/recaptcha
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace ReCaptcha\RequestMethod;

/**
 * Convenience wrapper around native socket and file functions to allow for
 * mocking.
 */
class Socket
{
    /**
     * @var resource
     */
    private $handle = null;

    /**
     * fsockopen
     * 
     * @see http://php.net/fsockopen
     * @param string $hostname
     * @param int $port
     * @param int $errno
     * @param string $errstr
     * @param float $timeout
     * @return resource|bool
     */
    public function fsockopen($hostname, $port = -1, &$errno = 0, &$errstr = '', $timeout = null)
    {
        $this->handle = fsockopen(
            $hostname,
            $port,
            $errno,
            $errstr,
            (
                \is_null($timeout)
                    ? (int) ini_get("default_socket_timeout")
                    : $timeout
            )
        );

        if ($this->handle != false && $errno === 0 && $errstr === '') {
            return $this->handle;
        }
        return false;
    }

    /**
     * fwrite
     * 
     * @see http://php.net/fwrite
     * @param string $string
     * @param int $length
     * @return int|bool
     */
    public function fwrite($string, $length = null)
    {
        if (!\is_resource($this->handle)) {
            throw new \RuntimeException('Handle not opened');
        }
        return fwrite($this->handle, $string, (is_null($length) ? strlen($string) : $length));
    }

    /**
     * fgets
     * 
     * @see http://php.net/fgets
     * @param int $length
     * @return string
     */
    public function fgets($length = null)
    {
        if (!\is_resource($this->handle)) {
            throw new \RuntimeException('Handle not opened');
        }
        /** @var int $length */
        $result = fgets($this->handle, $length);
        if (!\is_string($result)) {
            throw new \RuntimeException('Could not read from socket');
        }
        return $result;
    }

    /**
     * feof
     * 
     * @see http://php.net/feof
     * @return bool
     */
    public function feof()
    {
        if (!\is_resource($this->handle)) {
            throw new \RuntimeException('Handle not opened');
        }
        return feof($this->handle);
    }

    /**
     * fclose
     * 
     * @see http://php.net/fclose
     * @return bool
     */
    public function fclose()
    {
        if (!\is_resource($this->handle)) {
            throw new \RuntimeException('Handle not opened');
        }
        return fclose($this->handle);
    }
}
