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

use ReCaptcha\RequestParameters;

class PostTest extends \PHPUnit_Framework_TestCase
{
    public static $assert = null;
    /** @var RequestParameters */
    protected $parameters = null;
    protected $runcount = 0;

    public function setUp()
    {
        $this->parameters = new RequestParameters("secret", "response", "remoteip", "version");
    }

    public function tearDown()
    {
        self::$assert = null;
    }

    public function testHTTPContextOptions()
    {
        $req = new Post();
        self::$assert = array($this, "httpContextOptionsCallback");
        $req->submit($this->parameters);
        $this->assertEquals(1, $this->runcount, "The assertion was ran");
    }

    public function testSSLContextOptions()
    {
        $req = new Post();
        self::$assert = array($this, "sslContextOptionsCallback");
        $req->submit($this->parameters);
        $this->assertEquals(1, $this->runcount, "The assertion was ran");
    }

    public function httpContextOptionsCallback(array $args)
    {
        $this->runcount++;
        $this->assertCommonOptions($args);

        $options = stream_context_get_options($args[2]);
        $this->assertArrayHasKey('http', $options);

        $this->assertArrayHasKey('method', $options['http']);
        $this->assertEquals("POST", $options['http']['method']);

        $this->assertArrayHasKey('content', $options['http']);
        $this->assertEquals($this->parameters->toQueryString(), $options['http']['content']);

        $this->assertArrayHasKey('header', $options['http']);
        $headers = array(
            "Content-type: application/x-www-form-urlencoded",
        );
        foreach ($headers as $header) {
            $this->assertContains($header, $options['http']['header']);
        }
    }

    public function sslContextOptionsCallback(array $args)
    {
        $this->runcount++;
        $this->assertCommonOptions($args);

        $options = stream_context_get_options($args[2]);
        $this->assertArrayHasKey('http', $options);
        $this->assertArrayHasKey('verify_peer', $options['http']);
        $this->assertTrue($options['http']['verify_peer']);

        $key = version_compare(PHP_VERSION, "5.6.0", "<") ? "CN_name" : "peer_name";

        $this->assertArrayHasKey($key, $options['http']);
        $this->assertEquals("www.google.com", $options['http'][$key]);
    }

    protected function assertCommonOptions(array $args)
    {
        $this->assertCount(3, $args);
        $this->assertStringStartsWith("https://www.google.com/", $args[0]);
        $this->assertFalse($args[1]);
        $this->assertTrue(is_resource($args[2]), "The context options should be a resource");
    }

    public function httpContextWithGivenOptionsCallback(array $args)
    {
        $this->httpContextOptionsCallback($args);
        $options = stream_context_get_options($args[2]);
        $headers = array(
            "X-Header-Test: a test",
        );
        foreach ($headers as $header) {
            $this->assertContains($header, $options['http']['header']);
        }

        $this->assertArrayHasKey('ssl', $options);
        $this->assertArrayHasKey('verify_peer_name', $options['ssl']);
        $this->assertEquals(true, $options['ssl']['verify_peer_name']);

        $this->assertArrayHasKey('proxy', $options['http']);
    }

    public function testHTTPContextWithGivenOptions()
    {
        $options = array(
            'http' => array(
                // test append option
                'proxy' => 'tcp://proxy.example.com:5100',
                // test replace option
                'header' => "Content-type: application/x-www-form-urlencoded\r\n".
                            "X-Header-Test: a test\r\n",
            ),
            // test new option
            'ssl' => array(
                'verify_peer_name' => true,
            ),
        );
        $req = new Post($options);
        self::$assert = array($this, "httpContextWithGivenOptionsCallback");
        $req->submit($this->parameters);
        $this->assertEquals(1, $this->runcount, "The assertion was ran");
    }
}

function file_get_contents()
{
    if (PostTest::$assert) {
        return call_user_func(PostTest::$assert, func_get_args());
    }
    // Since we can't represent maxlen in userland...
    return call_user_func_array('file_get_contents', func_get_args());
}
