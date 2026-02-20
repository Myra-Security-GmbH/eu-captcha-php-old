<?php

/*
 * Copyright (c) 2026 Myra Security GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

declare(strict_types=1);

namespace Myrasec\Tests;

use Myrasec\EU_Captcha;
use Myrasec\EU_Captcha_Result;
use PHPUnit\Framework\TestCase;

/**
 * Testable subclass that stubs doApiCall() so no real HTTP requests are made.
 *
 * Set $mockedResponse to the JSON string the API should appear to return,
 * or false to simulate a network failure.
 * After calling validate(), $lastCallData holds the array that was passed
 * to doApiCall(), allowing assertions on what was sent to the API.
 */
class TestableEuCaptcha extends EU_Captcha
{
    /** @var string|false */
    public $mockedResponse = false;

    /** @var array|null */
    public $lastCallData = null;

    protected function doApiCall($url, $data)
    {
        $this->lastCallData = $data;

        return $this->mockedResponse;
    }
}

class EU_CaptchaTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public function testConstructorThrowsOnMissingSitekey(): void
    {
        $this->expectException(\Exception::class);

        new EU_Captcha(['secret' => 'sec']);
    }

    public function testConstructorThrowsOnMissingSecret(): void
    {
        $this->expectException(\Exception::class);

        new EU_Captcha(['sitekey' => 'sk']);
    }

    public function testConstructorSucceedsWithValidCredentials(): void
    {
        $captcha = new EU_Captcha(['sitekey' => 'sk', 'secret' => 'sec']);

        $this->assertInstanceOf(EU_Captcha::class, $captcha);
    }

    // -------------------------------------------------------------------------
    // validate()
    // -------------------------------------------------------------------------

    public function testValidateSuccessWhenTokenIsValid(): void
    {
        $captcha                  = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse  = json_encode(['success' => true]);

        $result = $captcha->validate('good-token', '127.0.0.1');

        $this->assertTrue($result->success());
        $this->assertTrue($result->successNetwork());
        $this->assertTrue($result->successToken());
    }

    public function testValidateFailsWhenTokenIsInvalid(): void
    {
        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => false]);

        $result = $captcha->validate('bad-token', '127.0.0.1');

        $this->assertFalse($result->success());
        $this->assertTrue($result->successNetwork());
        $this->assertFalse($result->successToken());
    }

    public function testValidateOnNetworkFailureWithFailDefaultTrue(): void
    {
        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec', 'failDefault' => true]);
        $captcha->mockedResponse = false;

        $result = $captcha->validate('token', '127.0.0.1');

        $this->assertTrue($result->successNetwork());
        $this->assertTrue($result->successToken());
        $this->assertTrue($result->success());
    }

    public function testValidateOnNetworkFailureWithFailDefaultFalse(): void
    {
        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec', 'failDefault' => false]);
        $captcha->mockedResponse = false;

        $result = $captcha->validate('token', '127.0.0.1');

        $this->assertFalse($result->successNetwork());
        $this->assertFalse($result->successToken());
        $this->assertFalse($result->success());
    }

    public function testValidateOnMalformedResponseActsAsNetworkFailure(): void
    {
        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec', 'failDefault' => false]);
        $captcha->mockedResponse = 'not-json';

        $result = $captcha->validate('token', '127.0.0.1');

        $this->assertFalse($result->successNetwork());
        $this->assertFalse($result->successToken());
    }

    public function testValidateReadsTokenFromPost(): void
    {
        $_POST['eu-captcha-response'] = 'post-token';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate(null, '1.2.3.4');

        $this->assertSame('post-token', $captcha->lastCallData['response']);

        unset($_POST['eu-captcha-response']);
    }

    public function testValidateUsesEmptyTokenWhenPostIsAbsent(): void
    {
        unset($_POST['eu-captcha-response']);

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => false]);

        $captcha->validate(null, '1.2.3.4');

        $this->assertSame('', $captcha->lastCallData['response']);
    }

    public function testValidateSendsSuppliedRemoteAddr(): void
    {
        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token', '5.6.7.8');

        $this->assertSame('5.6.7.8', $captcha->lastCallData['remote']);
    }

    public function testValidateReadsRemoteAddrFromRemoteAddr(): void
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token');

        $this->assertSame('10.0.0.1', $captcha->lastCallData['remote']);

        unset($_SERVER['REMOTE_ADDR']);
    }

    // -------------------------------------------------------------------------
    // resolveClientIp() / check_cdn_headers
    // -------------------------------------------------------------------------

    public function testCheckCdnHeadersTrueUsesHttpClientIp(): void
    {
        $_SERVER['HTTP_CLIENT_IP']       = '203.0.113.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.2';
        $_SERVER['REMOTE_ADDR']          = '10.0.0.1';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token');

        $this->assertSame('203.0.113.1', $captcha->lastCallData['remote']);

        unset($_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['REMOTE_ADDR']);
    }

    public function testCheckCdnHeadersTrueUsesXForwardedForWhenNoClientIp(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.2';
        $_SERVER['REMOTE_ADDR']          = '10.0.0.1';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token');

        $this->assertSame('203.0.113.2', $captcha->lastCallData['remote']);

        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['REMOTE_ADDR']);
    }

    public function testCheckCdnHeadersTrueUsesFirstEntryOfXForwardedFor(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.10, 203.0.113.20, 10.0.0.1';
        $_SERVER['REMOTE_ADDR']          = '10.0.0.1';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token');

        $this->assertSame('203.0.113.10', $captcha->lastCallData['remote']);

        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['REMOTE_ADDR']);
    }

    public function testCheckCdnHeadersTrueUsesXRealIpAsFallback(): void
    {
        $_SERVER['HTTP_X_REAL_IP'] = '203.0.113.3';
        $_SERVER['REMOTE_ADDR']    = '10.0.0.1';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec']);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token');

        $this->assertSame('203.0.113.3', $captcha->lastCallData['remote']);

        unset($_SERVER['HTTP_X_REAL_IP'], $_SERVER['REMOTE_ADDR']);
    }

    public function testCheckCdnHeadersFalseIgnoresProxyHeadersAndUsesRemoteAddr(): void
    {
        $_SERVER['HTTP_CLIENT_IP']       = '203.0.113.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.2';
        $_SERVER['HTTP_X_REAL_IP']       = '203.0.113.3';
        $_SERVER['REMOTE_ADDR']          = '10.0.0.1';

        $captcha                 = new TestableEuCaptcha(['sitekey' => 'sk', 'secret' => 'sec', 'check_cdn_headers' => false]);
        $captcha->mockedResponse = json_encode(['success' => true]);

        $captcha->validate('token');

        $this->assertSame('10.0.0.1', $captcha->lastCallData['remote']);

        unset($_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['REMOTE_ADDR']);
    }
}
