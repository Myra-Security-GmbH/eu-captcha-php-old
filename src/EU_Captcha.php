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

namespace Myrasec;

/**
 * EU-Captcha client for PHP 5+.
 *
 * Verifies client tokens against the EU-Captcha API using
 * file_get_contents() with a stream context — no additional HTTP
 * libraries required.
 */
class EU_Captcha
{
    /** @var string Public sitekey that identifies your site. */
    protected $sitekey;

    /** @var string Private secret key for server-side verification. */
    protected $secret;

    /** @var string Full URL of the /verify endpoint. */
    protected $verifyUrl;

    /**
     * When true (default), a network or API failure is treated as a
     * successful validation so legitimate users are not blocked.
     * Set to false to fail closed on any API communication error.
     *
     * @var bool
     */
    protected $failDefault = true;

    /**
     * When true (default), the client IP is resolved from CDN/proxy
     * headers (HTTP_CLIENT_IP, HTTP_X_FORWARDED_FOR, HTTP_X_REAL_IP)
     * before falling back to REMOTE_ADDR.
     * Set to false when running behind no proxy, or when the caller
     * always supplies $remote_addr explicitly to validate().
     *
     * @var bool
     */
    protected $checkCdnHeaders = true;

    /**
     * Constructor.
     *
     * Accepted keys in $options:
     *   - sitekey           (string, required) Public sitekey.
     *   - secret            (string, required) Private secret key.
     *   - failDefault       (bool,   optional) Fail-open on network error. Default true.
     *   - checkCdnHeaders   (bool,   optional) Read client IP from proxy headers. Default true.
     *
     * @param  array $options Configuration options.
     * @throws \Exception If 'sitekey' or 'secret' are missing.
     */
    public function __construct(array $options = array())
    {
        if (!isset($options['sitekey'])) {
            throw new \Exception("missing option sitekey");
        }

        if (!isset($options['secret'])) {
            throw new \Exception("missing option secret");
        }

        $this->sitekey   = $options['sitekey'];
        $this->secret    = $options['secret'];
        $this->verifyUrl = 'https://api.eu-captcha.eu/v1/verify/';

        if (isset($options['failDefault'])) {
            $this->failDefault = (bool) $options['failDefault'];
        }

        if (isset($options['checkCdnHeaders'])) {
            $this->checkCdnHeaders = (bool) $options['checkCdnHeaders'];
        }
    }

    /**
     * Sends a JSON POST request to the given URL and returns the raw response body.
     *
     * Returns false on network failure.
     *
     * @param  string $url  Full endpoint URL.
     * @param  array  $data Associative array to JSON-encode as the request body.
     * @return string|false Response body, or false on failure.
     */
    protected function doApiCall($url, $data)
    {
        $context = stream_context_create(array(
            'http' => array(
                'method'  => 'POST',
                'content' => json_encode($data),
                'header'  => 'Content-Type: application/json',
            ),
        ));

        return file_get_contents($url, false, $context);
    }

    /**
     * Resolves the client IP address from the current request.
     *
     * When $checkCdnHeaders is true, the following $_SERVER keys are
     * checked in order; the first value that passes FILTER_VALIDATE_IP
     * is returned:
     *   HTTP_CLIENT_IP, HTTP_X_FORWARDED_FOR (first entry of a
     *   comma-separated list), HTTP_X_REAL_IP.
     * Falls back to REMOTE_ADDR in all cases.
     *
     * @return string Client IP address, or empty string if unavailable.
     */
    protected function resolveClientIp()
    {
        if ($this->checkCdnHeaders) {
            $headers = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP');
            foreach ($headers as $header) {
                if (!empty($_SERVER[$header])) {
                    $parts = explode(',', $_SERVER[$header]);
                    $ip    = trim($parts[0]);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        return $ip;
                    }
                }
            }
        }

        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    /**
     * Validates a captcha token against the EU-Captcha API.
     *
     * If $token is null, the value of $_POST['eu-captcha-response'] is
     * used (falling back to an empty string if also absent, so the API
     * still counts the attempt).
     * If $remote_addr is empty, the client IP is resolved automatically
     * via resolveClientIp().
     *
     * On network or API failure, both stateNetwork and stateToken are
     * set to $failDefault so callers can distinguish a clean failure
     * from a network problem.
     *
     * @param  string|null $token       Captcha response token from the form. Falls back to $_POST.
     * @param  string      $remote_addr Client IP address. Resolved automatically when empty.
     * @return EU_Captcha_Result
     */
    public function validate($token = null, $remote_addr = '')
    {
        if (is_null($token)) {
            $token = isset($_POST['eu-captcha-response']) ? $_POST['eu-captcha-response'] : '';
        }

        if (empty($remote_addr)) {
            $remote_addr = $this->resolveClientIp();
        }

        $data = array(
            'sitekey'  => $this->sitekey,
            'secret'   => $this->secret,
            'remote'   => $remote_addr,
            'response' => $token,
        );

        $json = $this->doApiCall($this->verifyUrl, $data);

        if ($json === false) {
            return new EU_Captcha_Result($this->failDefault, $this->failDefault);
        }

        $decode = json_decode($json, true);

        if (!is_array($decode) || !isset($decode['success'])) {
            return new EU_Captcha_Result($this->failDefault, $this->failDefault);
        }

        return new EU_Captcha_Result(true, (bool) $decode['success']);
    }
}
