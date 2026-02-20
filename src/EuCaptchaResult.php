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
 * Holds the outcome of an EU-Captcha token verification.
 *
 * Three independent states are tracked so callers can distinguish a
 * token failure (the user did not solve the captcha), a network failure
 * (the API could not be reached), and a bypass (the API skipped real
 * validation due to misconfigured credentials):
 *
 *   - stateNetwork: true when the API call completed without error.
 *   - stateToken:   true when the API reported the token as valid.
 *   - stateTrain:   true when the API skipped real validation and forced
 *                   success (misconfigured credentials or disabled protection).
 *                   Null when no API response was received.
 *
 * success() returns true only when all three states indicate a clean,
 * real validation: network succeeded, token is valid, and train is not set.
 */
class EuCaptchaResult
{
    /**
     * Whether the API call itself succeeded (no network/transport error).
     *
     * @var bool
     */
    protected $stateNetwork;

    /**
     * Whether the API reported the submitted token as valid.
     *
     * @var bool
     */
    protected $stateToken;

    /**
     * The `train` flag from the API response.
     *
     * True means validation was skipped and success was forced (misconfigured
     * credentials or disabled protection). False means normal operation. Null
     * when no API response was received (network failure).
     *
     * @var bool|null
     */
    protected $stateTrain;

    /**
     * @param bool      $stateNetwork True if the HTTP request completed without error.
     * @param bool      $stateToken   True if the API reported the token as valid.
     * @param bool|null $stateTrain   The `train` flag from the API response, or null on network failure.
     */
    public function __construct($stateNetwork, $stateToken, $stateTrain = null)
    {
        $this->stateNetwork = $stateNetwork;
        $this->stateToken   = $stateToken;
        $this->stateTrain   = $stateTrain;
    }

    /**
     * Returns true only when the network call succeeded, the token was valid,
     * and the `train` flag is not set.
     *
     * When `train` is true the API forced `success` to true without performing
     * real validation (misconfigured credentials or disabled protection). This
     * method treats that case as a failure so misconfigured sites fail securely
     * by default. Use isTrain() to inspect the flag directly.
     *
     * @return bool
     */
    public function success()
    {
        return ($this->stateNetwork && $this->stateToken && !$this->stateTrain);
    }

    /**
     * Returns true when the API call completed without a network or transport error.
     *
     * @return bool
     */
    public function successNetwork()
    {
        return $this->stateNetwork;
    }

    /**
     * Returns true when the API reported the submitted token as valid.
     *
     * Note: this reflects the raw `success` field from the API response. When
     * isTrain() returns true, the API forced this field to true without real
     * validation. Prefer success() for the safe combined check.
     *
     * @return bool
     */
    public function successToken()
    {
        return $this->stateToken;
    }

    /**
     * Returns the `train` flag from the API response.
     *
     * True means the API skipped real validation and forced `success` to true —
     * typically because the sitekey does not exist, the secret does not match,
     * or the sitekey's protection toggle is disabled. In production this means
     * every submission appears successful regardless of whether the user solved
     * the captcha. Check your sitekey and secret immediately if you see this.
     *
     * False means normal operation and successToken() reflects the real result.
     *
     * Null means no API response was received (network failure) so the train
     * state is unknown.
     *
     * @return bool|null
     */
    public function isTrain()
    {
        return $this->stateTrain;
    }
}
