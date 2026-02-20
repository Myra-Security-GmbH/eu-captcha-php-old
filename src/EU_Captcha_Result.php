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
 * Two independent states are tracked so callers can distinguish a
 * token failure (the user did not solve the captcha) from a network
 * failure (the API could not be reached):
 *
 *   - stateNetwork: true when the API call completed without error.
 *   - stateToken:   true when the API reported the token as valid.
 *
 * success() returns true only when both states are true.
 */
class EU_Captcha_Result
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
     * @param bool $stateNetwork True if the HTTP request completed without error.
     * @param bool $stateToken   True if the API reported the token as valid.
     */
    public function __construct($stateNetwork, $stateToken)
    {
        $this->stateNetwork = $stateNetwork;
        $this->stateToken   = $stateToken;
    }

    /**
     * Returns true only when both the network call and token validation succeeded.
     *
     * @return bool
     */
    public function success()
    {
        return ($this->stateNetwork && $this->stateToken);
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
     * @return bool
     */
    public function successToken()
    {
        return $this->stateToken;
    }
}
