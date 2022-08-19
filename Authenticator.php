<?php

class Authenticator {

    private $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * Sign a value and return the value concatenated with the signature
     *
     * @param string $value
     * @param string $info A value that will be used to create a new key from the master key provider in the constructor
     *
     * @return string The signature concatenated to the value. The signature is a binary
     */
    public function sign(string $value, string $info): string
    {
        if (empty($info)) {
            throw new InvalidArgumentException('parameter 2 cannot be empty');
        }

        $salt = openssl_random_pseudo_bytes(32);

        return $salt . $this->getSignature($value, $info, $salt) . $value;
    }

    /**
     * Check a signed value and return the value
     *
     * @param string $value
     * @param string $info Derivation key used while signing
     *
     * @return string
     * @throws AuthenticationFailureException
     */
    public function check(string $value, string $info): string
    {
        if (empty($info)) {
            throw new InvalidArgumentException('parameter 2 cannot be empty');
        }

        $salt = substr($value, 0, 32);
        $hmac = substr($value, 32, 32);
        $value = $this->getValue($value);
        if (hash_equals($this->getSignature($value, $info, $salt), $hmac)) {
            return $value;
        }

        throw new AuthenticationFailureException();
    }

    /**
     * Get the original value, with the signature
     *
     * @param string $value
     *
     * @return string
     */
    public function getValue(string $value): string
    {
        return substr($value, 64);
    }

    /**
     * Generate a signature
     *
     * @param string $value
     * @param string $info
     * @param string $salt
     *
     * @return string
     */
    private function getSignature(string $value, string $info, string $salt): string
    {
        $final_key = hash_hkdf('sha256', $this->key, 0, hash('sha256', $info), hash('sha256', $salt));
        return hash_hmac('sha256', $value, $final_key, true);
    }

}