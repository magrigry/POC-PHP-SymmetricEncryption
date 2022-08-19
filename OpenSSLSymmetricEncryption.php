<?php

class OpenSSLSymmetricEncryption
{

    private $cipher_algorithm;
    private $key;
    private $authenticator;

    public const MINIMAL_KEY_LENGTH = 64;

    /**
     * @param string $cipher_algo Alg that will be used {@see https://www.php.net/manual/fr/function.openssl-get-cipher-methods.php}
     * @param string $key Master key to use for encryption. Minimal key size {@see OpenSSLSymmetricEncryption::MINIMAL_KEY_LENGTH}
     * @param Authenticator $authenticator Will be used to sign the encrypted value or verify a signature
     */
    public function __construct(string $cipher_algo, string $key, Authenticator $authenticator) {

        if (strlen($key) < self::MINIMAL_KEY_LENGTH) {
            throw new MinimalKeyLength($key, self::MINIMAL_KEY_LENGTH);
        }

        if (in_array($cipher_algo, openssl_get_cipher_methods(), false) === false) {
            throw new UnknownCipher($cipher_algo, openssl_get_cipher_methods());
        }

        $this->cipher_algorithm = $cipher_algo;
        $this->key = $key;
        $this->authenticator = $authenticator;
    }

    /**
     * Encrypt a value
     *
     * @param string $value the value we want to encrypt
     * @param string $info A value that will be used to create a new key from the master key provider in the constructor
     *
     * @return string The string encrypted and encoded to base64.
     *                  base64(($salt.$signature).$iv.encrypt($iv.$value))
     */
    public function encrypt(string $value, string $info): string {

        if (empty($info)) {
            throw new InvalidArgumentException('parameter 2 cannot be empty');
        }

        $iv = $this->getIV();
        $final_key = $this->getFinalKey($info, $iv);
        $encrypted = openssl_encrypt($value, $this->cipher_algorithm, $final_key,OPENSSL_RAW_DATA,  $iv);
        $encrypted = $iv.$encrypted;
        return base64_encode($this->authenticator->sign($encrypted, $final_key));
    }

    /**
     * Decrypt an encrypted string
     *
     * @param string $value the encrypted value
     * @param string $info A value that has been be used to create a new key from the master key
     *
     * @return string The string not encrypted
     *
     * @throws AuthenticationFailureException If the {@param $value} cannot be authenticated, meaning it has been altered
     */
    public function decrypt(string $value, string $info): string {

        if (empty($info)) {
            throw new InvalidArgumentException('parameter 2 cannot be empty');
        }

        $value = base64_decode($value);
        $base_value = $value;
        $value = $this->authenticator->getValue($value);
        $iv_length = openssl_cipher_iv_length($this->cipher_algorithm);
        $iv = substr($value, 0, $iv_length);
        $final_key = $this->getFinalKey($info, $iv);
        $this->authenticator->check($base_value, $final_key);
        $raw = substr($value, $iv_length);
        return openssl_decrypt($raw, $this->cipher_algorithm, $final_key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Create an initialisation vector
     *
     * @return string
     */
    private function getIV(): string {

        $iv_length = openssl_cipher_iv_length($this->cipher_algorithm);

        do {
            $iv = openssl_random_pseudo_bytes($iv_length, $strong);
        } while ($iv === false || $strong === false);

        return $iv;
    }

    /**
     * Generate a HKDF key derivation of a supplied key in the constructor
     *
     * @param string $info usually called "info". PHP describe it as "Application/context-specific info string."
     * @param string $salt Salt used during derivation
     *
     * @return string Raw binary representation of the derived key
     */
    private function getFinalKey(string $info, string $salt): string
    {
        return hash_hkdf('sha256', $this->key, 0, $info . $this->cipher_algorithm, hash('sha256', $salt));
    }
}