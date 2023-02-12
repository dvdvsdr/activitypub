<?php

namespace ActivityPub\Security;

class KeyGenerator
{
    public function generateKeys(): array
    {
        $pki = openssl_pkey_new($this->getConfig());
        openssl_pkey_export($pki, $privateKey);
        $publicKey = openssl_pkey_get_details($pki);
        $publicKey = $publicKey['key'];

        return [
            'public' => $publicKey,
            'private' => $privateKey,
        ];
    }

    private function getConfig(): array
    {
        return [
            'digest_alg'       => 'sha512',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
    }
}