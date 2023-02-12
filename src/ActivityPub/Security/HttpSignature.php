<?php

namespace ActivityPub\Security;

use OpenSSLAsymmetricKey;
use DateTime;

class HttpSignature
{
    public function verify(
        array $headers,
        string $body,
        array $signatureData,
        OpenSSLAsymmetricKey $publicKey,
        ?string $targetPath = null
    ): bool {
        $digest = 'SHA-256=' . base64_encode(hash('sha256', $body, true));

        $headersToSign = [];

        foreach (explode(' ', $signatureData['headers']) as $header) {
            if ($header == '(request-target)') {
                if ($targetPath === null) {
                    return false;
                }

                $headersToSign[$header] = 'post '. $targetPath;
            } elseif ($header == 'digest') {
                $headersToSign[$header] = $digest;
            } elseif (isset($headers[$header][0])) {
                $headersToSign[$header] = $headers[$header][0];
            }
        }
        $signingString = $this->headersToSigningString($headersToSign);
        $verified = openssl_verify($signingString, base64_decode($signatureData['signature']), $publicKey, OPENSSL_ALGO_SHA256);

        return $verified === 1;
    }

    public function sign(
        string $keyId,
        string $privateKey,
        string $url,
        array|string|null $body = null,
        array $additionalHeaders = [],
    ): array {
        $digest = $this->digestBody($body);

        $headers = $this->getSignatureHeaders($url, $digest);
        $headers = array_merge($headers, $additionalHeaders);

        $stringToSign = $this->headersToSigningString($headers);
        $signedHeaders = implode(' ', array_map('strtolower', array_keys($headers)));

        $key = openssl_pkey_get_private($privateKey);
        openssl_sign($stringToSign, $signature, $key, OPENSSL_ALGO_SHA256);
        $signature = base64_encode($signature);

        $signatureHeader = 'keyId="' . $keyId . '",headers="' . $signedHeaders . '",algorithm="rsa-sha256",signature="' . $signature . '"';

        unset($headers['(request-target)']);
        $headers['Signature'] = $signatureHeader;

        return $headers;
    }

    public function parseSignatureHeader(string $signature): array
    {
        $parts = explode(',', $signature);
        $signatureData = [];

        foreach($parts as $part) {
            if(preg_match('/(.+)="(.+)"/', $part, $match)) {
                $signatureData[$match[1]] = $match[2];
            }
        }

        if(!isset($signatureData['keyId'])) {
            return [
                'error' => 'No keyId was found in the signature header. Found: ' . implode(', ', array_keys($signatureData))
            ];
        }

        if(!filter_var($signatureData['keyId'], FILTER_VALIDATE_URL)) {
            return [
                'error' => 'keyId is not a URL: ' . $signatureData['keyId']
            ];
        }

        if(!isset($signatureData['headers']) || !isset($signatureData['signature'])) {
            return [
                'error' => 'Signature is missing headers or signature parts'
            ];
        }

        return $signatureData;
    }

    private function headersToSigningString(array $headersToSign): string
    {
        return implode("\n", array_map(function($k, $v) {
            return strtolower($k) . ': ' . $v;
        }, array_keys($headersToSign), $headersToSign));
    }

    private function digestBody(string|array|null $body): ?string
    {
        if (empty($body)) {
            return null;
        }

        if (is_array($body)) {
            $body = json_encode($body);
        }

        return base64_encode(hash('sha256', $body, true));
    }

    private function getSignatureHeaders(
        string $url,
        ?string $digest = null
    ): array {
        $date = new DateTime('UTC');

        $headers = [
            '(request-target)' => 'post '. parse_url($url, PHP_URL_PATH),
            'Date' => $date->format('D, d M Y H:i:s \G\M\T'),
            'Host' => parse_url($url, PHP_URL_HOST),
        ];

        if($digest !== null) {
            $headers['Digest'] = 'SHA-256='.$digest;
        }

        return $headers;
    }
}
