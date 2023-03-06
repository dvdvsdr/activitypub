<?php

namespace ActivityPub;

use ActivityPub\Security\HttpSignature;
use ActivityPub\Webfinger\Webfinger;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Exception;

class ActivityPub
{
    const HTTP_HEADER_ACCEPT = 'application/activity+json,application/ld+json,application/json';

    const WEBFINGER_URL = 'https://%s%s/.well-known/webfinger?resource=acct:%s';

    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly HttpSignature $httpSignature
    ) {
    }

    /**
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function getWebfinger(
        string $handle,
        array $keyInformation = []
    ): ?Webfinger {
        $json = $this->signAndGetRequest($keyInformation, $this->buildWebfingerUrl($handle));

        if ($json === null) {
            return null;
        }

        return new Webfinger($json);
    }

    /**
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    public function getActorByHandle(
        string $handle,
        array $keyInformation = [],
    ): ?array {
        $webfinger = $this->getWebfinger($handle, $keyInformation);

        if ($webfinger === null) {
            return null;
        }

        return $this->getActorByWebfinger($webfinger);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getActor(
        ?string $profileId,
        array $keyInformation = []
    ): ?array {
        if ($profileId === null) {
            throw new Exception('Invalid profile ID');
        }

        return $this->signAndGetRequest($keyInformation, $profileId);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getActorFollowersCollection(
        array $actor,
        array $keyInformation = []
    ): ?array {
        if (!isset($actor['followers'])) {
            return null;
        }

        return $this->signAndGetRequest($keyInformation, $actor['followers']);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getActorFollowingCollection(
        array $actor,
        array $keyInformation = []
    ): ?array {
        if (!isset($actor['following'])) {
            return null;
        }

        return $this->signAndGetRequest($keyInformation, $actor['following']);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getActorOutboxCollection(
        array $actor,
        array $keyInformation = []
    ): ?array {
        if (!isset($actor['outbox'])) {
            return null;
        }

        return $this->signAndGetRequest($keyInformation, $actor['outbox']);
    }

    /**
     * AFAIK nobody really does this, but it's in the ActivityPub spec:
     * "sharedInbox endpoints SHOULD also be publicly readable OrderedCollection objects containing
     *  objects addressed to the Public special collection."
     */
    public function getActorSharedInboxCollection(
        array $actor,
        array $keyInformation = []
    ): ?array {
        if (!isset($actor['endpoints'])) {
            return null;
        }

        if (!isset($actor['endpoints']['sharedInbox'])) {
            return null;
        }

        return $this->signAndGetRequest($keyInformation, $actor['endpoints']['sharedInbox']);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getFirstPageInCollection(
        array $collection,
        array $keyInformation = [],
    ): array {
        if (!isset($collection['first'])) {
            return [];
        }

        return $this->signAndGetRequest($keyInformation, $collection['first']);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getAllPagesInCollection(
        array $collection,
        array $keyInformation = [],
        int $limit = 5,
    ): array {
        if (!isset($collection['first'])) {
            return [];
        }

        $pages = [];

        $page = $this->signAndGetRequest($keyInformation, $collection['first']);
        $pages[] = $page;
        $counter = 0;

        while (isset($page['next'])) {
            if (++$counter >= $limit) {
                break;
            }

            $page = $this->signAndGetRequest($keyInformation, $page['next']);
            $pages[] = $page;
        }

        return $pages;
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getNextPage(array $collectionPage, array $keyInformation = []): array
    {
        if (!isset($collectionPage['next'])) {
            return [];
        }

        return $this->signAndGetRequest($keyInformation, $collectionPage['next']);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function getPreviousPage(array $collectionPage, array $keyInformation = []): array
    {
        if (!isset($collectionPage['prev'])) {
            return [];
        }

        return $this->signAndGetRequest($keyInformation, $collectionPage['prev']);
    }

    /**
     * borrowed a lot from dansup (pixelfed) and aaronpk (nautilus)
     * TODO properly credit also in HttpSignature
     */
    public function verifyRequestSignature(array $headers, string $body, ?string $targetPath = null): bool
    {
        if (!array_key_exists('signature', $headers) || !array_key_exists('date', $headers)) {
            return false;
        }

        $signature = is_array($headers['signature']) ? $headers['signature'][0] : $headers['signature'];

        if (!$signature) {
            return false;
        }

        $date = is_array($headers['date']) ? $headers['date'][0] : $headers['date'];

        if (!$date) {
            return false;
        }

        $decodedBody = json_decode($body, true);

        if (!isset($decodedBody['id'])) {
            return false;
        }

        $signatureData = $this->httpSignature->parseSignatureHeader($signature);

        $keyDomain = parse_url($signatureData['keyId'], PHP_URL_HOST);
        $idDomain = parse_url($decodedBody['id'], PHP_URL_HOST);

        if( isset($decodedBody['object'])
            && is_array($decodedBody['object'])
            && isset($decodedBody['object']['attributedTo'])
        ) {
            $attr = $decodedBody['object']['attributedTo'];
            if (is_array($attr)) {
                if (isset($attr['id'])) {
                    $attr = $attr['id'];
                } else {
                    $attr = "";
                }
            }
            if(parse_url($attr, PHP_URL_HOST) !== $keyDomain) {
                return false;
            }
        }

        if(!$keyDomain || !$idDomain || $keyDomain !== $idDomain) {
            return false;
        }

        $sender = $this->getActor($signatureData['keyId']);

        if (empty($sender)) {
            return false;
        }
        
        if (!isset($sender['publicKey']) || !isset($sender['publicKey']['publicKeyPem'])) {
            return false;
        }

        $publicKey = openssl_pkey_get_public($sender['publicKey']['publicKeyPem']);

        if (!$publicKey) {
            return false;
        }

        return $this->httpSignature->verify($headers, $body, $signatureData, $publicKey, $targetPath);
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function signAndGetRequest(
        array $keyInformation,
        string $url,
        array|string|null $body = null,
        array $additionalHeaders = []
    ): ?array {
        return $this->doSignedRequest(
            'GET',
            $keyInformation,
            $url,
            $body,
            $additionalHeaders
        );
    }

    /**
     * @throws ClientExceptionInterface
     */
    public function signAndPostRequest(
        array $keyInformation,
        string $url,
        array|string|null $body = null,
        array $additionalHeaders = []
    ): ?array {
        return $this->doSignedRequest(
            'POST',
            $keyInformation,
            $url,
            $body,
            $additionalHeaders
        );
    }

    /**
     * @throws ClientExceptionInterface
     */
    private function doSignedRequest(
        string $method,
        array $keyInformation,
        string $url,
        array|string|null $body = null,
        array $additionalHeaders = []
    ): ?array {
        if (
            empty($keyInformation) ||
            !array_key_exists('private_key', $keyInformation) ||
            !array_key_exists('key_id', $keyInformation)
        ) {
            $headers = $additionalHeaders;
        } else {
            $headers = $this->httpSignature->sign(
                $keyInformation['key_id'],
                $keyInformation['private_key'],
                $url,
                $body,
                $additionalHeaders
            );
        }

        if ($body === null) {
            $parameters = [];
        } else {
            if (!is_array($body)) {
                $parameters = json_decode($body, true);
            } else {
                $parameters = $body;
            }
        }

        return $this->doCall($url, $parameters, $method, $headers);
    }

    /**
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    public function getActorByWebfinger(Webfinger $webfinger): ?array
    {
        return $this->getActor($webfinger->getProfileId());
    }

    /**
     * @throws ClientExceptionInterface
     */
    private function doCall(
        string $url,
        array $parameters = [],
        string $method = 'GET',
        array $headers = [],
    ): ?array {
        $data = null;

        if ($method === 'GET' && !empty($parameters)) {
            $url .= '?' . http_build_query($parameters, null);
        }

        if ($method === 'POST' || $method === 'PUT') {
            $data = json_encode($parameters);
        }

        $request = $this->requestFactory->createRequest($method, $url);
        if ($data !== null) {
            $request = $request->withBody($this->streamFactory->createStream($data));
        }

        $request = $request->withAddedHeader('Accept', self::HTTP_HEADER_ACCEPT);

        foreach ($headers as $key => $value) {
            $request = $request->withAddedHeader($key, $value);
        }

        $response = $this->client->sendRequest($request);

        $data = json_decode($response->getBody()->getContents(), true);

        if ($response->getStatusCode() !== 200) {
            $data['response']['status'] = $response->getStatusCode();
        }

        return $data;
    }

    public function buildWebfingerUrl(string $handle): string
    {
        if (!preg_match(
            '/^@?(?P<user>[\w\-\.]+)@(?P<host>[\w\.\-]+)(?P<port>:[\d]+)?$/',
            $handle,
            $matches)
        ) {
            throw new Exception(
                "WebFinger handle is malformed '{$handle}'"
            );
        }

        // Unformat handle @user@host => user@host
        $handle = str_starts_with($handle, '@') ?
            substr($handle, 1) :
            $handle
        ;

        // Build a WebFinger URL
        return sprintf(
            self::WEBFINGER_URL,
            $matches['host'],
            $matches['port'] ?? '',
            $handle
        );
    }
}
