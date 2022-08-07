<?php

namespace Furdarius\OIDConnect\Adapter;

use Furdarius\OIDConnect\Contract\JSONGetter;
use Furdarius\OIDConnect\Contract\JSONPoster;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class JSONFetcherAdapter implements JSONGetter, JSONPoster
{
    /**
     * @var Client
     */
    private Client $client;

    /**
     * JSONFetcherAdapter constructor.
     *
     * @param Client $client
     */
    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     * @throws GuzzleException
     */
    public function get(string $url, array $params = [], array $options = []): array
    {
        $reqOpts = array_merge([
            'query' => $params,
            'headers' => [
                'Accept' => 'application/json',
            ],
        ], $options);

        return $this->request("GET", $url, $reqOpts);
    }

    /**
     * @param string $method
     * @param string $url
     * @param array $options
     *
     * @return array
     * @throws GuzzleException
     */
    protected function request(string $method, string $url, array $options): array
    {
        $response = $this->client->request($method, $url, $options);

        // TODO: Handle request errors (ex.: authorization error with 403 status code)

        $data = $response->getBody()->getContents();

        return json_decode($data, true);
    }

    /**
     * {@inheritdoc}
     * @throws GuzzleException
     */
    public function post(string $url, array $params = [], $body = null, array $options = []): array
    {
        $reqOpts = array_merge([
            'query' => $params,
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => $body,
        ], $options);

        return $this->request("POST", $url, $reqOpts);
    }
}
