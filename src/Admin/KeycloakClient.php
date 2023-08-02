<?php

namespace Keycloak\Admin;

use GuzzleHttp\Command\Guzzle\GuzzleClient;
use GuzzleHttp\Command\Guzzle\Description;
use GuzzleHttp\Command\Guzzle\Serializer;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use Keycloak\Admin\Classes\FullBodyLocation;
use Keycloak\Admin\Classes\FullTextLocation;

class KeycloakClient extends GuzzleClient
{

    /**
     * Factory to create new KeycloakClient instance.
     *
     * @param array $config
     *
     * @return \Keycloak\Admin\KeycloakClient
     */
    public static function factory($config = array())
    {
        $default = array(
            'apiVersion'  => '1.1',
            'username' => null,
            'password' => null,
            'realm'    => 'master',
            'baseUri'  => null,
            'verify'   => true,
        );

        $config = self::parseConfig($config, $default);
        $file = 'custom_keycloak_18.0.php';
        $stack = new HandlerStack();
        $stack->setHandler(new CurlHandler());
        $middlewares = isset($config["middlewares"]) && is_array($config["middlewares"]) ? $config["middlewares"] : [];
        foreach ($middlewares as $middleware) {
            if (is_callable($middleware)) {
                $stack->push($middleware);
            }
        }
        $config['handler'] = $stack;

        $serviceDescription = include __DIR__ . "/Resources/{$file}";
        $customOperations = isset($config["custom_operations"]) && is_array($config["custom_operations"]) ? $config["custom_operations"] : [];
        foreach ($customOperations as $operationKey => $operation) {
            if (isset($serviceDescription['operations'][$operationKey])) {
                continue;
            }
            $serviceDescription['operations'][$operationKey] = $operation;
        }
        $description = new Description($serviceDescription);

        return new static(
            new Client($config),
            $description,
            new Serializer($description, [
                "fullBody" => new FullBodyLocation(),
                "fullText" => new FullTextLocation(),
            ]),
            function ($response) {
                $responseBody = $response->getBody()->getContents();
                return json_decode($responseBody, true) ?? ['content' => $responseBody];
            },
            null,
            $config
        );
    }

    public function getCommand($name, array $params = [])
    {
        if (!isset($params['realm'])) {
            $params['realm'] = $this->getRealmName();
        }
        return parent::getCommand($name, $params);
    }

    /**
     * Sets the BaseUri used by the Keycloak Client
     *
     * @param string $baseUri
     */
    public function setBaseUri($baseUri)
    {
        $this->setConfig('baseUri', $baseUri);
    }

    /**
     * Sets the Realm name used by the Keycloak Client
     *
     * @param string $realm
     */
    public function getBaseUri()
    {
        return $this->getConfig('baseUri');
    }

    /**
     * Sets the Realm name used by the Keycloak Client
     *
     * @param string $realm
     */
    public function setRealmName($realm)
    {
        $this->setConfig('realm', $realm);
    }

    /**
     * Gets the Realm name being used by the Keycloak Client
     *
     * @return string|null Value of the realm or NULL
     */
    public function getRealmName()
    {
        return $this->getConfig('realm');
    }

    /**
     * Sets the API Version used by the Keycloak Client.
     * Changing the API Version will attempt to load a new Service Definition for that Version.
     *
     * @param string $version
     */
    public function setVersion($version)
    {
        $this->setConfig('apiVersion', $version);
    }

    /**
     * Gets the Version being used by the Keycloak Client
     *
     * @return string|null Value of the Version or NULL
     */
    public function getVersion()
    {
        return $this->getConfig('apiVersion');
    }

    /**
     * Attempt to parse config and apply defaults
     *
     * @param  array  $config
     * @param  array  $default
     *
     * @return array Returns the updated config array
     */
    protected static function parseConfig($config, $default)
    {
        array_walk($default, function ($value, $key) use (&$config) {
            if (!isset($config[$key])) {
                $config[$key] = $value;
            }
        });
        return $config;
    }
}