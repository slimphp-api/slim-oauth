<?php
namespace SlimApi\OAuth;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Uri\UriFactory;
use OAuth\ServiceFactory;

/**
 * Factory for creating OAuth services
 */
class OAuthFactory {
    private $storageClass      = '\OAuth\Common\Storage\Session';
    private $registeredService = false;
    private $serviceFactory;
    private $storage;
    private $oAuthCredentials;

    /**
     * Create new OAuthFactory
     *
     * @param mixed $config  An array of oauth key/secrets
     */
    public function __construct($oAuthCredentials)
    {
        $this->serviceFactory   = new ServiceFactory;
        $this->storage          = new $this->storageClass();
        $this->oAuthCredentials = $oAuthCredentials;
    }

    /**
     * Create an oauth service based on type
     *
     * @param  string $type the type of oauth services to create
     */
    public function createService($type, $scopes = ['user'])
    {
        $typeLower = strtolower($type);

        if (!array_key_exists($typeLower, $this->oAuthCredentials)) {
            return false;
        }

        // Create a new instance of the URI class with the current URI, stripping the query string
        $uriFactory = new UriFactory();
        $currentUri = $uriFactory->createFromSuperGlobalArray($_SERVER);
        $currentUri->setQuery('');

        // Setup the credentials for the requests
        $credentials = new Credentials(
            $this->oAuthCredentials[$typeLower]['key'],
            $this->oAuthCredentials[$typeLower]['secret'],
            $currentUri->getAbsoluteUri() . '/callback'
        );

        // Instantiate the OAuth service using the credentials, http client and storage mechanism for the token
        $this->registeredService = $this->serviceFactory->createService($type, $credentials, $this->storage, $scopes);
    }

    /**
     * if we don't have a registered service we attempt to make one
     *
     * @param  string       $type the oauth provider type
     *
     * @return OAuthService       the created service
     */
    public function getOrCreateByType($type)
    {
        if (! $this->registeredService) {
            $this->createService($type);
        }

        return $this->registeredService;
    }

    /**
     * retrieve the registered service
     *
     * @return OAuthService the registered oauth service
     */
    public function getService()
    {
        return $this->registeredService;
    }
}
