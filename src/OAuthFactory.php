<?php
namespace Slim\OAuth;

use OAuth\Common\Storage\Session;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Uri\UriFactory;
use OAuth\ServiceFactory;

/**
 * Factory for creating OAuth services
 */
class OAuthFactory {
    private $sessionName       = 'slim_oauth_middle';
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
        $this->storage          = new Session;
        $this->oAuthCredentials = $oAuthCredentials;
    }

    /**
     * Create an oauth service based on type
     *
     * @param  string $type the type of oauth services to create
     */
    public function createService($type)
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
        $this->registeredService = $this->serviceFactory->createService($type, $credentials, $this->storage, ['user']);
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

    /**
     * Check if user is authenticated
     *
     * @return boolean              whether the user is authenticated or not
     */
    public function isAuthenticated()
    {
        $service = $this->getOrCreateByType($this->getValue('oauth_service_type'));

        return $service && $this->storage->hasAccessToken($service->service());
    }

    /**
     * store a value in the session
     *
     * @param  string $name  name of value to store
     * @param  mixed  $value value to store
     */
    public function storeValue($name, $value)
    {
        if (!array_key_exists($this->sessionName, $_SESSION)) {
            $_SESSION[$this->sessionName] = [];
        }

        $_SESSION[$this->sessionName][$name] = $value;
    }

    /**
     * retrieve value from session
     *
     * @param  string $name the name of value to get from session
     *
     * @return mixed        the value from the session
     */
    public function getValue($name)
    {
        if (!array_key_exists($this->sessionName, $_SESSION)) {
            return false;
        }

        if (!array_key_exists($name, $_SESSION[$this->sessionName])) {
            return false;
        }

        return $_SESSION[$this->sessionName][$name];
    }

    /**
     * delete a value from session
     *
     * @param  string $name the name to delete
     *
     * @return void
     */
    public function delValue($name)
    {
        if (!array_key_exists($this->sessionName, $_SESSION)) {
            return;
        }

        if (!array_key_exists($name, $_SESSION[$this->sessionName])) {
            return;
        }

        unset($_SESSION[$this->sessionName][$name]);
    }
}
