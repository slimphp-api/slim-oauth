<?php
namespace Slim\OAuth;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * OAuth middleware
 */
class OAuthMiddleware
{
    private $sessionName    = 'slim_oauth_middle';
    private $unauthedRoute  = '/auth';
    private $ignoredRoutes  = ['/', '/auth'];
    private $oAuthProviders = ['github'];
    private $oAuthFactory;

    private static $authRoute     = '/auth/(?<oauthServiceType>\w+)';
    private static $callbackRoute = '/auth/(?<oauthServiceType>\w+)/callback';
    private static $regexFixes    = '@';

    /**
     * @param  OAuthFactory  $oAuthFactory  The OAuthFacotry instance to use
     * @param  Array         $ignoredRoutes An array of ignorable routes
     */
    public function __construct(OAuthFactory $oAuthFactory = null, array $ignoredRoutes = [])
    {
        if ($ignoredRoutes) {
            $this->ignoredRoutes = $ignoredRoutes;
        }

        $this->oAuthFactory  = is_null($oAuthFactory) ? (new OAuthFactory) : $oAuthFactory;
    }

    /**
     * Invoke middleware
     *
     * @param  RequestInterface  $request  PSR7 request object
     * @param  ResponseInterface $response PSR7 response object
     * @param  callable          $next     Next middleware callable
     *
     * @return ResponseInterface PSR7 response object
     */
    public function __invoke(RequestInterface $request, ResponseInterface $response, callable $next)
    {
        $path = $request->getUri()->getPath();

        if (!is_string($path)) {
            return $next($request, $response);
        }

        foreach ($this->ignoredRoutes as $ignoredRoute) {
            $pathIsIgnorable = (1 === preg_match($this->regexRoute($ignoredRoute), $path));

            if ($pathIsIgnorable) {
                return $next($request, $response);
            }
        }

        // this matches the request to authenticate for an oauth provider
        if (1 === preg_match($this->getAuthRouteRegex(), $path, $matches)) {
            if (!in_array($matches['oauthServiceType'], $this->oAuthProviders)) {
                return $response->withStatus(403)->withHeader('Location', $this->unauthedRoute);
            }

            $url = $this->oAuthFactory->getOrCreateByType($matches['oauthServiceType'])->getAuthorizationUri();

            return $response->withStatus(302)->withHeader('Location', $url);
        }

        // this matches the request to post-authentication for an oauth provider
        if (1 === preg_match($this->getCallbackRouteRegex(), $path, $matches)) {
            if (!in_array($matches['oauthServiceType'], $this->oAuthProviders)) {
                return $response->withStatus(403)->withHeader('Location', $this->unauthedRoute);
            }

            $service        = $this->oAuthFactory->getOrCreateByType($matches['oauthServiceType']);
            $accessTokenEnt = $service->requestAccessToken($request->getParam('code'));
            $url            = $this->getValue('originalDestination')?:'/';

            $this->delValue('originalDestination');
            $this->storeValue('oauth_service_type', $matches['oauthServiceType']);

            if ($url) {
                return $response->withStatus(200)->withHeader('Location', $url);
            }
        }

        // we need to know somehow what the actual service type is, ie github/facebook before here.
        if (!$this->oAuthFactory->isAuthenticated($this->getValue('oauth_service_type'))) {
            $this->storeValue('originalDestination', $path);
            return $response->withStatus(403)->withHeader('Location', $this->unauthedRoute);
        }

        return $next($request, $response);
    }

    /**
     * convert the route to a regex
     *
     * @param  string $route the route to convert
     *
     * @return string        a regex of the route
     */
    public function regexRoute($route)
    {
        return static::$regexFixes . '^' . $route . '$' . static::$regexFixes;
    }

    /**
     * get the regex for the route used to authenticate
     *
     * @return string the auth route regex
     */
    public function getAuthRouteRegex()
    {
        return $this->regexRoute(static::$authRoute);
    }

    /**
     * get the regex for the callback route for authentication
     *
     * @return string regex route
     */
    public function getCallbackRouteRegex()
    {
        return $this->regexRoute(static::$callbackRoute);
    }

    /**
     * set the oauth factory
     *
     * @param OAuthFactory $oAuthFactory the oauth factory instance to use
     */
    public function setOAuthFactory(OAuthFactory $oAuthFactory)
    {
        $this->oAuthFactory = $oAuthFactory;
    }

    /**
     * fetch the current oauth factory
     *
     * @return OAuthFactory current oauth faactory
     */
    public function getOAuthFactory()
    {
        return $this->oAuthFactory;
    }

    /**
     * set the routes that should be ignored for authentication checks
     *
     * @param array $ignoredRoutes ignorable routes
     */
    public function setIgnoredRoutes(array $ignoredRoutes)
    {
        $this->ignoredRoutes = $ignoredRoutes;
    }

    /**
     * get the routes that are currently being ignored for authentication calls
     *
     * @return array the ignored routes
     */
    public function getIgnoredRoutes()
    {
        return $this->ignoredRoutes;
    }

    /**
     * sets the array of allowed OAuth Providers
     *
     * @param array $oAuthProviders OAuth Providers
     */
    public function setOAuthProviders(array $oAuthProviders)
    {
        $this->oAuthProviders = $oAuthProviders;
    }

    /**
     * get the current allowed OAuth Providers
     *
     * @return array Current OAuth Providers
     */
    public function getoAuthProviders()
    {
        return $this->oAuthProviders;
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
