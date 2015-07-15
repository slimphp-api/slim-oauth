<?php
namespace Slim\OAuth;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * OAuth middleware
 */
class OAuthMiddleware
{
    private $unauthedRoute  = '/';
    private $returnRoute    = false;
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
    public function __construct(OAuthFactory $oAuthFactory, array $ignoredRoutes = [])
    {
        $this->oAuthFactory  = $oAuthFactory;

        if ($ignoredRoutes) {
            $this->ignoredRoutes = $ignoredRoutes;
        }
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
            $url            = $this->oAuthFactory->getValue('originalDestination')?:'/';

            $this->oAuthFactory->delValue('originalDestination');
            $this->oAuthFactory->storeValue('oauth_service_type', $matches['oauthServiceType']);

            if ($url) {
                return $response->withStatus(200)->withHeader('Location', $url);
            }
        }

        // we need to know somehow what the actual service type is, ie github/facebook before here.
        if (!$this->oAuthFactory->isAuthenticated()) {
            $this->oAuthFactory->storeValue('originalDestination', ($this->returnRoute?:$path));
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
    public function getOAuthProviders()
    {
        return $this->oAuthProviders;
    }

    /**
     * gets the current returning route
     *
     * @return string Current return route
     */
    public function getReturnRoute()
    {
        return $this->returnRoute;
    }

    /**
     * Sets an override return route, allowing developer to specify
     * a route to return to after authentication
     *
     * @param string $returnRoute override return route
     */
    public function setReturnRoute($returnRoute)
    {
        $this->returnRoute = $returnRoute;
    }

    /**
     * gets the current unauthorised route
     *
     * @return string Current unauthorised route
     */
    public function getUnauthedRoute()
    {
        return $this->unauthedRoute;
    }

    /**
     * Sets a route to redirect to if unauthorised
     *
     * @param string $unauthedRoute unauthorised route
     */
    public function setUnauthedRoute($unauthedRoute)
    {
        $this->unauthedRoute = $unauthedRoute;
    }
}
