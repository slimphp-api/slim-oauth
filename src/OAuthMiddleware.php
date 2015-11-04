<?php
namespace SlimApi\OAuth;

use Exception;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * OAuth middleware
 */
class OAuthMiddleware
{
    private $defaultRole  = 'guest';
    private $returnRoute    = false;
    private $oAuthProviders = ['github'];
    private $oAuthFactory;

    private static $authRoute     = '/auth/(?<oAuthServiceType>\w+)';
    private static $callbackRoute = '/auth/(?<oAuthServiceType>\w+)/callback';

    /**
     * @param  OAuthFactory  $oAuthFactory  The OAuthFacotry instance to use
     */
    public function __construct(OAuthFactory $oAuthFactory)
    {
        $this->oAuthFactory  = $oAuthFactory;
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

        // this matches the request to authenticate for an oauth provider
        if (1 === preg_match($this->getAuthRouteRegex(), $path, $matches)) {
            // validate we have an allowed oAuthServiceType
            if (!in_array($matches['oAuthServiceType'], $this->oAuthProviders)) {
                throw new Exception("Unknown oAuthServiceType");
            }

            // validate the return url
            parse_str($_SERVER['QUERY_STRING'], $query);
            if (!filter_var($query['return'], FILTER_VALIDATE_URL) === false) {
                throw new Exception("Invalid return url");
            }

            $_SESSION['oauth_return_url'] = $query['return'];

            $url = $this->oAuthFactory->getOrCreateByType($matches['oAuthServiceType'])->getAuthorizationUri();

            return $response->withStatus(302)->withHeader('Location', $url);
        } elseif (1 === preg_match($this->getCallbackRouteRegex(), $path, $matches)) { // this matches the request to post-authentication for an oauth provider
            if (!in_array($matches['oAuthServiceType'], $this->oAuthProviders)) {
                throw new Exception("Unknown oAuthServiceType");
            }

            $service = $this->oAuthFactory->getOrCreateByType($matches['oAuthServiceType']);
            // turn our code into a token that's stored internally
            $service->requestAccessToken($request->getParam('code'));

            // generate a temporary session token
            $prngToken = $this->oAuthFactory->tempToken();
            // set our token in the header and then redirect to the client's chosen url
            return $response->withStatus(200)->withHeader('Authorization', $prngToken)->withHeader('Location', $_SESSION['oauth_return_url']);
        }

        if ($this->oAuthFactory->isAuthenticated()) {
            // generate a temporary session token
            $prngToken = $this->oAuthFactory->tempToken();
            $response  = $response->withHeader('Authorization', $prngToken);
        } else {

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
        return '@^' . $route . '$@';
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
}
