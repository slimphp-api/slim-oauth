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
    private $oAuthProviders;
    private $oAuthFactory;
    private $userService;

    private static $authRoute     = '/auth/(?<oAuthServiceType>\w+)';
    private static $callbackRoute = '/auth/(?<oAuthServiceType>\w+)/callback';

    /**
     * @param  OAuthFactory          $oAuthFactory  The OAuthFacotry instance to use
     * @param  UserServiceInterface  $userService
     * @param  array                 $oAuthProviders An array of valid oauth providers
     */
    public function __construct(OAuthFactory $oAuthFactory, UserServiceInterface $userService, $oAuthProviders = ['github'])
    {
        $this->oAuthFactory   = $oAuthFactory;
        $this->userService    = $userService;
        $this->oAuthProviders = $oAuthProviders;
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
        $returnValue = $this->checkForOAuthPaths($request, $response, $next);

        if (false !== $returnValue) {
            return $returnValue;
        }

        // Fetches the current user or returns a default
        $authHeaders = $request->getHeader('Authorization');
        $authValue   = $this->parseForAuthentication($authHeaders);

        $user     = $this->userService->findOrNew($authValue);
        $request  = $request->withAttribute('user', $user);
        if ($user->token) {
            $response = $response->withHeader('Authorization', 'token '.$user->token);
        }

        return $next($request, $response);
    }

        /**
         * Check the current url for oauth paths
         *
         * @param  RequestInterface  $request  PSR7 request object
         * @param  ResponseInterface $response PSR7 response object
         * @param  callable          $next     Next middleware callable
         *
         * @return ResponseInterface|false PSR7 response object
         */
    private function checkForOAuthPaths(RequestInterface $request, ResponseInterface $response, callable $next)
    {
        $path = $request->getUri()->getPath();

        if (!is_string($path)) {
            return false;
        }

        // this matches the request to authenticate for an oauth provider
        if (1 === preg_match($this->getAuthRouteRegex(), $path, $matches)) {
            // validate we have an allowed oAuthServiceType
            if (!in_array($matches['oAuthServiceType'], $this->oAuthProviders)) {
                throw new Exception("Unknown oAuthServiceType");
            }

            // validate the return url
            parse_str($_SERVER['QUERY_STRING'], $query);
            if (!array_key_exists('return', $query) || filter_var($query['return'], FILTER_VALIDATE_URL) === false) {
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
            // validates and creates the user entry in the db if not already exists
            $user = $this->userService->createUser($service);
            // set our token in the header and then redirect to the client's chosen url
            return $response->withStatus(200)->withHeader('Authorization', 'token '.$user->token)->withHeader('Location', $_SESSION['oauth_return_url']);
        }

        return false;
    }

    /**
     * Parse the Authorization header for auth tokens
     *
     * @param  array $authHeaders Array of PSR7 headers specific to authorization
     *
     * @return string|false Return either the auth token of false if none found
     *
     */
    private function parseForAuthentication(array $authHeaders)
    {
        $authValue  = false;
        if (count($authHeaders) > 0) {
            foreach ($authHeaders as $authHeader) {
                $authValues = explode(' ', $authHeader);
                if (2 === count($authValues) && array_search(strtolower($authValues[0]), ['bearer', 'token'])) {
                    $authValue = $authValues[1];
                    break;
                }
            }
        }
        return $authValue;
    }

    /**
     * convert the route to a regex
     *
     * @param  string $route the route to convert
     *
     * @return string        a regex of the route
     */
    private function regexRoute($route)
    {
        return '@^' . $route . '$@';
    }

    /**
     * get the regex for the route used to authenticate
     *
     * @return string the auth route regex
     */
    private function getAuthRouteRegex()
    {
        return $this->regexRoute(static::$authRoute);
    }

    /**
     * get the regex for the callback route for authentication
     *
     * @return string regex route
     */
    private function getCallbackRouteRegex()
    {
        return $this->regexRoute(static::$callbackRoute);
    }
}
