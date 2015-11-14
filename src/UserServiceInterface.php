<?php
namespace SlimApi\OAuth;

use OAuth\Common\Service\ServiceInterface;

interface UserServiceInterface {
    /**
     * this uses the service interface, as it's down to the implementation
     * and the different service types to figure out what info to get from the api
     *
     * e.g.with a github service, doing $service->request('user') will result in thhe following
     * what is done with it and how it is stored is down to implementation
     *
     * This is also the place you should be checking if this user is actually allowed to be created,
     * checking if the user belongs to the right org or team. Doesn't matter on an open site,
     * but would matter for a org specific api
     *
     * {
     *   "login": "octocat",
     *   "id": 1,
     *   "avatar_url": "https://github.com/images/error/octocat_happy.gif",
     *   "gravatar_id": "",
     *   "url": "https://api.github.com/users/octocat",
     *   "html_url": "https://github.com/octocat",
     *   "followers_url": "https://api.github.com/users/octocat/followers",
     *   "following_url": "https://api.github.com/users/octocat/following{/other_user}",
     *   "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
     *   "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
     *   "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
     *   "organizations_url": "https://api.github.com/users/octocat/orgs",
     *   "repos_url": "https://api.github.com/users/octocat/repos",
     *   "events_url": "https://api.github.com/users/octocat/events{/privacy}",
     *   "received_events_url": "https://api.github.com/users/octocat/received_events",
     *   "type": "User",
     *   "site_admin": false,
     *   "name": "monalisa octocat",
     *   "company": "GitHub",
     *   "blog": "https://github.com/blog",
     *   "location": "San Francisco",
     *   "email": "octocat@github.com",
     *   "hireable": false,
     *   "bio": "There once was...",
     *   "public_repos": 2,
     *   "public_gists": 1,
     *   "followers": 20,
     *   "following": 0,
     *   "created_at": "2008-01-14T04:33:35Z",
     *   "updated_at": "2008-01-14T04:33:35Z",
     *   "total_private_repos": 100,
     *   "owned_private_repos": 100,
     *   "private_gists": 81,
     *   "disk_usage": 10000,
     *   "collaborators": 8,
     *   "plan": {
     *     "name": "Medium",
     *     "space": 400,
     *     "private_repos": 20,
     *     "collaborators": 0
     *   }
     * }
     *
     * @param ServiceInterface $service oauth service
     */
    public function createUser(ServiceInterface $service);

    /**
     * Create a user object, whether it's blank or filled,
     * $authToken is header from Authorization so you can retrieve from db
     * or some kind of in-memory storage redis etc
     *
     * @param string|false $authToken The auth token from the Authorization header
     */
    public function findOrNew($authToken);
}
