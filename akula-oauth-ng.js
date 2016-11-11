'use strict';
angular
    .module('akulaOAuthNG', [])
    .constant('oAuthConfig', {
        env: 'dev',
        requiredKeys: [
            'baseUrl',
            'clientId',
            'grantPath',
            'revokePath'
        ],
        servers: {
            dev: {
                baseUrl: null,
                clientId: null,
                clientSecret: null,
                grantPath: '/oauth2/token',
                revokePath: '/oauth2/revoke'
            },
            prod: {
                baseUrl: null,
                clientId: null,
                clientSecret: null,
                grantPath: '/oauth2/token',
                revokePath: '/oauth2/revoke'
            }
        }
    })
    .config(oauthConfigInterceptor)
    .factory('oauthInterceptor', oauthInterceptor)
    .provider('OAuth', oAuthProvider)
    .provider('OAuthToken', oAuthTokenProvider);

oAuthProvider.$inject = ['oAuthConfig'];
function oAuthProvider(config) {
    Object.defineProperties(this, {
        env: {
            get: function () { return config.env },
            set: function (value) { config.env = value }
        }
    });

    var buildQueryString = function (obj) {
        var str = [];

        angular.forEach(obj, function (value, key) {
            str.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
        });

        return str.join('&');
    };

    var configure = function (evKey, params) {
        var ev = config.servers[evKey];

        if (!(params instanceof Object)) {
            throw new TypeError('Invalid argument: config must be an Object.');
        }

        angular.extend(ev, params);

        angular.forEach(config.requiredKeys, function (key) {
            if (!ev[key]) {
                throw new Error('Missing parameter: ' + key);
            }
        });

        // Remove baseUrl trailing slash.
        if ('/' === ev.baseUrl.substr(-1)) {
            ev.baseUrl = ev.baseUrl.slice(0, -1);
        }

        // Add grantPath facing slash.
        if ('/' !== ev.grantPath[0]) {
            ev.grantPath = "/" + ev.grantPath;
        }

        // Add revokePath facing slash.
        if ('/' !== ev.revokePath[0]) {
            ev.revokePath = "/" + ev.revokePath;
        }
    }

    this.configureDev = function (params) {
        configure('dev', params);
    }

    this.configureProd = function (params) {
        configure('prod', params);
    }

    this.$get = function ($http, OAuthToken) {
        var OAuth = function () {
            var ev = config.servers[config.env];

            this.isAuthenticated = function () {
                return !!OAuthToken.getToken();
            }

            this.getAccessToken = function (data, options) {
                data = angular.extend({
                    client_id: ev.clientId,
                    grant_type: 'password'
                }, data);

                if (null !== ev.clientSecret) {
                    data.client_secret = ev.clientSecret;
                }

                data = buildQueryString(data);

                options = angular.extend({
                    headers: {
                        'Authorization': undefined,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }, options);

                return $http.post(ev.baseUrl + ev.grantPath, data, options)
                    .then(function (response) {
                        OAuthToken.setToken(response.data);
                        return response;
                    });
            }

            this.getRefreshToken = function (data, options) {
                data = angular.extend({
                    client_id: ev.clientId,
                    grant_type: 'refresh_token',
                    refresh_token: OAuthToken.getRefreshToken(),
                }, data);

                if (null !== ev.clientSecret) {
                    data.client_secret = ev.clientSecret;
                }

                data = buildQueryString(data);

                options = angular.extend({
                    headers: {
                        'Authorization': undefined,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }, options);

                return $http.post(ev.baseUrl + ev.grantPath, data, options)
                    .then(function (response) {
                        OAuthToken.setToken(response.data);
                        return response;
                    });
            }

            this.revokeToken = function (data, options) {
                var refreshToken = OAuthToken.getRefreshToken();

                data = angular.extend({
                    client_id: ev.clientId,
                    token: refreshToken ? refreshToken : OAuthToken.getAccessToken(),
                    token_type_hint: refreshToken ? 'refresh_token' : 'access_token'
                }, data);

                if (null !== ev.clientSecret) {
                    data.client_secret = ev.clientSecret;
                }

                data = buildQueryString(data);

                options = angular.extend({
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }, options);

                return $http.post(ev.baseUrl + ev.revokePath, data, options)
                    .then(function (response) {
                        OAuthToken.removeToken();
                        return response;
                    });
            }
        }

        return new OAuth();
    }
    this.$get.$inject = ['$http', 'OAuthToken'];
}

function oAuthTokenProvider() {
    this.$get = function ($localStorage) {
        var OAuthToken = function () {
            this.setToken = function (data) {
                $localStorage.authToken = data;
            }

            this.getToken = function () {
                return $localStorage.authToken;
            }

            this.getAccessToken = function () {
                return this.getToken() ? this.getToken().access_token : undefined;
            }

            this.getAuthorizationHeader = function () {
                if (!(this.getTokenType() && this.getAccessToken())) {
                    return;
                }

                return this.getTokenType().charAt(0).toUpperCase() +
                    this.getTokenType().substr(1) + this.getAccessToken();
            }

            this.getRefreshToken = function () {
                return this.getToken() ? this.getToken().refresh_token : undefined;
            }

            this.getTokenType = function () {
                return this.getToken() ? this.getToken().token_type : undefined;
            }

            this.removeToken = function () {
                $localStorage.authToken = undefined;
                return $localStorage.authToken;
            }
        }

        return new OAuthToken();
    }
    this.$get.$inject = ['$localStorage'];
}

oauthInterceptor.$inject = ['$q', '$rootScope', 'OAuthToken', 'oAuthConfig'];
function oauthInterceptor($q, $rootScope, OAuthToken, oAuthConfig) {
    return {
        request: function (config) {
            var ev = oAuthConfig.servers[oAuthConfig.env];

            config.headers = config.headers || {};

            // Inject Authorization header.
            if (config.url.startsWith(ev.baseUrl)) {
                if (!config.headers.hasOwnProperty('Authorization') && OAuthToken.getAuthorizationHeader()) {
                    config.headers.Authorization = OAuthToken.getAuthorizationHeader();
                }
            }
            return config;
        },
        responseError: function (rejection) {
            // Catch invalid_request and invalid_grant errors and ensure that the token is removed.
            if (400 === rejection.status && rejection.data &&
                ('invalid_request' === rejection.data.error ||
                    'invalid_grant' === rejection.data.error)) {
                OAuthToken.removeToken();

                $rootScope.$emit('oauth:error', rejection);
            }

            // Catch invalid_token and unauthorized errors.
            // The token isn't removed here so it can be refreshed when the invalid_token error occurs.
            if (401 === rejection.status &&
                (rejection.data && 'invalid_token' === rejection.data.error) ||
                (rejection.headers('www-authenticate') &&
                    0 === rejection.headers('www-authenticate').indexOf('Bearer'))) {
                $rootScope.$emit('oauth:error', rejection);
            }

            return $q.reject(rejection);
        }
    }
}

oauthConfigInterceptor.$inject = ['$httpProvider'];
function oauthConfigInterceptor($httpProvider) {
    $httpProvider.interceptors.push('oauthInterceptor');
}


//kitKat problem
if (typeof String.prototype.startsWith != 'function') {
    // see below for better implementation!
    String.prototype.startsWith = function (str) {
        return this.indexOf(str) === 0;
    };
}