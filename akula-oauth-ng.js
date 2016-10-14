(function() {
    'use strict';
    angular
        .module('akulaOAuthNG', [])
        .config(oauthConfig)
        .factory('oauthInterceptor', oauthInterceptor)
        .provider('OAuth', OAuthProvider)
        .provider('OAuthToken', OAuthTokenProvider);


    var defaults = {
		  baseUrl: null,
		  clientId: null,
		  clientSecret: null,
		  grantPath: '/oauth2/token',
		  revokePath: '/oauth2/revoke'
		};

		var requiredKeys = [
		  'baseUrl',
		  'clientId',
		  'grantPath',
		  'revokePath'
		];

		/**
		 * OAuth provider.
		 */

		function OAuthProvider() {
		  var config;

		  /**
		   * Configure.
		   *
		   * @param {object} params - An object of params to extend.
		   */

		  this.configure = function(params) {
		    // Can only be configured once.
		    if (config) {
		      throw new Error('Already configured.');
		    }

		    // Check if is an object.
		    if (!(params instanceof Object)) {
		      throw new TypeError('Invalid argument: config must be an Object.');
		    }

		    // Extend default configuration.
		    config = angular.extend({}, defaults, params);

		    // Check if all required keys are set.
		    /*
		    angular.forEach(requiredKeys, (key) => {
		      if (!config[key]) {
		        throw new Error('Missing parameter: ' + key);
		      }
		    });*/

		    // Remove baseUrl trailing slash.
		    if('/' === config.baseUrl.substr(-1)) {
		      config.baseUrl = config.baseUrl.slice(0, -1);
		    }

		    // Add grantPath facing slash.
		    if('/' !== config.grantPath[0]) {
		      config.grantPath = "/" + config.grantPath;
		    }

		    // Add revokePath facing slash.
		    if('/' !== config.revokePath[0]) {
		      config.revokePath = "/" + config.revokePath;
		    }

		    return config;
		  };

		  /**
		   * OAuth service.
		   */

		  this.$get = function($http, OAuthToken) {
		    var OAuth = function() {


		    	var buildQueryString = function(obj) {
		        var str = [];

		        angular.forEach(obj, function(value, key) {
		          str.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
		        });

		        return str.join('&');
		      };

		      /**
		       * Check if OAuthProvider is configured.
		       */

		      this.constructor = function() {
		        if (!config) {
		          throw new Error('OAuthProvider must be configured first.');
		        }
		      }

		      /**
		       * Verifies if the user is authenticated or not based on the token
		       * cookie.
		       *
		       * @return {boolean}
		       */

		      this.isAuthenticated = function() {
		        return !!OAuthToken.getToken();
		      }

		      /**
		       * Retrieves the access_token and stores the response.data on cookies
		       * using the OAuthToken.
		       *
		       * @param {object} data - Request content, e.g., username and password.
		       * @param {object} options - Optional configuration.
		       * @return {promise} A response promise.
		       */

		      this.getAccessToken = function(data, options) {
		        data = angular.extend({
		          client_id: config.clientId,
		          grant_type: 'password'
		        }, data);

		        if (null !== config.clientSecret) {
		          data.client_secret = config.clientSecret;
		        }

		        data = buildQueryString(data);

		        options = angular.extend({
		          headers: {
		            'Authorization': undefined,
		            'Content-Type': 'application/x-www-form-urlencoded'
		          }
		        }, options);

		        return $http.post(config.baseUrl + config.grantPath, data, options).then(function(response) {
		          OAuthToken.setToken(response.data);

		          return response;
		        });
		      }

		      /**
		       * Retrieves the refresh_token and stores the response.data on cookies
		       * using the OAuthToken.
		       *
		       * @param {object} data - Request content.
		       * @param {object} options - Optional configuration.
		       * @return {promise} A response promise.
		       */

		      this.getRefreshToken = function(data, options) {
		        data = angular.extend({
		          client_id: config.clientId,
		          grant_type: 'refresh_token',
		          refresh_token: OAuthToken.getRefreshToken(),
		        }, data);

		        if (null !== config.clientSecret) {
		          data.client_secret = config.clientSecret;
		        }

		        data = buildQueryString(data);

		        options = angular.extend({
		          headers: {
		            'Authorization': undefined,
		            'Content-Type': 'application/x-www-form-urlencoded'
		          }
		        }, options);

		        return $http.post(config.baseUrl + config.grantPath, data, options).then(function(response) {
		          OAuthToken.setToken(response.data);

		          return response;
		        });
		      }

		      /**
		       * Revokes the token and removes the stored token from cookies
		       * using the OAuthToken.
		       *
		       * @param {object} data - Request content.
		       * @param {object} options - Optional configuration.
		       * @return {promise} A response promise.
		       */

		      this.revokeToken = function(data, options) {
		        var refreshToken = OAuthToken.getRefreshToken();

		        data = angular.extend({
		          client_id: config.clientId,
		          token: refreshToken ? refreshToken : OAuthToken.getAccessToken(),
		          token_type_hint: refreshToken ? 'refresh_token' : 'access_token'
		        }, data);

		        if (null !== config.clientSecret) {
		          data.client_secret = config.clientSecret;
		        }

		        data = buildQueryString(data);

		        options = angular.extend({
		          headers: {
		            'Content-Type': 'application/x-www-form-urlencoded'
		          }
		        }, options);

		        return $http.post(config.baseUrl + config.revokePath, data, options).then(function(response) {
		          OAuthToken.removeToken();

		          return response;
		        });
		      }
		    }

		    return new OAuth();
		  };

		  this.$get.$inject = ['$http', 'OAuthToken'];
		}    

    function OAuthTokenProvider() {
		  var config = {
		    name: 'token',
		    options: {
		      secure: true
		    }
		  };

		  /**
		   * Configure.
		   *
		   * @param {object} params - An object of params to extend.
		   */

		  this.configure = function(params) {
		    // Check if is an object.
		    if (!(params instanceof Object)) {
		      throw new TypeError('Invalid argument: config must be an Object.');
		    }

		    // Extend default configuration.
		    angular.extend(config, params);

		    return config;
		  };

		  /**
		   * OAuthToken service.
		   */

		  this.$get = function($localStorage) {
		    var OAuthToken = function() {

		      /**
		       * Set token.
		       */

		      this.setToken = function(data) {
		      	$localStorage.authToken = data;
		        //return $cookies.put(config.name, data, config.options);
		        return $localStorage.authToken;
		      }

		      /**
		       * Get token.
		       */

		      this.getToken = function() {
		        //return $cookies.get(config.name);
		        return $localStorage.authToken;
		      }

		      /**
		       * Get accessToken.
		       */

		      this.getAccessToken = function() {
		        return this.getToken() ? this.getToken().access_token : undefined;
		      }

		      /**
		       * Get authorizationHeader.
		       */

		      this.getAuthorizationHeader = function() {
		        if (!(this.getTokenType() && this.getAccessToken())) {
		          return;
		        }

		        return this.getTokenType().charAt(0).toUpperCase() + this.getTokenType().substr(1) + this.getAccessToken();
		      }

		      /**
		       * Get refreshToken.
		       */

		      this.getRefreshToken = function() {
		        return this.getToken() ? this.getToken().refresh_token : undefined;
		      }

		      /**
		       * Get tokenType.
		       */

		      this.getTokenType = function() {
		        return this.getToken() ? this.getToken().token_type : undefined;
		      }

		      /**
		       * Remove token.
		       */

		      this.removeToken = function() {
		        //return $cookies.remove(config.name, config.options);
		        $localStorage.authToken = undefined;
		        return $localStorage.authToken;
		      }
		    }

		    return new OAuthToken();
		  };

		  this.$get.$inject = ['$localStorage'];
		}    

    oauthConfig.$inject = ['$httpProvider'];
    function oauthConfig($httpProvider) {
		  $httpProvider.interceptors.push('oauthInterceptor');
		}

		oauthInterceptor.$inject = ['$q', '$rootScope', 'OAuthToken'];
		function oauthInterceptor($q, $rootScope, OAuthToken) {
		  return {
		    request: function(config) {
		      config.headers = config.headers || {};

		      // Inject Authorization header.
		      if (!config.headers.hasOwnProperty('Authorization') && OAuthToken.getAuthorizationHeader()) {
		        config.headers.Authorization = OAuthToken.getAuthorizationHeader();
		      }

		      return config;
		    },
		    responseError: function(rejection) {
		      // Catch invalid_request and invalid_grant errors and ensure that the token is removed.
		      if (400 === rejection.status && rejection.data &&
		        ('invalid_request' === rejection.data.error || 'invalid_grant' === rejection.data.error)
		      ) {
		        OAuthToken.removeToken();

		        $rootScope.$emit('oauth:error', rejection);
		      }

		      // Catch invalid_token and unauthorized errors.
		      // The token isn't removed here so it can be refreshed when the invalid_token error occurs.
		      if (401 === rejection.status &&
		        (rejection.data && 'invalid_token' === rejection.data.error) ||
		        (rejection.headers('www-authenticate') && 0 === rejection.headers('www-authenticate').indexOf('Bearer'))
		      ) {
		        $rootScope.$emit('oauth:error', rejection);
		      }

		      return $q.reject(rejection);
		    }
		  };
	} 
})();
