angular.module( 'sample', [
  'sample.devices',
  'sample.shares',
  'sample.history',
  'sample.login',
  'sample.signup',
  'sample.account',
  'angular-storage',
  'angular-jwt',
  'angular-loading-bar',
  'ngDialog',
  'vs-repeat'
])
.config( function myAppConfig ($urlRouterProvider, jwtInterceptorProvider, $httpProvider) {
  $urlRouterProvider.otherwise('/');

  jwtInterceptorProvider.tokenGetter = ['AuthenticationService', 'config', function(AuthenticationService, config) {
	if (config.url.substr(config.url.length - 5) == '.html') {
      return null;
    }
	  
	return AuthenticationService.getAccessToken(); 

  }];
  $httpProvider.interceptors.push('jwtInterceptor');
}).run(function($rootScope, $state, store, AuthenticationService) {

	$rootScope.$on('$stateChangeStart', function (e, to) {
		if (to.data && to.data.requiresLogin && !AuthenticationService.loggedIn) {
			e.preventDefault();
			$state.go('login');	
		}	
	});
	$rootScope.$on('$stateChangeSuccess',function(event, toState, toParams, fromState, fromParams){
        $rootScope.bodyId = toState.bodyId;
    });

	$rootScope.$on('loggedOut', function(event, args) {
		$state.go('login');	
	});
	
})
.controller( 'AppCtrl', function AppCtrl ($rootScope, $state, $scope, $location, AuthenticationService, API) {
	$scope.AuthenticationService = AuthenticationService
	$scope.$on('$routeChangeSuccess', function(e, nextRoute){
		if ( nextRoute.$$route && angular.isDefined( nextRoute.$$route.pageTitle ) ) {
		  $scope.pageTitle = nextRoute.$$route.pageTitle + ' | ngEurope Sample' ;
		}
	});

	$rootScope.$on('loggedIn', function(event, args) {
		updateUserArea();
	});

	
	var updateUserArea = function() {
		console.log("updateUserArea")
		API.GET(API.endpoints.user).then(function(data) {
			$scope.user = data
		}, function(error) {
			console.log(error);
		});
	}
	

	
	if(AuthenticationService.loggedIn)
		updateUserArea();

	$scope.logout = function() {
		AuthenticationService.logout();	
	}
	
	$scope.showAccount = function() {
		AuthenticationService.logout();	
	}
})
.factory( 'AuthenticationService', function($rootScope, $http, store, jwtHelper, $q) {
	var authService = {loggedIn: false};
	setUser = function(refreshToken){
			if(refreshToken == null)
				return console.error("User is not logged in yet")
			
			authService.currentUser = jwtHelper.decodeToken(refreshToken); 		
			authService.loggedIn = true; 
			console.log("loggedIn")
			$rootScope.$broadcast('loggedIn');

	};
	
	getRefreshToken = function() { 
		return store.get('refreshToken')
	}
	
	setRefreshToken = function(refreshToken) {
		store.set('refreshToken', refreshToken);
	}
	
	hasRefreshToken = function() { 
		return getRefreshToken() != null
	}
	
	login = function(refreshToken) {
		setRefreshToken(refreshToken);
		setUser(refreshToken);
	}
	getUser = function() { return currentUser; },
	getUserId = function() { return currentUser.userId; }

	if(hasRefreshToken()) {
		setUser(getRefreshToken());			
	} 
		
	authService.login = function (credentials) {
		return $http({
			url: 'https://hosted-dev.owntracks.org/api/v1/authenticate',
			method: 'POST',
			data: credentials,
			skipAuthorization: true
		}).then(function(response) {
			login(response.data.data.refreshToken)
		})
	}
	
	authService.logout = function () {
		store.remove("accessToken");
		store.remove("refreshToken");

		authService.loggedIn = false; 
	
		console.log("loggedOut")
		$rootScope.$broadcast('loggedOut');
	}
	

	
	var accessTokenRequestLock = false;
	var requestPromiseQueue = []; 
	authService.getAccessToken = function() {
	
		var refreshToken = store.get('refreshToken');

		if(!refreshToken) {
		  console.error("user is not logged in"); 
		  return; 
		}
		
		var idToken = store.get('accessToken');
		if (!idToken || jwtHelper.isTokenExpired(idToken)) {
			console.log("access token is expired or not preset, gettig one");
			
			if(accessTokenRequestLock) {
				// An access token is already being requested
				// Return a not fulfilled promise
				// It will be fulfilled with the access token once it is availale
				return new Promise(function(resolve, reject) {
					requestPromiseQueue.push(resolve);
				})	
			} else {
				accessTokenRequestLock = true;
			}
			
			// This is a promise of a JWT id_token
			return $http({
				url: '/api/v1/authenticate/refresh',
				// This makes it so that this request doesn't send the JWT
				skipAuthorization: true,
				method: 'POST',
				headers: {
				  'Authorization':('Bearer ' + refreshToken)
				}
			}).then(function(response) {
				console.log("response for refresh token: "); 
				console.log(response);
				var id_token = response.data.data.accessToken;
				if(!id_token)
					  return;
				  
				store.set('accessToken', id_token);
				console.log("new access token is now available"); 
				console.log("fulfilling  " + requestPromiseQueue.length + " promises"); 

				for(var i=0; i< requestPromiseQueue.length; i++) {
					console.log(requestPromiseQueue[i]);
					requestPromiseQueue[i](id_token);
				}
				requestPromiseQueue.length = 0 // clear queue
				accessTokenRequestLock = false;
				
				return id_token;
			});
		} else {
			//console.log("using access token: " + idToken); 
			return idToken;
		}
	}
	
  
		
	return authService;

})
.factory('API', function($q, $http, AuthenticationService) {

    var baseApiUrl = 'https://hosted-dev.owntracks.org/api/v1/',
    endpoints = {
		signup: baseApiUrl + 'users',
        users : baseApiUrl + 'users',
        user: baseApiUrl + 'users/:userId',
        devices: baseApiUrl + 'users/:userId/devices',
        device: baseApiUrl + 'users/:userId/devices/:deviceId',
        deviceHistory: baseApiUrl + 'users/:userId/devices/:deviceId/history',
        deviceHistoryExport: baseApiUrl + 'users/:userId/devices/:deviceId/history/export',
        shares: baseApiUrl + 'users/:userId/shares',
        share: baseApiUrl + 'users/:userId/shares/:shareId',
        sessions: baseApiUrl + 'users/:userId/sessions',
        session: baseApiUrl + 'users/:userId/sessions/:sessionId',

    };

    function fillUrl(urlFormat, pathParams, options) {
        var url = urlFormat;

	var params = pathParams || {};
	if(!options.skipAuthorization && !params.userId) {
		params.userId = AuthenticationService.currentUser.userId;
        }

        angular.forEach(params, function (val, name) {
            if (typeof(val) === 'undefined' || val === null || val === '') {
                url = url.replace(RegExp('/:' + name, 'g'), '');
            } else {
                url = url.replace(RegExp(':' + name, 'g'), val);
            }

        });

        return url;
    }
  
    var queryEndpoint = function(endpoint, options, method) {

		if(!options)
			options = {}

		var url = fillUrl(endpoint, options.pathParams, options); 
		console.log("running API query to endpoint: " + url);

		var d = $q.defer();
		$http({url: url, method: method || 'GET', data: options.data, params: options.params, skipAuthorization: options.skipAuthorization || false}).success(function(data){
			return d.resolve(data);
		}).error(function(error){
			return d.reject(error);
		});
 
		return d.promise;
    };

    var GET = function(endpoint, options) {
		return queryEndpoint(endpoint, options, 'GET');
	}
	var POST = function(endpoint, options) {
		return queryEndpoint(endpoint, options, 'POST');
	}
	var PUT = function(endpoint, options) {
		return queryEndpoint(endpoint, options, 'PUT');
	}
	var DELETE = function(endpoint, options) {
		return queryEndpoint(endpoint, options, 'DELETE');
	}
    return {
        endpoints: endpoints,
        q: queryEndpoint ,
		get: GET,
		post: POST, 
		put: PUT, 
		GET: GET,
		POST: POST, 
		PUT: PUT, 
		DELETE: DELETE, 
		fillUrl: fillUrl
    };
}).directive('ngReallyClick', [function() {
    return {
        restrict: 'A',
        link: function(scope, element, attrs) {
            element.bind('click', function() {
                var message = attrs.ngReallyMessage;
                if (message && confirm(message)) {
                    scope.$apply(attrs.ngReallyClick);
                }
            });
        }
    }
}]);
;




