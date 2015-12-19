angular.module( 'sample.account', [
  'ui.router',
  'angular-storage'
])
.config(function($stateProvider) {
  $stateProvider.state('account', {
    url: '/account',
    controller: 'AccountCtrl',
    templateUrl: 'account/account.html',
	bodyId: 'account'
  });
})
.controller( 'AccountCtrl', function LoginController( $scope, $interval, $window, $http, store, $state, AuthenticationService, API) {

	API.get(API.endpoints.sessions, {params: {last: true}}).then(function(response) {
		$scope.sessions = response.data
		console.log(data)
	}, function(error) {
		console.log(error);
	});


});
