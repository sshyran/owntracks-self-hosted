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
.controller( 'AccountCtrl', function LoginController( $scope, $interval, $window, $http, store, $state, AuthenticationService, API, ngDialog, Flash) {

	API.get(API.endpoints.sessions, {params: {last: true}}).then(function(response) {
		$scope.sessions = response.data
	}, function(error) {
		console.log(error);
	});

	$scope.editAccount = function() {
		$scope.formData = {};


		
        var dialog = ngDialog.open({ template: 'account/edit.html', showClose: false, closeByEscape: true, closeByDocument: true, overlay: true, scope:  $scope});
			
		dialog.closePromise.then(function(data) {
		    console.log(data.id + ' has been dismissed.');
			console.log(data);
		})
    };
	
	$scope.saveAccount = function() {
		console.log($scope.formData); 
		
		if($scope.formData.newPassword != $scope.formData.newPasswordRepeat) {
			Flash.create('danger', 'new passwords do not match', 'custom-class');
			return; 
		}

		API.POST(API.endpoints.user, {data: $scope.formData}).then(function(response) {
			ngDialog.closeAll();
			Flash.create('success', 'Account details updated successfully', 'custom-class');
		}, function(error){
			Flash.create('danger', 'Account details could not be updated', 'custom-class');
			console.error(error);
		})
		
		
	}

});