angular.module( 'sample.shares', [
  'ui.router',
  'angular-storage',
  'angular-jwt'
])
.config(function($stateProvider) {
  $stateProvider.state('shares', {
    url: '/shares',
    controller: 'SharesCtrl',
    templateUrl: 'shares/shares.html',
    data: {
      requiresLogin: true
    },
	bodyId: 'shares'
  });
})
.controller( 'SharesCtrl', function DevicesController( $scope, API, ngDialog) {
	var controller = this; 
	API.GET(API.endpoints.shares).then(function(data) {
		$scope.shares = data
    }, function(error) {
		console.log(error);
    });
	
	


	
//	API.GET(API.endpoints.trackers).then(function(data) {
//		$scope.trackers = data
 //   }, function(error) {
//		console.log(error);
 //   });
	
	API.GET(API.endpoints.trackings).then(function(data) {
		$scope.trackings = data
	}, function(error) {
		console.log(error);
	});

	$scope.deleteTracking = function(id) {
		
	}
	
	$scope.acceptTracking = function(id) {
		
	}

		
	$scope.deleteShare = function(share) {
		API.DELETE(API.endpoints.share, {pathParams: {shareId: share.id}}).then(function(data) {		
			var index = $scope.share.indexOf(share);
			$scope.shareS.splice(index, 1);     
		}, function(error) {
			console.log(error);
		});

	}
	
	$scope.addTracker = function() {
		$scope.formData = {};

        var dialog = ngDialog.open({ template: 'shares/add.html', showClose: false, closeByEscape: true, closeByDocument: true, overlay: true, scope:  $scope});
		API.GET(API.endpoints.devices).then(function(data) {
			$scope.devices = data;
		}, function(error) {
			console.log(error);
		});
		

		dialog.closePromise.then(function(data) {
		    console.log(data.id + ' has been dismissed.');
			console.log(data);
		})
    };
	
	$scope.saveTracker = function() {
		console.log($scope.formData); 
		
		API.POST(API.endpoints.trackers, {data: $scope.formData}).then(function(tracker) {
			console.log("tracker created");
			console.log(tracker);
			$scope.trackers.push(tracker)
		}, function(error){
			console.error(error);
		})
		
		ngDialog.closeAll();
	}



}).controller('SampleModalController', function($scope, close) {
  console.log("sample controller startet")

 $scope.dismissModal = function(result) {
	console.log("dismissmodal")
    close(result, 200); // close, but give 200ms for bootstrap to animate
 };

});
;
