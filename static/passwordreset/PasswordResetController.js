(function () {
    'use strict';
    angular.module('PasswordReset')
        .controller('PasswordResetController', [
            PasswordResetController
        ]);
    function PasswordResetController() {
        var self = this;
        self.domains = [
            '@students.iiit.ac.in',
            '@research.iiit.ac.in',
            '@alumni.iiit.ac.in',
            '@iiit.ac.in',
        ];
        self.domain = self.domains[0];
        self.uid = "";
        self.newCAPassword1 = "";
        self.newCAPassword2 = "";
        self.newLANPassword1 = "";
        self.newLANPassword2 = "";
    }
})();
