document.addEventListener('DOMContentLoaded', function () {
    var alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function (a) {
        setTimeout(function () { a.remove(); }, 4000);
    });
});
