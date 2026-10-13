document.addEventListener('DOMContentLoaded', function() {
    const btn = $(".settings-create-key-btn");

    btn.on('click', function (event) {
        event.preventDefault();

        const permission1 = $("#checkbox-permission1").is(":checked");
        const permission2 = $("#checkbox-permission2").is(":checked");
        const permission3 = $("#checkbox-permission3").is(":checked");
        const permission4 = $("#checkbox-permission4").is(":checked");
        const permission5 = $("#checkbox-permission5").is(":checked");
        const permission6 = $("#checkbox-permission6").is(":checked");

        if (!permission1 && !permission2 && !permission3 && !permission4 && !permission5 && !permission6) {
            noti(getMessage('settings.api.permissions.not.selected'), 'error');
            return;
        }

        $.ajax({
            url: "../api/user/settings",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({
                action: "CREATE_API_KEY",
                permission_1: permission1,
                permission_2: permission2,
                permission_3: permission3,
                permission_4: permission4,
                permission_5: permission5,
                permission_6: permission6
            }),
            success: function (response) {
                if (response === 'settings.settings.api.key.created') {
                    noti(getMessage(response), "success");
                    setTimeout(() => {
                        location.reload();
                    }, 700);
                } else {
                    noti(getMessage(response), 'error');
                }
            }
        });
    });

    $(".settings-api-key-delete-btn").on('click', function (event) {
        const btn = $(this);
        const id = btn.attr('id').split("_")[2];

        $.ajax({
            url: "../api/user/settings",
            type: "POST",
            contentType: "application/json",
            data: JSON.stringify({
                action: "DELETE_API_KEY",
                id: id
            }),
            success: function (response) {
                if (response === 'settings.settings.api.key.deleted') {
                    noti(getMessage(response), "success");
                    btn.closest('tr').remove();
                } else {
                    location.reload();
                }
            }
        });
    });
});