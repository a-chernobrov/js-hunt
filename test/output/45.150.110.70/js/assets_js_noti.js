const errorsCache = new Map();

$("#app").prepend(`<div id="v-notifications" class="v-snack v-snack--active v-snack--bottom v-snack--has-background">
   
</div>`)

function noti(msg, status) {
    var statusIcon = 'mdi-check-circle-outline';
    if (status === 'error') {
        statusIcon = 'mdi-close-circle-outline';
    } else if (status === 'info') {
        statusIcon = 'info-slab-circle-outline';
    }

    const alertHtml = `
    <div class="v-snack__wrapper v-sheet theme--dark" style="">
      <div role="status" aria-live="polite" class="v-snack__content">${msg}</div>
      <div class="v-snack__action ">
          <button onclick="closeNoti(this)" type="button" class="v-btn v-btn--text theme--dark v-size--default white--text v-snack__btn">
              <span class="v-btn__content">
                  <i aria-hidden="true" class="v-icon notranslate mdi ${statusIcon} theme--dark"></i>
              </span>
          </button>
      </div>
    </div>`;

    const notifications = $("#v-notifications");

    if (notifications.find('.v-snack__wrapper').length >= 3) {
        notifications.find('.v-snack__wrapper').first().remove();
    }

    notifications.append(alertHtml);

    const notification = notifications.find('.v-snack__wrapper').last();

    setTimeout(() => {
        if (notification) {
            try {
                notification.remove();
            } catch (ignored) {}
        }
    }, 2500);
}

function closeNoti(el) {
    const parent = $(el).closest('.v-snack__wrapper');
    parent.remove();
}

var currentOnClose;

function popup(title, message, img, status, withBtn, onClose, btnMessage) {
    if ($("#custom-popup")) {
        $("#custom-popup").remove();
    }

    currentOnClose = onClose;

    const btn = withBtn ? `
        <button type="button" onclick="closePopup()" class="discard-modal__verification-btn v-btn v-btn--is-elevated v-btn--has-bg theme--light v-size--default" style="width: 100%;">
            <span class="v-btn__content">${btnMessage ? btnMessage : getMessage('popup.button.good')}</span>
        </button>` : null;

    var banner = "warning.png";
    if (img.indexOf('gift') > 0) {
        banner = "gift.png"
    }

    const html = `
    <div id="custom-popup" role="dialog" aria-modal="true" class="custom-popup v-dialog__content v-dialog__content--active" style="z-index: 99999999999999999;">
        <div tabIndex="0" class="discard-modal v-dialog dialog v-dialog--active" style="transform-origin: center center; width: ${img && (img.indexOf('qrcode.svg') > 0 || img.indexOf('antiphishing.svg') > 0) ? '400' : '500'}px; padding-top: 25px; text-align: center; padding: 0 !important; transform-origin: center center; text-align: center;">
            <div class="dialog__close" onclick="closePopup()">
                <i aria-hidden="true" class="v-icon notranslate dialog__close__icon mdi mdi-close theme--light"></i>
            </div>
           
            <img src="../assets/img/banners/${banner}">
            <div style="padding-top: 4px !important; padding: 32px;">
                <div class="discard-modal__title discard-title" style="font-size: 1.6rem; position: relative; display: inline-block;">${title}</div>
                <div class="discard-modal__text">${message}</div>
                ${withBtn ? btn : ''}
            </div>
        </div>
    </div>`;

    $("footer").after(html);

    setTimeout(() => {
        $("#custom-popup").attr('showed', 'true');
    }, 300);
}

async function addErrorAction(type) {
    $.ajax({
        url: "../api/user/profile",
        type: "POST",
        contentType: 'application/json; charset=UTF-8',
        data: JSON.stringify({
            action: "ADD_ACTION",
            action_type: "GET_ERROR",
            type: type
        }),
        success: function (response) {}
    });
}

function verificationPopup(event) {
    if (event) {
        event.preventDefault();
    }

    if ($("#user-authorized").length === 0 || $("#user-authorized").val() === 'false') {
        location.replace('../signin');
        return;
    }

    if ($("#custom-popup")) {
        $("#custom-popup").remove();
    }

    currentOnClose = null;

    if (errorsCache.has('OTHER')) {
        addErrorAction("OTHER");

        const html = `
        <div id="custom-popup" role="dialog" aria-modal="true" class="custom-popup v-dialog__content v-dialog__content--active" style="z-index: 99999999999999999;">
            <div tabIndex="0" class="discard-modal v-dialog dialog v-dialog--active" style="transform-origin: center center; width: 500px; padding-top: 25px; text-align: center; padding: 0 !important; transform-origin: center center; text-align: center;">
                <div class="dialog__close" onclick="closePopup()">
                    <i aria-hidden="true" class="v-icon notranslate dialog__close__icon mdi mdi-close theme--light"></i>
                </div>
                <img src="../assets/img/banners/error.png">
                <div style="padding-top: 4px !important; padding: 32px;">
                    <div class="discard-modal__title discard-title" style="font-size: 1.6rem; position: relative; display: inline-block;">${getMessage('popup.title.verification')}</div>
                    <div class="discard-modal__text">${errorsCache.get('OTHER')}</div>
                    <button type="button" onclick="window.location.href = '../profile/verification';" class="discard-modal__verification-btn v-btn v-btn--is-elevated v-btn--has-bg theme--light v-size--default" style="width: 100%;">
                        <span class="v-btn__content">${getMessage('popup.button.verification')}</span>
                    </button>
                </div>
            </div>
        </div>`;

        $("footer").after(html);

        setTimeout(() => {
            $("#custom-popup").attr('showed', 'true');
        }, 300);
        return;
    }

    $.ajax({
        url: "../api/user/profile",
        type: "POST",
        contentType: 'application/json; charset=UTF-8',
        dataType: "text",
        data: JSON.stringify({
            action: "GET_ERROR_MESSAGE",
            type: "OTHER"
        }),
        success: function (response) {
            errorsCache.set("OTHER", response);

            verificationPopup();
        }
    });
}

function errorPopup(type, onClose, event) {
    if (event) {
        event.preventDefault();
    }

    if ($("#user-authorized").length === 0 || $("#user-authorized").val() === 'false') {
        location.replace('../signin');
        return;
    }

    if ($("#custom-popup")) {
        $("#custom-popup").remove();
    }

    currentOnClose = onClose;

    if (errorsCache.has(type)) {
        addErrorAction(type);

        const html = `
        <div id="custom-popup" role="dialog" aria-modal="true" class="custom-popup v-dialog__content v-dialog__content--active" style="z-index: 99999999999999999;">
            <div tabIndex="0" class="discard-modal v-dialog dialog v-dialog--active" style="transform-origin: center center; width: 500px; padding-top: 25px; text-align: center; padding: 0 !important; transform-origin: center center; text-align: center;">
                <div class="dialog__close" onclick="closePopup()">
                    <i aria-hidden="true" class="v-icon notranslate dialog__close__icon mdi mdi-close theme--light"></i>
                </div>
                <img src="../assets/img/banners/error.png">
                <div style="padding-top: 4px !important; padding: 32px;">
                    <div class="discard-modal__title discard-title" style="font-size: 1.6rem; position: relative; display: inline-block;">${getMessage('popup.title.verification')}</div>
                    <div class="discard-modal__text">${errorsCache.get(type)}</div>
                    <button type="button" onclick="closePopup()" class="discard-modal__verification-btn v-btn v-btn--is-elevated v-btn--has-bg theme--light v-size--default" style="width: 100%;">
                        <span class="v-btn__content">${getMessage('popup.button.good')}</span>
                    </button>
                </div>
            </div>
        </div>`;

        $("footer").after(html);

        setTimeout(() => {
            $("#custom-popup").attr('showed', 'true');
        }, 300);
        return;
    }

    $.ajax({
        url: "../api/user/profile",
        type: "POST",
        contentType: 'application/json; charset=UTF-8',
        dataType: "text",
        data: JSON.stringify({
            action: "GET_ERROR_MESSAGE",
            type: type
        }),
        success: function (response) {
            errorsCache.set(type, response);

            errorPopup(type, event);
        }
    });
}

function withdrawPopup(type, event) {
    if (event) {
        event.preventDefault();
    }

    if ($("#user-authorized").length === 0 || $("#user-authorized").val() === 'false') {
        location.replace('../signin');
        return;
    }

    if ($("#custom-popup")) {
        $("#custom-popup").remove();
    }

    currentOnClose = null;

    if (errorsCache.has(type)) {
        addErrorAction(type);

        const html = `
        <div id="custom-popup" role="dialog" aria-modal="true" class="custom-popup v-dialog__content v-dialog__content--active" style="z-index: 99999999999999999;">
            <div tabIndex="0" class="discard-modal v-dialog dialog v-dialog--active" style="transform-origin: center center; width: 500px; padding-top: 25px; text-align: center; padding: 0 !important; transform-origin: center center; text-align: center;">
                <div class="dialog__close" onclick="closePopup()">
                    <i aria-hidden="true" class="v-icon notranslate dialog__close__icon mdi mdi-close theme--light"></i>
                </div>
                <img src="../assets/img/banners/${type && type === 'WITHDRAW_AML' ? 'aml.png' : 'error.png'}">
                <div style="padding-top: 4px !important; padding: 32px;">
                    <div class="discard-modal__title discard-title" style="font-size: 1.6rem; position: relative; display: inline-block;">${getMessage(type === 'WITHDRAW_AML' ? 'popup.aml.title' : 'popup.withdraw.title')}</div>
                    <div class="discard-modal__text">${errorsCache.get(type)}</div>
                    <button type="button" onclick="location.replace('../profile/deposit-verification')" class="discard-modal__verification-btn v-btn v-btn--is-elevated v-btn--has-bg theme--light v-size--default" style="width: 100%;">
                        <span class="v-btn__content">${getMessage('popup.button.deposit.verification')}</span>
                    </button>
                </div>
            </div>
        </div>`;

        $("footer").after(html);

        setTimeout(() => {
            $("#custom-popup").attr('showed', 'true');
        }, 300);
        return;
    }

    $.ajax({
        url: "../api/user/profile",
        type: "POST",
        contentType: 'application/json; charset=UTF-8',
        dataType: "text",
        data: JSON.stringify({
            action: "GET_ERROR_MESSAGE",
            type: type
        }),
        success: function (response) {
            errorsCache.set(type, response);

            withdrawPopup(type, event);
        }
    });
}

function closePopup(){
    const popup = $("#custom-popup");
    popup.addClass('custom-popup-fade-out');

    setTimeout(() => {
        popup.remove();

        if (currentOnClose && typeof currentOnClose === 'function') {
            currentOnClose();
        }
    }, 500);

    $("#custom-popup").attr('showed', 'false');
}

document.addEventListener('click', function () {
    if ($("#custom-popup") && $("#custom-popup").attr('showed') === 'true' && !event.target.closest('.custom-popup')) {
        closePopup();
    }
});