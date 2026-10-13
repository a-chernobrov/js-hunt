var locale = null;

//event doesn't work
var messagesLoaded = false;

let lang = getCookie("lang");
if (lang == null) {
    lang = "en";
}

$.ajax({
    type: "GET",
    url: "/api/getLocale?v=2&lang=" + lang,
    success: function (response) {
        locale = response;
        messagesLoaded = true;

        checkCookiesAccepted();
    }
});

function getMessage(key, replacers) {
    let message = locale[key];

    if (replacers && replacers.length > 0) {
        replacers.forEach((replacer, index) => {
            message = message.replace(`{${index}}`, replacer);
        });
    }

    return message;
}

function checkCookiesAccepted() {
    const cookiesAccepted = getCookie("cookies_accepted");

    if (!cookiesAccepted || cookiesAccepted === "") {
        const acceptMessage = getMessage('cookies.accept.message');
        const privacyPolicy = getMessage('cookies.privacy.policy');
        const acceptButton = getMessage('cookies.accept.button');

        $("footer").prepend(`
            <div class="cookie">
               <div class="cookie__content">
                  <div class="cookie__text">
                     ${acceptMessage}
                     <a href="/info#privacy" class="">
                     ${privacyPolicy}</a>
                  </div>
                  <div class="spacer"></div>
                 <button type="button" onclick="acceptCookies(event)" class="cookie__btn">
                    <span class="v-btn__content">${acceptButton}</span>
                 </button>
               </div>
            </div>
        `);
    }
}

function getCookie(name) {
    let cookieArr = document.cookie.split(";");

    for(let i = 0; i < cookieArr.length; i++) {
        let cookiePair = cookieArr[i].split("=");

        if(name === cookiePair[0].trim()) {
            return decodeURIComponent(cookiePair[1]);
        }
    }

    return null;
}

function setCookie(cookieName, cookieValue, daysToExpire) {
    let expires = "";
    if (daysToExpire) {
        const date = new Date();
        date.setTime(date.getTime() + (daysToExpire * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = cookieName + "=" + cookieValue + expires + "; path=/";
}

function acceptCookies() {
    event.preventDefault();

    setCookie("cookies_accepted", "true", 999);
    $(".cookie").remove();
}

//mobile app start
const banner = $('#mobile-app-banner');

$('#mobile-app-btn').on('click', () => {
    banner.css('display', 'flex');
});

$('#mobile-app-close').on('click', () => {
    banner.addClass('custom-popup-fade-out');

    setTimeout(() => {
        banner.css('display', 'none');
        banner.removeClass('custom-popup-fade-out')
    }, 500);
});

document.addEventListener('click', () => {
    if (banner.css('display') !== 'none' && !event.target.closest('.v-dialog__content') && event.target.id !== 'mobile-app-btn') {
        banner.css('display', 'none');
    }
});

document.addEventListener('click', function() {
    if (!event.target.closest('.main-menu__section__menu') && !event.target.closest('.main-menu__section__nav-button')
        && !event.target.closest('.main-menu__section__profile') && !event.target.closest('.mobile-menu-button') && !event.target.closest('.mobile-menu') && !event.target.closest('.assets-hide-show')) {
        $('.main-menu__section__nav-button').each((index, btn) => {
            $(btn).removeClass('active');
        });
        $('.main-menu__section__menu').each((index, menu) => {
            $(menu).css('display', 'none');
        });
        $(".mobile-menu-button > div").removeClass('open');
        $(".mobile-menu").css('display', 'none');
        $('.menu-lang').css('display', 'none');
    }
});
//mobile app end

//header start
//mobile start

$(".main-menu__section").on('click', function (event) {
    if (event.target.closest('.main-menu__section__menu')) {
        return;
    }

    const el = $(this).find('.main-menu__section__menu');
    if ($(this).hasClass('lang-button')) {
        return;
    }
    const active = el.css('display') !== 'none';

    $('.main-menu__section__nav-button').each((index, btn) => {
        $(btn).removeClass('active');
    });
    $('.main-menu__section__menu').each((index, menu) => {
        $(menu).css('display', 'none');
    });

    $(".mobile-menu-button > div").removeClass('open');
    $(".mobile-menu").css('display', 'none');
    $('.menu-lang').css('display', 'none');

    $('.mobile-menu__item__panel').each(function() {
        const btnWrapper = $(this);

        btnWrapper.removeClass('v-expansion-panel--active');
        btnWrapper.removeClass('v-item--active');

        const btn = btnWrapper.find('button');
        btn.removeClass('v-expansion-panel-header--active');
        btn.attr('aria-expanded', 'false');

        btnWrapper.find('a').each(function() {
            $(this).css('display', 'none');
        });
    });

    if (!active) {
        if (el.hasClass('main-menu__section-flex')) {
            el.css('display', 'flex');
        } else {
            el.css('display', 'block');
        }
    }
});
//mobile end

$(".main-menu__section").on('mouseenter', function (event) {
    if (window.innerWidth < 1400) {
        return;
    }

    $(this).find('.main-menu__section__nav-button').addClass('active');
    const el = $(this).find('.main-menu__section__menu');
    if (el.hasClass('main-menu__section-flex')) {
        el.css('display', 'flex');
    } else {
        el.css('display', 'block');
    }
});

$(".main-menu__section").on('mouseleave', function (event) {
    if (window.innerWidth < 1400) {
        return;
    }

    $(this).find('.main-menu__section__nav-button').removeClass('active');
    $(this).find('.main-menu__section__menu').css('display', 'none');
});

$(".nav-button-lang").on('click', function () {
    const has = $(this).hasClass('active');

    $('.main-menu__section__nav-button').each((index, btn) => {
        $(btn).removeClass('active');
    });
    $('.main-menu__section__menu').each((index, menu) => {
        $(menu).css('display', 'none');
    });

    $(".mobile-menu-button > div").removeClass('open');
    $(".mobile-menu").css('display', 'none');
    $('.menu-lang').css('display', 'none');

    $('.mobile-menu__item__panel').each(function() {
        const btnWrapper = $(this);

        btnWrapper.removeClass('v-expansion-panel--active');
        btnWrapper.removeClass('v-item--active');

        const btn = btnWrapper.find('button');
        btn.removeClass('v-expansion-panel-header--active');
        btn.attr('aria-expanded', 'false');

        btnWrapper.find('a').each(function() {
            $(this).css('display', 'none');
        });
    });

    if (has) {
        $(this).removeClass('active');
        $('.menu-lang').css('display', 'none');
    } else {
        $(this).addClass('active');
        $('.menu-lang').css('display', 'flex');
    }
});

$(".mobile-menu-button").on('click', function () {
    const buttonIcon = $(this).find('div');

    const has = buttonIcon.hasClass('open');
    $('.main-menu__section__nav-button').each((index, btn) => {
        $(btn).removeClass('active');
    });
    $('.main-menu__section__menu').each((index, menu) => {
        $(menu).css('display', 'none');
    });
    $(".mobile-menu-button > div").removeClass('open');
    $(".mobile-menu").css('display', 'none');
    $('.menu-lang').css('display', 'none');

    $('.mobile-menu__item__panel').each(function() {
        const btnWrapper = $(this);

        btnWrapper.removeClass('v-expansion-panel--active');
        btnWrapper.removeClass('v-item--active');

        const btn = btnWrapper.find('button');
        btn.removeClass('v-expansion-panel-header--active');
        btn.attr('aria-expanded', 'false');

        btnWrapper.find('a').each(function() {
            $(this).css('display', 'none');
        });
    });

    if (has) {
        buttonIcon.removeClass('open');
        $(".mobile-menu").css('display', 'none');
    } else {
        buttonIcon.addClass('open');
        $(".mobile-menu").css('display', 'block');
    }

    $(".main-menu__section > button").each(el => {
        $(el).removeClass('active');
        $('.menu-lang').css('display', 'none');
    })
});

$(".v-expansion-panel-header").on('click', function () {
    const opened = $(this).hasClass('v-expansion-panel-header--active');
    const panel = $(this).parent();
    const content = panel.find('.v-expansion-panel-content');

    if (opened) {
        $(this).removeClass('v-expansion-panel-header--active');
        panel.removeClass('v-expansion-panel--active v-item--active');
        panel.attr('aria-expanded', 'false');
        content.css({
            'max-height': '0',
            'overflow': 'hidden',
            'padding': '0',
            'margin': '0',
            'display': 'none'
        });
    } else {
        content.css({
            'display': 'block',
            'padding': '',
            'margin': ''
        });
        const contentHeight = content.prop('scrollHeight');
        $(this).addClass('v-expansion-panel-header--active');
        panel.addClass('v-expansion-panel--active v-item--active');
        panel.attr('aria-expanded', 'true');
        content.css({
            'max-height': contentHeight + 'px',
            'overflow': 'hidden'
        });
    }
});

$(".footer-title__wrapper").on('click', function() {
    const section = $(this).closest('.footer-section');

    if (section.hasClass('active')) {
        section.removeClass('active');
    } else {
        section.addClass('active');
    }
});

$("#balances-general").on('click', function() {
    window.scrollTo(0, 0);
});
//header end

function copyToClipboard(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
}

function copyWithButton(copyCodeBtn, copyMsg, copyFunction) {
    copyCodeBtn.on('mousedown', function (event) {
        if (event.button === 0) {
            copyFunction();
        }
    });

    copyCodeBtn.on('mouseup', function (event) {
        if (event.button === 0) {
            noti(copyMsg, 'success');
        }
    });
}

const usdBalance = $("#usd-balance");
const btcBalance = $("#btc-balance");
const spotBalance = $("#spot-balance");
const marginBalance = $("#margin-balance");
const futuresBalance = $("#futures-balance");
const earnBalance = $("#earn-balance");

var balanceShowed = getCookie("balance_showed");
const assetsHideShow = $("#assets-hide-show");

if (balanceShowed && balanceShowed !== 'true') {
    hideBalance();
}

function hideBalance() {
    usdBalance.html('***** USD');
    btcBalance.html('≈ ***** BTC');
    spotBalance.html('$*.**');
    marginBalance.html('$*.**');
    futuresBalance.html('$*.**');
    earnBalance.html('$*.**');
    assetsHideShow.attr('src', 'src="../assets/img/show.svg"');
}

function showBalance() {
    usdBalance.html(usdBalance.attr('usd-balance') + ' USD');
    btcBalance.html('≈ ' + btcBalance.attr('btc-balance') + ' BTC');
    spotBalance.html('$0.00');
    marginBalance.html('$0.00');
    futuresBalance.html('$0.00');
    earnBalance.html('$0.00');
    assetsHideShow.attr('src', 'src="../hide/img/show.svg"');
}

function onAssetsHideShow(event) {
    event.preventDefault();

    balanceShowed = getCookie("balance_showed");

    if (balanceShowed && balanceShowed !== 'true') {
        setCookie("balance_showed", "true", 30);
        showBalance();
    } else {
        setCookie("balance_showed", "false", 30);
        hideBalance();
    }
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return "0 Bytes";
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    const index = Math.floor(Math.log(bytes) / Math.log(1024));
    const value = parseFloat((bytes / Math.pow(1024, index)).toFixed(dm));
    return `${value} ${sizes[index]}`;
}

