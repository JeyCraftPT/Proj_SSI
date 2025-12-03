function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    // Envia os dados para Python via Toga WebView
    if (window.pywebview) {
        window.pywebview.api.process_login(username, password);
    } else {
        alert(`Login: ${username} / ${password}`);
    }
}
