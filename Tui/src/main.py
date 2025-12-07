from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    Header, Footer, Button, Input, Label, TabbedContent, TabPane, 
    Log, Select, Static, DirectoryTree
)
from textual import on
from datetime import datetime
import os
import binascii

# --- IMPORT BACKEND MODULES ---
try:
    from src.auth import auth
    from src.crypto.lamport import LamportSigner
    from src.crypto import symmetric
    from src.crypto import hashing
    from src.auth.db import initializeDB
    initializeDB()
except ImportError:
    auth = None
    LamportSigner = None
    symmetric = None
    hashing = None

# --- CSS STYLING ---
CSS = """
Screen {
    align: center middle;
    background: $surface-darken-1;
    padding: 1 2;
}

#login-container {
    width: 60;
    height: auto;
    border: solid $accent;
    background: $surface;
    padding: 2;
}

#login-title {
    text-align: center;
    text-style: bold;
    color: $accent;
    margin-bottom: 2;
}

#audit-log {
    height: 30%;
    border-top: solid $secondary;
    background: $surface-darken-2;
    color: $text-muted;
}

FilePickerScreen {
    align: center middle;
    background: rgba(0,0,0,0.7);
}

#dialog {
    width: 80%;
    height: 80%;
    border: solid $accent;
    background: $surface;
    layout: vertical;
}

#dialog-title {
    text-align: center;
    background: $accent;
    color: $text;
    padding: 1;
    width: 100%;
}

DirectoryTree {
    height: 1fr;
    border-top: solid $secondary;
    border-bottom: solid $secondary;
}

.input-group {
    height: auto;
    margin-bottom: 1;
    align: left middle;
}

.file-input {
    width: 40%;
}

/* INPUTS BLOQUEADOS (READ-ONLY) */
Input:disabled {
    opacity: 100%;
    color: $text;
    background: $surface-darken-1;
    border: wide $secondary;
}

.btn-browse {
    width: 5%;
    min-width: 10; 
    margin-left: 1;
}

.action-btn {
    width: 25%;
    margin-top: 1;
    margin-bottom: 1;
}

.separator {
    margin-top: 1;
    margin-bottom: 1;
    color: $accent;
    text-style: bold;
}

.btn-select {
    width: 40%;
    margin-bottom: 1;
    margin-left: 0;
    margin-top: 1;
}

.split-view {
    height: auto;
    width: 100%;
}

.half-column {
    width: 1fr;       
    height: auto;
    padding: 0 1;     
    border-left: solid $secondary; 
}

.half-column:first-child {
    border-left: none; 
}

.half-column .file-input {
    width: 75%;      
}

.half-column .btn-browse {
    width: 20%;
    min-width: 5;
    margin-left: 1;
}

.half-column .input-group {
    width: 100%;
    align: left middle; /* Alinhamento importante */
}

.section-title {
    text-align: center;
    background: $secondary;
    color: $text;
    width: 100%;
    margin-bottom: 1;
}

/* --- ESTILO ESPECÍFICO PARA A ABA HMAC (Colunas) --- */
.half-column .file-input {
    width: 1fr; 
}

.half-column .btn-browse {
    width: 8;       
    min-width: 8;
    margin-left: 1;
}

.half-column .input-group {
    width: 100%;
    align: left middle; 
}
/* -------------------------------------------------- */
"""

# --- FILE PICKER SCREEN (MODAL) ---
class FilePickerScreen(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        with Container(id="dialog"):
            yield Label("Selecione um ficheiro", id="dialog-title")
            yield DirectoryTree("./")
            yield Button("Cancelar", variant="error", id="btn-cancel")

    @on(DirectoryTree.FileSelected)
    def on_file_selected(self, event: DirectoryTree.FileSelected):
        self.dismiss(str(event.path))

    @on(Button.Pressed, "#btn-cancel")
    def cancel(self):
        self.dismiss(None)


# --- LOGIN SCREEN ---
class LoginScreen(Screen):
    def compose(self) -> ComposeResult:
        with Container(id="login-container"):
            yield Label("CRYPTO VAULT SYSTEM", id="login-title")
            with TabbedContent(initial="tab-login"):
                with TabPane("Login", id="tab-login"):
                    yield Label("Username")
                    yield Input(placeholder="Username", id="login_user")
                    yield Label("Password")
                    yield Input(placeholder="Password", password=True, id="login_pass")
                    yield Button("Sign In", variant="primary", id="btn-login", classes="action-btn")

                with TabPane("Create Account", id="tab-register"):
                    yield Label("New Username")
                    yield Input(placeholder="Choose a username", id="reg_user")
                    yield Label("New Password")
                    yield Input(placeholder="Choose a password", password=True, id="reg_pass")
                    yield Button("Create Account", variant="success", id="btn-register", classes="action-btn")

    @on(Button.Pressed, "#btn-login")
    def login(self):
        username = self.query_one("#login_user").value
        password = self.query_one("#login_pass").value
        
        if auth:
            try:
                challenge_client = auth.chap_UserValChallenge(username, password)
                if challenge_client and auth.verifyChallengeBD(username, challenge_client):
                    self.app.user = username
                    self.app.push_screen("main")
                    self.notify(f"Welcome back, {username}!")
                else:
                    self.notify("Invalid credentials.", severity="error")
            except Exception as e:
                self.notify(f"Login Error: {e}", severity="error")
        else:
            self.app.user = username
            self.app.push_screen("main")

    @on(Button.Pressed, "#btn-register")
    def register(self):
        username = self.query_one("#reg_user").value
        password = self.query_one("#reg_pass").value
        if auth:
            if auth.registerUser(username, password):
                self.notify("Account created!", severity="success")
            else:
                self.notify("Registration failed.", severity="error")

# --- MAIN DASHBOARD SCREEN ---
class MainScreen(Screen):
    
    BROWSE_MAP = {
        # Lamport
        "browse-lamport-file": "lamport-file-input",
        "browse-lamport-priv": "lamport-priv-input",
        "browse-lamport-sig": "lamport-sig-input",
        "browse-lamport-pub": "lamport-pub-input",
        "browse-lamport-verify": "lamport-verify-file-input",
        
        # Encryption
        "browse-enc-file": "encrypt-file-input",
        
        # Decryption
        "browse-dec-file": "decrypt-file-input",
        "browse-dec-key": "decrypt-key-input",

        # HMAC
        "browse-hmac-calc-file": "hmac-calc-file-input",
        "browse-hmac-calc-key": "hmac-calc-key-input",
        "browse-hmac-verify-file": "hmac-verify-file-input",
        "browse-hmac-verify-key": "hmac-verify-key-input",
    }

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with TabbedContent():
            
            # --- TAB 1: LAMPORT SIGNATURES ---
            with TabPane("Lamport Signatures"):
                with Container():
                    yield Label("1. Operações de Chaves & Assinatura", classes="separator")
                    with Horizontal():
                        yield Button("Generate Key Pair", id="btn-lamport-gen", variant="warning")
                    
                    yield Label("File to Sign:")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="lamport-file-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-lamport-file", classes="btn-browse")
                    
                    yield Label("Private Key Path (Will be destroyed):")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="lamport-priv-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-lamport-priv", classes="btn-browse")
                    
                    yield Button("SIGN FILE & DESTROY KEY", id="btn-lamport-sign", variant="error", classes="action-btn")
                    
                    yield Static("--- Verification ---", classes="separator")
                    yield Label("Signature File (.sig):")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="lamport-sig-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-lamport-sig", classes="btn-browse")

                    yield Label("Public Key File (.pub):")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="lamport-pub-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-lamport-pub", classes="btn-browse")

                    yield Label("Original File:")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="lamport-verify-file-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-lamport-verify", classes="btn-browse")

                    yield Button("Verify Signature", id="btn-lamport-verify", variant="success", classes="action-btn")

            # --- TAB 2: ENCRYPTION ---
            with TabPane("Encryption"):
                with Container():
                    yield Label("Select Algorithm:")
                    yield Select([
                        ("AES-256-CBC", "aes256"), 
                        ("ChaCha20-Poly1305", "chacha20")
                    ], allow_blank=False, value="aes256", id="algo-select", classes="btn-select")
                    
                    yield Label("File to Encrypt:")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="encrypt-file-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-enc-file", classes="btn-browse")
                    
                    yield Button("Encrypt & Gen Key", id="btn-encrypt", variant="primary", classes="action-btn")
                    
                    yield Label("Output Key File:", id="key-output-label")
                    yield Input(id="key-output-display", disabled=True, classes="file-input") 
                    
                    yield Label("Output Encrypted File:")
                    yield Input(id="enc-output-display", disabled=True, classes="file-input")

            # --- TAB 3: DECRYPTION ---
            with TabPane("Decryption"):
                with Container():
                    yield Label("File to Decrypt (.enc):")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="decrypt-file-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-dec-file", classes="btn-browse")
                    
                    yield Label("Key File Path (.pem):")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="decrypt-key-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-dec-key", classes="btn-browse")
                    
                    yield Button("Decrypt", id="btn-decrypt", variant="success", classes="action-btn")

            # --- TAB 4: HMAC INTEGRITY ---
            with TabPane("HMAC Integrity"):
                with Container():
                    yield Label("Select Hash Algorithm:")
                    yield Select([
                        ("SHA-512", "SHA512"), 
                        ("SHA-256", "SHA256")
                    ], allow_blank=False, value="SHA512", id="hmac-algo-select", classes="btn-select")

                    # --- DIVISÃO LADO A LADO ---
                    with Horizontal(classes="split-view"):
                        
                        # === COLUNA ESQUERDA: CALCULATE ===
                        with Vertical(classes="half-column"):
                            yield Label("1. Calculate HMAC", classes="section-title")
                            
                            yield Label("File to Hash:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="File...", id="hmac-calc-file-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-calc-file", classes="btn-browse")

                            yield Label("Key File:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="Key...", id="hmac-calc-key-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-calc-key", classes="btn-browse")

                            yield Button("Calculate & Save HMAC", id="btn-hmac-calc", variant="warning", classes="action-btn")

                            # --- MUDANÇA: Label e Input para o Caminho do Ficheiro ---
                            yield Label("Output HMAC File (.hmac):")
                            yield Input(id="hmac-output-display", classes="file-input", disabled=True)


                        # === COLUNA DIREITA: VERIFY ===
                        with Vertical(classes="half-column"):
                            yield Label("2. Verify HMAC", classes="section-title")

                            yield Label("File to Verify:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="File...", id="hmac-verify-file-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-verify-file", classes="btn-browse")

                            yield Label("Key File:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="Key...", id="hmac-verify-key-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-verify-key", classes="btn-browse")

                            # --- MUDANÇA: Agora seleciona o ficheiro .hmac ---
                            yield Label("HMAC File (.hmac):")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="Select .hmac file...", id="hmac-verify-filepath-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-verify-filepath", classes="btn-browse")

                            yield Button("Verify HMAC", id="btn-hmac-verify", variant="success", classes="action-btn")


        yield Log(id="audit-log", highlight=True)
        yield Footer()

    def log_audit(self, message: str, level: str = "INFO"):
        log_widget = self.query_one("#audit-log")
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_widget.write_line(f"[{timestamp}] [{level}] {message}")

    @on(Button.Pressed)
    def handle_browse(self, event: Button.Pressed):
        btn_id = event.button.id
        if btn_id in self.BROWSE_MAP:
            target_input_id = self.BROWSE_MAP[btn_id]
            def set_path(path: str | None):
                if path:
                    self.query_one(f"#{target_input_id}").value = path
                    self.notify(f"Selecionado: {path}")
            self.app.push_screen(FilePickerScreen(), set_path)
        else:
            self.handle_system_actions(btn_id)

    def handle_system_actions(self, btn_id):
        user = self.app.user if self.app.user else "anon"
        if btn_id == "btn-cancel": return

        # --- LAMPORT ---
        if btn_id == "btn-lamport-gen":
            if LamportSigner:
                try:
                    priv_path, pub_json = LamportSigner.generate_keys(user_id=user)
                    pub_path = priv_path.replace(".priv", ".pub")
                    with open(pub_path, "w") as f: f.write(pub_json)
                    self.log_audit("Keys Generated", "LAMPORT")
                    self.query_one("#lamport-priv-input").value = priv_path
                    self.notify("Keys Generated")
                except Exception as e: self.log_audit(f"Error: {e}", "ERROR")

        elif btn_id == "btn-lamport-sign":
            fpath = self.query_one("#lamport-file-input").value
            kpath = self.query_one("#lamport-priv-input").value
            if LamportSigner and fpath and kpath:
                try:
                    sig_json = LamportSigner.sign(fpath, kpath)
                    with open(fpath + ".sig", "w") as f: f.write(sig_json)
                    self.log_audit(f"Signed: {fpath}", "SUCCESS")
                    
                    try:
                        os.remove(kpath)
                        self.log_audit(f"Private Key Destroyed: {kpath}", "SECURITY")
                        self.query_one("#lamport-priv-input").value = "" 
                    except OSError as e:
                        self.log_audit(f"Failed to destroy key: {e}", "WARNING")

                    self.notify("File Signed & Key Destroyed")
                except Exception as e: self.log_audit(f"Sign Error: {e}", "ERROR")

        elif btn_id == "btn-lamport-verify":
            sig_path = self.query_one("#lamport-sig-input").value
            pub_path = self.query_one("#lamport-pub-input").value
            fpath = self.query_one("#lamport-verify-file-input").value
            if LamportSigner and sig_path and pub_path and fpath:
                try:
                    with open(sig_path, "r") as f: sig = f.read()
                    with open(pub_path, "r") as f: pub = f.read()
                    if LamportSigner.verify(fpath, sig, pub):
                        self.log_audit("Signature VALID", "SUCCESS")
                        self.notify("Valid Signature")
                    else:
                        self.log_audit("Signature INVALID", "WARNING")
                        self.notify("Invalid Signature", severity="error")
                except Exception as e: self.log_audit(f"Verify Error: {e}", "ERROR")

        # --- ENCRYPTION ---
        elif btn_id == "btn-encrypt":
            fpath = self.query_one("#encrypt-file-input").value
            algo = self.query_one("#algo-select").value
            if symmetric and fpath:
                try:
                    key_path = symmetric.keygen(user)
                    out_path, iv = symmetric.encrypt(fpath, algo, key_path)
                    
                    if hashing:
                        hmac_val = hashing.calculate_hmac(out_path, key_path)
                        self.log_audit(f"Auto-HMAC (SHA512): {hmac_val[:16]}...", "INTEGRITY")
                    
                    self.query_one("#key-output-display").value = key_path
                    self.query_one("#enc-output-display").value = out_path 
                    
                    self.log_audit(f"Encrypted ({algo}): {out_path}", "SUCCESS")
                    self.notify("Encryption Done")
                except Exception as e: self.log_audit(f"Enc Error: {e}", "ERROR")

        # --- DECRYPTION ---
        elif btn_id == "btn-decrypt":
            fpath = self.query_one("#decrypt-file-input").value
            kpath = self.query_one("#decrypt-key-input").value
            if symmetric and fpath and kpath:
                try:
                    out = symmetric.decrypt(fpath, "aes256", kpath)
                    self.log_audit(f"Decrypted to {out}", "SUCCESS")
                    self.notify("Decryption Done")
                except Exception as e: 
                    self.log_audit(f"Dec Error: {e}", "ERROR")
                    self.notify("Failed to Decrypt", severity="error")

        # --- HMAC HANDLERS ---
        elif btn_id == "btn-hmac-calc":
            fpath = self.query_one("#hmac-calc-file-input").value
            kpath = self.query_one("#hmac-calc-key-input").value
            algo_hash = self.query_one("#hmac-algo-select").value
            
            if hashing and fpath and kpath:
                try:
                    if algo_hash == "SHA256":
                        self.log_audit("Backend currently defaults to SHA512", "WARNING")
                    
                    # 1. Calcula o Hash
                    digest = hashing.calculate_hmac(fpath, kpath)
                    
                    # 2. Cria o caminho do ficheiro de saída
                    hmac_out_path = fpath + ".hmac"
                    
                    # 3. Guarda o resultado no ficheiro
                    with open(hmac_out_path, "w") as f:
                        f.write(digest)
                        
                    # 4. Atualiza a UI
                    self.query_one("#hmac-output-display").value = hmac_out_path
                    self.log_audit(f"HMAC Saved: {hmac_out_path}", "SUCCESS")
                    self.notify("HMAC Saved to file")
                except Exception as e:
                    self.log_audit(f"HMAC Error: {e}", "ERROR")

        elif btn_id == "btn-hmac-verify":
            fpath = self.query_one("#hmac-verify-file-input").value
            kpath = self.query_one("#hmac-verify-key-input").value
            # Agora lemos o caminho do ficheiro .hmac
            hmac_file_path = self.query_one("#hmac-verify-filepath-input").value
            
            if hashing and fpath and kpath and hmac_file_path:
                try:
                    # 1. Lê o hash esperado do ficheiro
                    with open(hmac_file_path, "r") as f:
                        expected_hex = f.read().strip()
                    
                    # 2. Verifica
                    is_valid = hashing.verify_hmac(fpath, kpath, expected_hex)
                    if is_valid:
                        self.log_audit("HMAC Verification: MATCH", "SUCCESS")
                        self.notify("Integrity Verified!", severity="success")
                    else:
                        self.log_audit("HMAC Verification: MISMATCH", "WARNING")
                        self.notify("Integrity Check FAILED!", severity="error")
                except Exception as e:
                    self.log_audit(f"HMAC Verify Error: {e}", "ERROR")

# --- APP CONFIGURATION ---
class CryptoVaultApp(App):
    CSS = CSS
    SCREENS = {"login": LoginScreen, "main": MainScreen}
    BINDINGS = [("q", "quit", "Quit"), ("d", "toggle_dark", "Dark Mode")]
    user = None 

    def on_mount(self) -> None:
        self.push_screen("login")

if __name__ == "__main__":
    app = CryptoVaultApp()
    app.run()