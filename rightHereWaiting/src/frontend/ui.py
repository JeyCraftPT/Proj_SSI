from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    Header, Footer, Button, Input, Label, TabbedContent, TabPane, 
    Log, Select, Static, DirectoryTree
)
from textual import on
from datetime import datetime
from pathlib import Path

# --- IMPORT BACKEND MODULES ---
try:
    from src.backend.auth.auth import chap_UserValChallenge, verifyChallengeBD, registerUser
    from src.backend.crypto import lamport,symmetric,hashing
    from src.backend.auth.db import initializeDB
    initializeDB()
except ImportError:
    lamport = None
    symmetric = None
    hashing = None

# --- CSS STYLING ---
CSS = (Path(__file__).parent / "styles.txt").read_text()


# --- FILE PICKER SCREEN ---
class FilePickerScreen(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        start_path = Path(__file__).resolve().parent.parent.parent
        with Container(id="dialog"):
            yield Label("Selecione um ficheiro", id="dialog-title")
            yield DirectoryTree(str(start_path))
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
            yield Label("RightHereWaiting", id="login-title")
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
    
        try:
            challenge_client = chap_UserValChallenge(username, password)
            if challenge_client and verifyChallengeBD(username, challenge_client):
                self.app.user = username
                self.app.push_screen("main")
                self.notify(f"Welcome back, {username}!")

                self.query_one("#login_user").value= ""
                self.query_one("#login_pass").value = ""
            else:
                self.notify("Invalid credentials.", severity="error")
                self.query_one("#login_pass").value = ""
        except Exception as e:
            self.notify(f"Login Error: {e}", severity="error")

    @on(Button.Pressed, "#btn-register")
    def register(self):
        username = self.query_one("#reg_user").value
        password = self.query_one("#reg_pass").value

        if registerUser(username, password):
            self.notify("Account created!", severity="success")
            self.query_one("#reg_user").value = ""
            self.query_one("#reg_pass").value = ""
        else:
            self.notify("Registration failed.", severity="error")
            self.query_one("#reg_user").value = ""




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
        "browse-hmac-verify-key": "hmac-verify-key-input",
        "browse-hmac-verify-filepath": "hmac-verify-filepath-input",
        "browse-hmac-verify-file": "hmac-verify-file-input",

    }


    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with TabbedContent():
            
            # --- LAMPORT SIGNATURES ---
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


            # --- ENCRYPTION ---
            with TabPane("Encryption"):
                with Container():
                    yield Label("Select Algorithm:")
                    yield Select([
                        ("AES-256-CBC", "aes-256-cbc"), 
                        ("ChaCha20", "chacha20")
                    ], allow_blank=False, value="aes-256-cbc", id="algo-select", classes="btn-select")
                    
                    yield Label("File to Encrypt:")
                    with Horizontal(classes="input-group"):
                        yield Input(placeholder="Use button ->", id="encrypt-file-input", classes="file-input", disabled=True)
                        yield Button("📂", id="browse-enc-file", classes="btn-browse")
                    
                    yield Button("Encrypt & Gen Key", id="btn-encrypt", variant="primary", classes="action-btn")
                    
                    yield Label("Output Key File:", id="key-output-label")
                    yield Input(id="key-output-display", disabled=True, classes="file-input") 
                    
                    yield Label("Output Encrypted File:")
                    yield Input(id="enc-output-display", disabled=True, classes="file-input")


            # --- DECRYPTION ---
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


            # --- HMAC INTEGRITY ---
            with TabPane("HMAC Integrity"):
                with Container():
                    yield Label("Select Hash Algorithm:")
                    yield Select([
                        ("SHA-512", "SHA-512"), 
                        ("SHA-256", "SHA-256")
                    ], allow_blank=False, value="SHA-512", id="hmac-algo-select", classes="btn-select")

                    with Horizontal(classes="split-view"):
                        
                        with Vertical(classes="half-column"):
                            yield Label("Calculate HMAC", classes="section-title")
                            
                            yield Label("File to Hash:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="File...", id="hmac-calc-file-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-calc-file", classes="btn-browse")

                            yield Label("Key File:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="Key...", id="hmac-calc-key-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-calc-key", classes="btn-browse")

                            yield Button("Calculate & Save HMAC", id="btn-hmac-calc", variant="warning", classes="action-btn")

                            yield Label("Output HMAC File (.hmac):")
                            yield Input(id="hmac-output-display", classes="file-input", disabled=True)


                        # --- VERIFY ---
                        with Vertical(classes="half-column"):
                            yield Label("Verify HMAC", classes="section-title")

                            yield Label("File to Verify:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="File...", id="hmac-verify-file-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-verify-file", classes="btn-browse")

                            yield Label("Key File:")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="Key...", id="hmac-verify-key-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-verify-key", classes="btn-browse")

                            yield Label("HMAC File (.hmac):")
                            with Horizontal(classes="input-group"):
                                yield Input(placeholder="Select .hmac file...", id="hmac-verify-filepath-input", classes="file-input", disabled=True)
                                yield Button("📂", id="browse-hmac-verify-filepath", classes="btn-browse")

                            yield Button("Verify HMAC", id="btn-hmac-verify", variant="success", classes="action-btn")


        yield Log(id="audit-log", highlight=True)
        yield Footer()



# EVENTS

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
            if lamport:
                try:
                    priv_path, pub_path = lamport.generate_keys(user_id=user)
                    self.log_audit("Keys Generated", "LAMPORT")
                    self.query_one("#lamport-priv-input").value = priv_path
                    self.query_one("#lamport-pub-input").value = pub_path
                    self.notify("Keys Generated")
                except Exception as e: self.log_audit(f"Error: {e}", "ERROR")

        elif btn_id == "btn-lamport-sign":
            fpath = self.query_one("#lamport-file-input").value
            kpath = self.query_one("#lamport-priv-input").value
            if lamport and fpath and kpath:
                try:
                    sig_path_sign = lamport.sign(fpath, kpath)
                    self.log_audit(f"Signed: {fpath}", "SUCCESS")
                    self.notify("File Signed & Key Destroyed")
                    self.query_one("#lamport-priv-input").value = ""
                    self.query_one("#lamport-file-input").value = ""
                except Exception as e: self.log_audit(f"Sign Error: {e}", "ERROR")

        elif btn_id == "btn-lamport-verify":
            sig_path = self.query_one("#lamport-sig-input").value
            pub_path = self.query_one("#lamport-pub-input").value
            fpath = self.query_one("#lamport-verify-file-input").value
            if lamport and sig_path and pub_path and fpath:
                try:
                    if lamport.verify(fpath, sig_path, pub_path):
                        self.log_audit("Signature VALID", "SUCCESS")
                        self.notify("Valid Signature")
                    else:
                        self.log_audit("Signature INVALID", "WARNING")
                        self.notify("Invalid Signature", severity="error")
                    self.query_one("#lamport-sig-input").value = ""
                    self.query_one("#lamport-pub-input").value = ""
                    self.query_one("#lamport-verify-file-input").value = ""
                except Exception as e: self.log_audit(f"Verify Error: {e}", "ERROR")

        # --- ENCRYPTION ---
        elif btn_id == "btn-encrypt":
            fpath = self.query_one("#encrypt-file-input").value
            algo = self.query_one("#algo-select").value
            if symmetric and fpath:
                try:
                    username = self.app.user
                    key_path = symmetric.keygen(username=username)
                    out_path = symmetric.encrypt(fpath, algo, key_path)

                    self.query_one("#encrypt-file-input").value = ""
                    
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
                    out = symmetric.decrypt(fpath,kpath)
                    self.query_one("#decrypt-file-input").value = ""
                    self.query_one("#decrypt-key-input").value = ""
                    self.log_audit(f"Decrypted to {out}", "SUCCESS")
                    self.notify("Decryption Done")
                except Exception as e: 
                    self.log_audit(f"Dec Error: {e}", "ERROR")
                    self.notify("Failed to Decrypt", severity="error")
                    self.query_one("#decrypt-key-input").value = ""

        # --- HMAC ---
        elif btn_id == "btn-hmac-calc":
            fpath = self.query_one("#hmac-calc-file-input").value
            kpath = self.query_one("#hmac-calc-key-input").value
            algo_hash = self.query_one("#hmac-algo-select").value
            
            if hashing and fpath and kpath:
                try:
                    
                    self.log_audit("Backend currently defaults to SHA512", "WARNING")

                    hmac_out_path = hashing.calculate_hmac(fpath, kpath, algo_hash)

                    self.query_one("#hmac-output-display").value = hmac_out_path
                    self.log_audit(f"HMAC Saved: {hmac_out_path}", "SUCCESS")
                    self.query_one("#hmac-calc-file-input").value = ""
                    self.query_one("#hmac-calc-key-input").value = ""
                    self.notify("HMAC Saved to file")
                except Exception as e:
                    self.log_audit(f"HMAC Error: {e}", "ERROR")

        elif btn_id == "btn-hmac-verify":
            fpath = self.query_one("#hmac-verify-file-input").value
            kpath = self.query_one("#hmac-verify-key-input").value
            hmac_file_path = self.query_one("#hmac-verify-filepath-input").value
            
            if hashing and fpath and kpath and hmac_file_path:
                try:
                    is_valid = hashing.verify_hmac(fpath, kpath, hmac_file_path)
                    if is_valid:
                        self.log_audit("HMAC Verification: MATCH", "SUCCESS")
                        self.notify("Integrity Verified!", severity="success")
                    else:
                        self.log_audit("HMAC Verification: MISMATCH", "WARNING")
                        self.notify("Integrity Check FAILED!", severity="error")

                    self.query_one("#hmac-verify-file-input").value = ""
                    self.query_one("#hmac-verify-key-input").value = ""
                    self.query_one("#hmac-verify-filepath-input").value = ""
                except Exception as e:
                    self.log_audit(f"HMAC Verify Error: {e}", "ERROR")



# --- MAIN APP ---
class RightHereWaitingApp(App):
    CSS = CSS
    SCREENS = {"login": LoginScreen, "main": MainScreen}
    BINDINGS = [("q", "quit", "Quit"), ("d", "toggle_dark", "Dark Mode")]
    user = None

    def on_mount(self) -> None:
        self.push_screen("login")
