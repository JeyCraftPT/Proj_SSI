from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, Button, Input, Label, TabbedContent, TabPane, 
    Log, Select, Static
)
from textual import on
from datetime import datetime
import os
import binascii
import json

# --- IMPORT BACKEND MODULES ---
try:
    from src.auth import auth
    from src.crypto.lamport import LamportSigner
    from src.crypto import symmetric
    from src.crypto import hashing
    from src.auth.db import initializeDB
    initializeDB()
except ImportError as e:
    print(f"BACKEND LOAD ERROR: {e}")
    auth = None
    LamportSigner = None
    symmetric = None
    hashing = None

# --- CSS STYLING ---
CSS = """
Screen {
    align: center middle;
    background: $surface-darken-1;
}

/* LOGIN SCREEN STYLES */
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

/* TABS IN LOGIN SCREEN */
TabbedContent {
    height: auto;
}

.input-label {
    margin-top: 1;
    color: $text-disabled;
}

.action-btn {
    width: 100%;
    margin-top: 2;
}

/* MAIN DASHBOARD STYLES */
.box {
    height: 100%;
    border: solid green;
}

#audit-log {
    height: 30%;
    border-top: solid $secondary;
    background: $surface-darken-2;
    color: $text-muted;
}
"""

# --- LOGIN SCREEN ---
class LoginScreen(Screen):
    def compose(self) -> ComposeResult:
        with Container(id="login-container"):
            yield Label("CRYPTO VAULT SYSTEM", id="login-title")
            
            # SEPARATE LOGIN AND REGISTER OPTIONS USING TABS
            with TabbedContent(initial="tab-login"):
                
                # --- OPTION 1: LOGIN (EXISTING ACCOUNT) ---
                with TabPane("Login", id="tab-login"):
                    yield Label("Username", classes="input-label")
                    yield Input(placeholder="Existing username", id="login_user")
                    
                    yield Label("Password", classes="input-label")
                    yield Input(placeholder="Password", password=True, id="login_pass")
                    
                    yield Button("Sign In", variant="primary", id="btn-login", classes="action-btn")

                # --- OPTION 2: CREATE ACCOUNT ---
                with TabPane("Create Account", id="tab-register"):
                    yield Label("New Username", classes="input-label")
                    yield Input(placeholder="Choose a username", id="reg_user")
                    
                    yield Label("New Password", classes="input-label")
                    yield Input(placeholder="Choose a password", password=True, id="reg_pass")
                    
                    yield Button("Create Account", variant="success", id="btn-register", classes="action-btn")

    @on(Button.Pressed, "#btn-login")
    def login(self):
        # We grab inputs specifically from the LOGIN tab IDs
        username = self.query_one("#login_user").value
        password = self.query_one("#login_pass").value
        
        if not username or not password:
            self.notify("Please enter credentials", severity="error")
            return

        if auth:
            try:
                # 1. Calculate client challenge
                challenge_client = auth.chap_UserValChallenge(username, password)
                
                # 2. Verify with DB
                if challenge_client and auth.verifyChallengeBD(username, challenge_client):
                    self.app.user = username
                    self.app.push_screen("main")
                    self.notify(f"Welcome back, {username}!")
                else:
                    self.notify("Invalid credentials or User not found.", severity="error")
            except Exception as e:
                self.notify(f"Login Error: {str(e)}", severity="error")
        else:
            self.notify("Backend not loaded", severity="warning")

    @on(Button.Pressed, "#btn-register")
    def register(self):
        # We grab inputs specifically from the REGISTER tab IDs
        username = self.query_one("#reg_user").value
        password = self.query_one("#reg_pass").value

        if not username or not password:
            self.notify("Username and Password required", severity="error")
            return

        if auth:
            # Call the register function
            success = auth.registerUser(username, password)
            if success:
                self.notify("Account created! You can now Login.", severity="success")
                # Optional: Switch back to login tab automatically?
                # For now, we let the user click the tab themselves.
            else:
                self.notify("Registration failed. Username may already exist.", severity="error")
        else:
            self.notify("Backend not loaded", severity="warning")

# --- MAIN DASHBOARD SCREEN ---
class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with TabbedContent():
            
            # TAB 1: LAMPORT SIGNATURES
            with TabPane("Lamport Signatures"):
                with Container():
                    yield Label("Lamport Operations", classes="section-title")
                    
                    with Horizontal():
                        yield Button("Generate Key Pair", id="btn-lamport-gen", variant="warning")
                    
                    yield Label("File to Sign:")
                    yield Input(placeholder="/path/to/file.txt", id="lamport-file-input")
                    
                    yield Label("Private Key Path (Will be destroyed!):")
                    yield Input(placeholder="/path/to/private.key", id="lamport-priv-input")
                    
                    yield Button("SIGN FILE & DESTROY KEY", id="btn-lamport-sign", variant="error", classes="action-btn")
                    
                    yield Static("--- Verification ---", classes="separator")
                    yield Label("Signature File Path (JSON):")
                    yield Input(placeholder="/path/to/file.txt.sig", id="lamport-sig-input")
                    yield Label("Public Key File Path (JSON):")
                    yield Input(placeholder="/path/to/public_key_json", id="lamport-pub-input")
                    yield Label("Original File Path:")
                    yield Input(placeholder="/path/to/original.txt", id="lamport-verify-file-input")
                    yield Button("Verify Signature", id="btn-lamport-verify", variant="success", classes="action-btn")

            # TAB 2: ENCRYPTION (SYMMETRIC)
            with TabPane("Encryption (AES/ChaCha)"):
                with Container():
                    yield Label("Select Algorithm:")
                    yield Select([
                        ("AES-512-CBC", "aes512"), 
                        ("ChaCha20-Poly1305", "chacha20")
                    ], allow_blank=False, value="aes512", id="algo-select")
                    
                    yield Label("File to Encrypt:")
                    yield Input(placeholder="Select file...", id="encrypt-file-input")
                    
                    yield Button("Encrypt File & Gen Key", id="btn-encrypt", variant="primary", classes="action-btn")
                    
                    yield Label("Output Key (Save this path!):", id="key-output-label")
                    yield Input(id="key-output-display")
                    yield Label("Output IV (Hex - Save this!):")
                    yield Input(id="iv-output-display")

            # TAB 3: DECRYPTION & INTEGRITY
            with TabPane("Decryption"):
                with Container():
                    yield Label("File to Decrypt (.enc):")
                    yield Input(placeholder="Path to encrypted file...", id="decrypt-file-input")
                    
                    yield Label("Key File Path:")
                    yield Input(placeholder="Path to .pem key file...", id="decrypt-key-input")

                    yield Label("IV (Hex String):")
                    yield Input(placeholder="Paste IV here...", id="decrypt-iv-input")
                    
                    yield Button("Decrypt & Verify HMAC", id="btn-decrypt", variant="success", classes="action-btn")

        yield Log(id="audit-log", highlight=True)
        yield Footer()

    def log_audit(self, message: str, level: str = "INFO"):
        log_widget = self.query_one("#audit-log")
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_widget.write_line(f"[{timestamp}] [{level}] {message}")

    @on(Button.Pressed)
    def handle_buttons(self, event: Button.Pressed):
        btn_id = event.button.id
        user = self.app.user if self.app.user else "anon"
        
        # --- LAMPORT HANDLERS ---
        if btn_id == "btn-lamport-gen":
            try:
                priv_path, pub_json = LamportSigner.generate_keys(user_id=user)
                pub_path = priv_path.replace(".priv", ".pub")
                with open(pub_path, "w") as f:
                    f.write(pub_json)

                self.log_audit(f"Generated Keys.", "LAMPORT")
                self.log_audit(f"Private: {priv_path}", "KEY")
                self.log_audit(f"Public: {pub_path}", "KEY")
                self.query_one("#lamport-priv-input").value = priv_path
                self.notify("Keys Generated")
            except Exception as e:
                self.log_audit(f"Error: {e}", "ERROR")

        elif btn_id == "btn-lamport-sign":
            fpath = self.query_one("#lamport-file-input").value
            kpath = self.query_one("#lamport-priv-input").value
            
            if not fpath or not kpath:
                self.notify("Missing file or key path", severity="error")
                return

            try:
                self.log_audit(f"Signing {fpath}...", "LAMPORT")
                signature_json = LamportSigner.sign(fpath, kpath)
                sig_path = fpath + ".sig"
                with open(sig_path, "w") as f:
                    f.write(signature_json)

                self.log_audit(f"Signature saved to: {sig_path}", "SUCCESS")
                self.log_audit(f"Private key destroyed.", "SECURITY")
                self.notify("File Signed & Key Destroyed")
            except Exception as e:
                self.log_audit(f"Error: {e}", "ERROR")

        elif btn_id == "btn-lamport-verify":
            sig_path = self.query_one("#lamport-sig-input").value
            pub_path = self.query_one("#lamport-pub-input").value
            fpath = self.query_one("#lamport-verify-file-input").value

            if not sig_path or not pub_path or not fpath:
                self.notify("Missing verification files", severity="error")
                return

            try:
                with open(sig_path, "r") as f: sig_json = f.read()
                with open(pub_path, "r") as f: pub_json = f.read()

                is_valid = LamportSigner.verify(fpath, sig_json, pub_json)
                
                if is_valid:
                    self.log_audit("Signature Verification: VALID", "SUCCESS")
                    self.notify("Signature Valid", severity="information")
                else:
                    self.log_audit("Signature Verification: INVALID", "WARNING")
                    self.notify("Signature Invalid!", severity="error")
            except Exception as e:
                self.log_audit(f"Verify Error: {e}", "ERROR")

        # --- ENCRYPTION HANDLERS ---
        elif btn_id == "btn-encrypt":
            algo = self.query_one("#algo-select").value
            fpath = self.query_one("#encrypt-file-input").value
            
            if not fpath or not os.path.exists(fpath):
                self.notify("File not found", severity="error")
                return

            try:
                key_path = symmetric.keygen(user)
                out_path, iv = symmetric.encrypt(fpath, algo, key_path)
                iv_hex = binascii.hexlify(iv).decode()

                hmac_val = hashing.calculate_hmac(out_path, key_path)
                self.log_audit(f"HMAC-SHA512: {hmac_val[:16]}...", "INTEGRITY")

                self.query_one("#key-output-display").value = key_path
                self.query_one("#iv-output-display").value = iv_hex
                
                self.log_audit(f"Encrypted: {out_path}", "SUCCESS")
                self.notify("Encryption Complete")
            except Exception as e:
                self.log_audit(f"Enc Error: {e}", "ERROR")

        # --- DECRYPTION HANDLERS ---
        elif btn_id == "btn-decrypt":
            fpath = self.query_one("#decrypt-file-input").value
            key_path = self.query_one("#decrypt-key-input").value
            iv_hex = self.query_one("#decrypt-iv-input").value
            
            if not fpath or not key_path or not iv_hex:
                self.notify("Missing Input Fields", severity="error")
                return

            try:
                current_hmac = hashing.calculate_hmac(fpath, key_path)
                self.log_audit(f"Current File HMAC: {current_hmac[:16]}...", "INTEGRITY")

                iv = binascii.unhexlify(iv_hex)
                out_path = symmetric.decrypt(fpath, "aes512", key_path, iv)
                
                self.log_audit(f"Decrypted to: {out_path}", "SUCCESS")
                self.notify("Decryption Successful")
            except binascii.Error:
                self.notify("Invalid IV Hex String", severity="error")
            except Exception as e:
                self.log_audit(f"Dec Error: {e}", "ERROR")
                self.notify("Decryption Failed", severity="error")

# --- APP CONFIGURATION ---
class CryptoVaultApp(App):
    CSS = CSS
    SCREENS = {"login": LoginScreen, "main": MainScreen}
    BINDINGS = [("q", "quit", "Quit App"), ("d", "toggle_dark", "Toggle Dark Mode")]
    
    user = None 

    def on_mount(self) -> None:
        self.push_screen("login")

if __name__ == "__main__":
    app = CryptoVaultApp()
    app.run()