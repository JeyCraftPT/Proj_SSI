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

.input-group {
    margin-bottom: 1;
}

.action-btn {
    width: 100%;
    margin-top: 1;
}

Label {
    margin-top: 1;
    margin-bottom: 0;
    color: $text-disabled;
}
"""

# --- LOGIN SCREEN ---
class LoginScreen(Screen):
    def compose(self) -> ComposeResult:
        with Container(id="login-container"):
            yield Label("CRYPTO VAULT SYSTEM", id="login-title")
            yield Label("Username")
            yield Input(placeholder="Enter username", id="username")
            yield Label("Password")
            # Note: We use the standard Input widget with password=True
            yield Input(placeholder="Enter password", password=True, id="password")
            
            with Horizontal(classes="input-group"):
                yield Button("Login", variant="primary", id="btn-login", classes="action-btn")
                yield Button("Register", variant="default", id="btn-register", classes="action-btn")

    @on(Button.Pressed, "#btn-login")
    def login(self):
        # TODO: Integrate with src.auth.login
        username = self.query_one("#username").value
        if username:
            self.app.user = username
            self.app.push_screen("main")
        else:
            self.notify("Please enter a username", severity="error")

    @on(Button.Pressed, "#btn-register")
    def register(self):
        # TODO: Integrate with src.auth.register
        self.notify("User registered (Simulation)", severity="information")

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
                    yield Input(placeholder="Signature File Path", id="lamport-sig-input")
                    yield Input(placeholder="Public Key Path", id="lamport-pub-input")
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
                    
                    yield Label("Output Key (Save this!):", id="key-output-label")
                    yield Input(readonly=True, id="key-output-display")

            # TAB 3: DECRYPTION & INTEGRITY
            with TabPane("Decryption"):
                with Container():
                    yield Label("File to Decrypt:")
                    yield Input(placeholder="Path to encrypted file...", id="decrypt-file-input")
                    
                    yield Label("Decryption Key (Hex/B64):")
                    yield Input(placeholder="Paste key here...", id="decrypt-key-input")
                    
                    yield Button("Decrypt & Verify HMAC", id="btn-decrypt", variant="success", classes="action-btn")

        # LOGGING AREA
        yield Log(id="audit-log", highlight=True)
        yield Footer()

    # --- EVENT HANDLERS (The Logic Bridge) ---

    def log_audit(self, message: str, level: str = "INFO"):
        """Helper to write to the bottom log window"""
        log_widget = self.query_one("#audit-log")
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_widget.write_line(f"[{timestamp}] [{level}] {message}")

    @on(Button.Pressed)
    def handle_buttons(self, event: Button.Pressed):
        btn_id = event.button.id
        
        # --- LAMPORT HANDLERS ---
        if btn_id == "btn-lamport-gen":
            # TODO: Call crypto.lamport.generate_keys()
            self.log_audit("Generating 2x 256 random number sets...", "LAMPORT")
            self.log_audit("Keys saved to ./data/keys/", "SUCCESS")
            self.notify("Keys Generated")

        elif btn_id == "btn-lamport-sign":
            fpath = self.query_one("#lamport-file-input").value
            kpath = self.query_one("#lamport-priv-input").value
            
            if not fpath or not kpath:
                self.notify("Missing file or key path", severity="error")
                return

            # TODO: Call crypto.lamport.sign()
            self.log_audit(f"Signing {fpath}...", "LAMPORT")
            self.log_audit("Calculating Hash...", "PROCESSING")
            self.log_audit(f"DELETING PRIVATE KEY at {kpath} (Secure Overwrite)", "WARNING")
            self.log_audit("Signature file created.", "SUCCESS")

        elif btn_id == "btn-lamport-verify":
            # TODO: Call crypto.lamport.verify()
            self.log_audit("Verifying signature against public key...", "LAMPORT")
            self.log_audit("Signature VALID.", "SUCCESS")
            self.notify("Signature Valid")

        # --- ENCRYPTION HANDLERS ---
        elif btn_id == "btn-encrypt":
            algo = self.query_one("#algo-select").value
            fpath = self.query_one("#encrypt-file-input").value
            
            # TODO: Call crypto.symmetric.encrypt()
            # This simulates generating a random key
            dummy_key = os.urandom(32).hex()
            
            self.log_audit(f"Encrypting {fpath} using {algo}...", "CIPHER")
            self.log_audit("Generating IV and calculating HMAC-SHA512...", "INTEGRITY")
            
            # Show the key to the user
            key_display = self.query_one("#key-output-display")
            key_display.value = dummy_key
            self.log_audit("Encryption complete.", "SUCCESS")

        # --- DECRYPTION HANDLERS ---
        elif btn_id == "btn-decrypt":
            key = self.query_one("#decrypt-key-input").value
            
            if len(key) < 10:
                self.notify("Invalid Key Format", severity="error")
                return

            # TODO: Call crypto.symmetric.decrypt()
            self.log_audit("Verifying HMAC-SHA512...", "INTEGRITY")
            self.log_audit("HMAC Verified. Decrypting content...", "CIPHER")
            self.log_audit("File restored successfully.", "SUCCESS")

# --- APP CONFIGURATION ---
class CryptoVaultApp(App):
    CSS = CSS
    SCREENS = {"login": LoginScreen, "main": MainScreen}
    BINDINGS = [("q", "quit", "Quit App"), ("d", "toggle_dark", "Toggle Dark Mode")]
    
    user = None # Stores current logged in user

    def on_mount(self) -> None:
        self.push_screen("login")

if __name__ == "__main__":
    app = CryptoVaultApp()
    app.run()