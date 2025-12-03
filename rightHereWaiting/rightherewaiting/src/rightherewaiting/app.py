import toga
from rightherewaiting.frontend.frontend import frontend
from toga.style import Pack
import gi
import os

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk

class rightThereWaiting(toga.App):
    def startup(self):
        def execute_callback(action_name):
            return f"Você selecionou: {action_name} (frontend)"

        css_path = os.path.join(os.path.dirname(__file__), 'resources/gtk.css')
        if os.path.exists(css_path):
            css_provider = Gtk.CssProvider()
            css_provider.load_from_path(css_path)
            Gtk.StyleContext.add_provider_for_screen(
                Gdk.Screen.get_default(),
                css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        else:
            print(f"[Aviso] Ficheiro CSS não encontrado: {css_path}")

        self.main_window = toga.MainWindow(title="RightThereWaiting")
        self.main_window.size = (1200, 800)
        self.main_window.position = (100, 50)

        main_box = frontend(self.main_window, execute_callback)
        self.main_window.content = main_box
        self.main_window.show()

def main():
    return rightThereWaiting()

