'''
"""
My first application
"""
import faker
import httpx
import toga
from toga.style.pack import COLUMN, ROW

def greeting(name):
   if name:
       return f"Hello, {name}"
   else:
       return "Hello, stranger"
   
class rightHereWaiting(toga.App):
    def startup(self):
        """Construct and show the Toga application.

        Usually, you would add your application to a main content box.
        We then create a main window (with a name matching the app), and
        show the main window.
        """
        main_box = toga.Box(direction=COLUMN)

        name_label = toga.Label(
            "Your name: ",
            margin=(0,5),
        )
        
        self.name_input = toga.TextInput(flex=1)
        name_box = toga.Box(direction=ROW ,margin=5)
        name_box.add(name_label)
        name_box.add(self.name_input)

        button = toga.Button(
            "Say Hello!",
            on_press=self.say_hello,
            margin=5,
        )

        main_box.add(name_box)
        main_box.add(button)


        
        self.main_window = toga.MainWindow(title=self.formal_name)
    
        self.main_window.content = main_box
        self.main_window.show()

    
   
    async def say_hello(self, widget):
        fake = faker.Faker()
        async with httpx.AsyncClient() as client:
            response = await client.get("https://jsonplaceholder.typicode.com/posts/42")

        payload = response.json()

        await self.main_window.dialog(
            toga.InfoDialog(
                greeting(self.name_input.value),
                f"A message from {fake.name()}: {payload['body']}",
            )
        )


def main():
    return rightHereWaiting()
'''
import toga
from rightHereWaiting.frontend.frontend import frontend
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









