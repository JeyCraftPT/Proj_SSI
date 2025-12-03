import toga
from toga.style import Pack

# 🎨 Dark Theme Premium
PRIMARY_COLOR   = "#4A90E2"
ACCENT_COLOR    = "#6B9CFF"
BG_DARK         = "#1A1A1A"
BG_CARD         = "#232323"
TEXT_LIGHT      = "#E6E6E6"
TEXT_MUTED      = "#A0A0A0"
HEADER_BG       = "#202020"
NAV_BG          = "#2A2A2A"
BUTTON_BG       = "#2F2F2F"
BUTTON_HOVER    = "#3A3A3A"
TEXT_DARK       = "#000000"


FONT_SIZE_TITLE = 26
FONT_SIZE_TEXT  = 15


# ------------------------------
# COMPONENTES
# ------------------------------

def nav_button(label, callback):
    return toga.Button(
        label,
        on_press=callback,
        style=Pack(
            padding=6,
            padding_left=14,
            padding_right=14,
            background_color=NAV_BG,
            color=TEXT_LIGHT,
            font_size=13,
            margin_right=8,
        )
    )


def action_button(label, callback):
    return toga.Button(
        label,
        on_press=callback,
        style=Pack(
            padding=8,
            background_color=NAV_BG,
            margin=0,
            color=TEXT_LIGHT,
            width=150,
            font_size=13,
            margin_top=10,
        )
    )


def content_card():
    return toga.Box(
        style=Pack(
            direction="column",
            margin=20,
            padding=25,
            flex=1,
            background_color=BG_DARK,
        )
    )


# ------------------------------
# PÁGINAS
# ------------------------------

# Página Gerar Chave
def page_gerar_chave(execute_callback=None):
    card = content_card()

    title = toga.Label(
        "Gerar Chave Lamport",
        style=Pack(font_size=FONT_SIZE_TITLE, color=PRIMARY_COLOR, margin_bottom=20)
    )

    result = toga.Label(
        "Aguardando comando...",
        style=Pack(font_size=FONT_SIZE_TEXT, color=TEXT_MUTED, margin_top=15)
    )

    def gerar(w):
        result.text = execute_callback("Gerar chave Lamport") if execute_callback else "Simulação"

    card.add(title)
    card.add(action_button("Gerar Chave", gerar))
    card.add(result)
    return card


# Página Cifrar/Decifrar
def page_cifrar_decifrar(execute_callback=None):
    card = content_card()

    title = toga.Label(
        "Cifrar / Decifrar Ficheiros",
        style=Pack(font_size=FONT_SIZE_TITLE, color=PRIMARY_COLOR, margin_bottom=20)
    )

    selection = toga.Selection(
        items=["Cifrar ficheiro (AES-512-CBC)", "Decifrar ficheiro (AES-512-CBC)"],
        style=Pack(width=350, padding=8, margin_bottom=15)
    )

    result = toga.Label(
        "Aguardando comando...",
        style=Pack(font_size=FONT_SIZE_TEXT, color=TEXT_MUTED, margin_top=15)
    )

    def do(w):
        escolha = selection.value
        result.text = execute_callback(escolha) if execute_callback else f"Ação: {escolha}"

    card.add(title)
    card.add(selection)
    card.add(action_button("Executar", do))
    card.add(result)
    return card


# Página HMAC
def page_hmac(execute_callback=None):
    card = content_card()

    title = toga.Label(
        "HMAC e Assinaturas",
        style=Pack(font_size=FONT_SIZE_TITLE, color=PRIMARY_COLOR, margin_bottom=20)
    )

    selection = toga.Selection(
        items=["Gerar HMAC-SHA512", "Verificar HMAC-SHA512", "Verificar assinatura Lamport"],
        style=Pack(width=350, padding=8, margin_bottom=15)
    )

    result = toga.Label(
        "Aguardando comando...",
        style=Pack(font_size=FONT_SIZE_TEXT, color=TEXT_MUTED, margin_top=15)
    )

    def do(w):
        escolha = selection.value
        result.text = execute_callback(escolha) if execute_callback else f"Ação: {escolha}"

    card.add(title)
    card.add(selection)
    card.add(action_button("Executar", do))
    card.add(result)
    return card


# ------------------------------
# FRONTEND PRINCIPAL
# ------------------------------

def frontend(main_window, execute_callback=None):
    main_box = toga.Box(
        style=Pack(direction="column", flex=1, background_color=BG_DARK)
    )

    # Header / Barra de navegação
    header = toga.Box(
        style=Pack(
            direction="row",
            padding=10,
            flex=0,
            align_items="center",
        )
    )

    nav = toga.Box(
        style=Pack(
            direction="row",
            flex=1
        )
    )

    # Função para trocar páginas
    def show(page):
        content_area.clear()
        content_area.add(page(execute_callback))

    # Botões de navegação
    nav.add(nav_button("Gerar Chave", lambda w: show(page_gerar_chave)))
    nav.add(nav_button("Cifrar / Decifrar", lambda w: show(page_cifrar_decifrar)))
    nav.add(nav_button("HMAC / Assinatura", lambda w: show(page_hmac)))

    header.add(nav)

    # Área de conteúdo
    content_area = toga.Box(style=Pack(flex=1))
    show(page_gerar_chave)

    main_box.add(header)
    main_box.add(content_area)

    return main_box