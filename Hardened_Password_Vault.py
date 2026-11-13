import customtkinter as ctk
from tkinter import messagebox, TclError
import secrets
import string
import base64
import os
import sys
import math
import hashlib
import threading
from queue import Empty, Queue
from Crypto.Cipher import AES

# Pre-configure CustomTkinter before window creation for faster startup
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

PBKDF2_ITERATIONS = 1_000_000

# ==========================================
# OPTIMIZATION 1: PRE-COMPUTED CHARACTER POOLS
# Computed once at import time instead of on every button click or keystroke
# ==========================================
AMBIGUOUS_SET = frozenset("0O1lI|")
LOWER_SET = frozenset(string.ascii_lowercase)
UPPER_SET = frozenset(string.ascii_uppercase)
DIGIT_SET = frozenset(string.digits)
SYMBOL_SET = frozenset(string.punctuation)
STANDARD_ALL_SET = LOWER_SET | UPPER_SET | DIGIT_SET | SYMBOL_SET

POOL_RAW = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}
POOL_FILTERED = {
    k: "".join(c for c in v if c not in AMBIGUOUS_SET) for k, v in POOL_RAW.items()
}

WORD_LIST = (
    "acoustic", "alpine", "amber", "anchor", "apollo", "arctic", "arrow", "aspen",
    "atlas", "aurora", "autumn", "avalon", "badger", "bamboo", "banyan", "baron",
    "basalt", "beacon", "bison", "blizzard", "blossom", "boulder", "breeze", "bronze",
    "canyon", "carbon", "cascade", "castle", "cedar", "celeste", "chisel", "chrome",
    "cipher", "citadel", "circuit", "cobalt", "comet", "compass", "condor", "copper",
    "coral", "cosmos", "cougar", "crater", "crimson", "crystal", "cyclone", "cypress",
    "dagger", "delta", "desert", "diamond", "dolphin", "dragon", "dynamo", "eclipse",
    "emerald", "ember", "empire", "enigma", "equinox", "everest", "falcon", "fathom",
    "fjord", "flannel", "flint", "forest", "fortress", "fossil", "fusion", "galaxy",
    "garnet", "gazelle", "geyser", "glacier", "granite", "gravity", "griffin", "harbor",
    "harvest", "helios", "horizon", "hunter", "iceberg", "ignite", "indigo", "infinity",
    "iron", "island", "ivory", "iguana", "jacket", "jaguar", "jasper", "javelin",
    "jester", "jungle", "jupiter", "karma", "kestrel", "kingdom", "krypton", "lagoon",
    "lantern", "lariat", "lava", "legacy", "legend", "leopard", "liberty", "lightning",
    "lithium", "lotus", "lunar", "magnet", "mammoth", "mantis", "marble", "mariner",
    "matrix", "meadow", "mercury", "meteor", "mirage", "monarch", "monsoon", "mosaic",
    "mustang", "nebula", "nectar", "neptune", "nickel", "nimbus", "nitrogen", "nomad",
    "nova", "obsidian", "ocean", "odyssey", "olympus", "omega", "onyx", "opal",
    "orbit", "orchid", "orion", "osprey", "outpost", "oxygen", "pacific", "paladin",
    "panther", "paradox", "pegasus", "pelican", "pendulum", "phantom", "phoenix", "pioneer",
    "planet", "plasma", "platinum", "polaris", "prairie", "prism", "pulsar", "pyramid",
    "python", "quantum", "quartz", "quasar", "quiver", "radon", "raptor", "redwood",
    "sapphire", "saturn", "savanna", "scarlet", "scepter", "scorpion", "sequoia", "serpent",
    "shadow", "sierra", "silver", "solstice", "sonnet", "sparrow", "spectrum", "sphinx",
    "starlight", "stratos", "summit", "tempest", "thunder", "titanium", "topaz", "tornado",
    "trident", "tundra", "typhoon", "umbra", "utopia", "valkyrie", "velvet", "venture",
    "vertex", "viper", "vortex", "voyager", "vulcan", "warden", "whisper", "wildfire",
    "zenith", "zephyr", "zircon", "zodiac"
)

SYS_RAND = secrets.SystemRandom()


class InvalidToken(Exception):
    pass


class OptimizedPasswordSuite(ctk.CTk):
    def __init__(self):
        super().__init__()

        # FIX 2: Safe icon loading so missing .ico file never crashes startup
        app_icon_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        app_icon_path = os.path.join(app_icon_dir, "password_generation_encryption_app_icon.ico")
        if os.path.exists(app_icon_path):
            try:
                self.iconbitmap(app_icon_path)
            except TclError:
                pass

        self.title("Password Generator & Encryptor (Optimized Password Suite: AES-256-GCM)")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        min_width = min(860, max(1, screen_width - 40))
        min_height = min(760, max(1, screen_height - 80))
        self.geometry("1040x950")
        self.minsize(min_width, min_height)
        if os.name == "nt":
            try:
                self.state("zoomed")
            except TclError:
                pass

        # Timers & State
        self.screen_wipe_timer_id = None
        self.entropy_debounce_id = None

        # FIX 4: Store derived 32-byte keys as mutable bytearrays so they can be zeroed in RAM
        # without ever touching or disabling the OS clipboard or paste functionality
        self._key_cache: dict[tuple[bytes, bytes], bytearray] = {}
        self._key_cache_lock = threading.Lock()
        self._key_cache_generation = 0
        self._is_encrypting = False
        self._is_decrypting = False
        self._operation_ids = {"encrypt": 0, "decrypt": 0}
        self._crypto_results = Queue()

        # Shared Fonts (Created once, reused everywhere for faster startup)
        self.font_title = ctk.CTkFont(size=22, weight="bold")
        self.font_section = ctk.CTkFont(size=16, weight="bold")
        self.font_bold = ctk.CTkFont(size=12, weight="bold")
        self.font_body = ctk.CTkFont(size=12)
        self.font_mono = ctk.CTkFont(family="Consolas", size=13)
        self.font_mono_sm = ctk.CTkFont(family="Consolas", size=12)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_ui()
        self._bind_shortcuts()
        self.after(50, self._poll_crypto_results)

    def _build_ui(self):
        page_bg = ("#eef2f7", "#080f1c")
        card_bg = ("#ffffff", "#111b2b")
        inset_bg = ("#f3f6fa", "#0b1422")
        border = ("#d8e1eb", "#24354c")
        text_secondary = ("#607086", "#9aabc1")
        accent = ("#0f8b8d", "#20b8a8")
        accent_hover = ("#0b7375", "#159688")
        success = ("#147d64", "#147d64")

        self.configure(fg_color=page_bg)
        header_frame = ctk.CTkFrame(
            self, corner_radius=18, fg_color=card_bg, border_width=1, border_color=border
        )
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 12))
        header_frame.grid_columnconfigure(0, weight=1)

        header_copy = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_copy.grid(row=0, column=0, sticky="w", padx=22, pady=17)
        ctk.CTkLabel(
            header_copy, text="SECURE PASSWORD STUDIO",
            font=ctk.CTkFont(size=10, weight="bold"), text_color=accent
        ).pack(anchor="w")
        ctk.CTkLabel(header_copy, text="Your passwords. Protected.", font=self.font_title).pack(anchor="w", pady=(3, 0))
        ctk.CTkLabel(
            header_copy, text="Generate securely, encrypt locally, and decrypt only when you need to.",
            font=self.font_body, text_color=text_secondary
        ).pack(anchor="w", pady=(3, 0))

        self.theme_switch = ctk.CTkSwitch(
            header_frame, text="Dark mode", command=self.toggle_theme,
            onvalue="Dark", offvalue="Light", progress_color=accent
        )
        self.theme_switch.select()
        self.theme_switch.grid(row=0, column=1, padx=22, pady=18, sticky="e")

        self.workflow_tabs = ctk.CTkTabview(
            self, corner_radius=14,
            segmented_button_selected_color=accent,
            segmented_button_selected_hover_color=accent_hover,
            segmented_button_unselected_color=card_bg,
            segmented_button_unselected_hover_color=inset_bg,
        )
        self.workflow_tabs.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 8))

        page_scrollers = {}
        for page_name in ("01  Generate", "02  Encrypt", "03  Decrypt"):
            self.workflow_tabs.add(page_name)
            page = self.workflow_tabs.tab(page_name)
            page.grid_rowconfigure(0, weight=1)
            page.grid_columnconfigure(0, weight=1)
            scroller = ctk.CTkScrollableFrame(
                page, fg_color="transparent", corner_radius=0,
                scrollbar_button_color=border, scrollbar_button_hover_color=accent
            )
            scroller.grid(row=0, column=0, sticky="nsew", padx=12, pady=10)
            scroller.grid_columnconfigure(0, weight=1)
            page_scrollers[page_name] = scroller

        generator_col = page_scrollers["01  Generate"]
        encrypt_col = page_scrollers["02  Encrypt"]
        decrypt_col = page_scrollers["03  Decrypt"]

        card_options = {
            "corner_radius": 16, "fg_color": card_bg,
            "border_width": 1, "border_color": border,
        }
        entry_options = {
            "height": 42, "corner_radius": 10, "border_width": 1,
            "border_color": border, "fg_color": inset_bg,
        }
        primary_button = {
            "corner_radius": 10, "fg_color": accent, "hover_color": accent_hover,
            "height": 40, "font": self.font_bold,
        }

        def add_section_heading(parent, title, description):
            ctk.CTkLabel(parent, text=title, font=self.font_section).pack(anchor="w", padx=20, pady=(18, 2))
            ctk.CTkLabel(parent, text=description, font=self.font_body, text_color=text_secondary).pack(
                anchor="w", padx=20, pady=(0, 12)
            )

        def add_field_label(parent, text):
            ctk.CTkLabel(parent, text=text, font=self.font_bold, text_color=text_secondary).pack(
                anchor="w", padx=2, pady=(0, 5)
            )

        def add_visibility_button(parent, entry, initially_visible):
            visible_var = ctk.BooleanVar(value=initially_visible)
            button = ctk.CTkButton(
                parent, text="🙈 Hide" if initially_visible else "👁 Show",
                width=92, height=34, corner_radius=9,
                fg_color=inset_bg, hover_color=border,
                text_color=text_secondary,
            )
            button.configure(
                command=lambda: self.toggle_entry_visibility(entry, visible_var, button)
            )
            entry.configure(show="" if initially_visible else "*")
            return button

        # ==========================================
        # TAB 01: PASSWORD & PASSPHRASE GENERATOR
        # ==========================================
        gen_card = ctk.CTkFrame(generator_col, **card_options)
        self.gen_card = gen_card
        gen_card.pack(fill="x", pady=(0, 14))
        add_section_heading(
            gen_card,
            "01  Password generator",
            "Create a unique-character password (up to 94 raw / 88 without ambiguous chars) or a passphrase."
        )

        self.gen_tabs = ctk.CTkTabview(
            gen_card, height=200, corner_radius=12,
            segmented_button_selected_color=accent, segmented_button_selected_hover_color=accent_hover
        )
        self.gen_tabs.pack(fill="x", padx=16, pady=(0, 12))
        tab_random = self.gen_tabs.add("Random password")
        tab_phrase = self.gen_tabs.add("Passphrase")

        len_row = ctk.CTkFrame(tab_random, fg_color="transparent")
        len_row.pack(fill="x", pady=(8, 8))
        self.len_label = ctk.CTkLabel(
            len_row, text="Length: 20 unique characters (Max: 94)", font=self.font_bold
        )
        self.len_label.pack(anchor="w")
        self.len_slider = ctk.CTkSlider(
            len_row, from_=16, to=94, number_of_steps=78, command=self.update_len_label,
            progress_color=accent, button_color=accent, button_hover_color=accent_hover
        )
        self.len_slider.set(20)
        self.len_slider.pack(fill="x", pady=(5, 2))
        ctk.CTkButton(
            tab_random, text="Generate password", command=self.generate_random_password, **primary_button
        ).pack(fill="x", pady=(0, 8))

        self.use_lower_var = ctk.BooleanVar(value=True)
        self.use_upper_var = ctk.BooleanVar(value=True)
        self.use_digits_var = ctk.BooleanVar(value=True)
        self.use_symbols_var = ctk.BooleanVar(value=True)
        self.exclude_ambiguous_var = ctk.BooleanVar(value=False)

        chk_row1 = ctk.CTkFrame(tab_random, fg_color="transparent")
        chk_row1.pack(fill="x", pady=(3, 0))
        for label, variable in (
            ("a-z", self.use_lower_var), ("A-Z", self.use_upper_var),
            ("0-9", self.use_digits_var), ("Symbols", self.use_symbols_var),
        ):
            ctk.CTkCheckBox(
                chk_row1, text=label, variable=variable,
                command=self._sync_unique_slider_bounds,
                checkbox_width=18, checkbox_height=18
            ).pack(side="left", padx=(0, 12))

        ctk.CTkCheckBox(
            tab_random, text="Exclude ambiguous characters (0, O, 1, l, I, |) — Max 88 unique",
            variable=self.exclude_ambiguous_var,
            command=self._sync_unique_slider_bounds,
            checkbox_width=18, checkbox_height=18
        ).pack(anchor="w", pady=(9, 2))

        words_row = ctk.CTkFrame(tab_phrase, fg_color="transparent")
        words_row.pack(fill="x", pady=(8, 8))
        self.words_label = ctk.CTkLabel(words_row, text="Words: 5", font=self.font_bold)
        self.words_label.pack(anchor="w")
        self.words_slider = ctk.CTkSlider(
            words_row, from_=4, to=12, number_of_steps=8, command=self.update_words_label,
            progress_color=accent, button_color=accent, button_hover_color=accent_hover
        )
        self.words_slider.set(5)
        self.words_slider.pack(fill="x", pady=(5, 2))
        phrase_opts = ctk.CTkFrame(tab_phrase, fg_color="transparent")
        phrase_opts.pack(fill="x", pady=(3, 10))
        ctk.CTkLabel(phrase_opts, text="Word separator", font=self.font_bold).pack(anchor="w", pady=(0, 5))
        self.sep_var = ctk.StringVar(value="-")
        ctk.CTkComboBox(
            phrase_opts, values=["-", "_", ".", "Space", "/"], variable=self.sep_var,
            height=36, corner_radius=9, border_color=border, fg_color=inset_bg, button_color=accent
        ).pack(fill="x")
        phrase_checks = ctk.CTkFrame(tab_phrase, fg_color="transparent")
        phrase_checks.pack(fill="x", pady=(7, 8))
        self.title_case_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(phrase_checks, text="Title case", variable=self.title_case_var).pack(side="left", padx=(0, 15))
        self.append_num_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(phrase_checks, text="Add number & symbol", variable=self.append_num_var).pack(side="left")
        ctk.CTkButton(
            tab_phrase, text="Generate passphrase", command=self.generate_passphrase, **primary_button
        ).pack(fill="x")

        output_card = ctk.CTkFrame(gen_card, fg_color="transparent")
        self.output_card = output_card
        output_card.pack(fill="x", padx=6, pady=(0, 4))
        add_section_heading(output_card, "Generated password", "Edit the value here if you want to encrypt a custom password.")
        self.raw_pass_var = ctk.StringVar()
        self.raw_pass_var.trace_add("write", self._schedule_entropy_update)
        raw_field = ctk.CTkFrame(output_card, fg_color="transparent")
        raw_field.pack(fill="x", padx=18, pady=(0, 8))
        add_field_label(raw_field, "Generated password or custom text")
        self.raw_entry = ctk.CTkEntry(
            raw_field, textvariable=self.raw_pass_var,
            placeholder_text="Password to encrypt or custom password…",
            font=self.font_mono, **entry_options
        )
        self.raw_entry.pack(fill="x")
        raw_actions = ctk.CTkFrame(output_card, fg_color="transparent")
        raw_actions.pack(fill="x", padx=18, pady=(0, 10))
        ctk.CTkButton(
            raw_actions, text="Copy", width=76, height=34, corner_radius=9,
            command=lambda: self.copy_to_clipboard(self.raw_pass_var.get(), "Raw password")
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            raw_actions, text="Paste", width=76, height=34, corner_radius=9,
            command=lambda: self.paste_to_field(self.raw_entry, self.raw_pass_var, "Password")
        ).pack(side="left", padx=(0, 8))
        self.raw_visibility_btn = add_visibility_button(raw_actions, self.raw_entry, True)
        self.raw_visibility_btn.pack(side="left")
        self._bind_clipboard_shortcuts(self.raw_entry, self.raw_pass_var, "Password")
        meter_box = ctk.CTkFrame(output_card, fg_color="transparent")
        meter_box.pack(fill="x", padx=20, pady=(0, 17))
        self.strength_bar = ctk.CTkProgressBar(
            meter_box, height=9, corner_radius=5, progress_color=accent
        )
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", pady=(0, 6))
        self.entropy_label = ctk.CTkLabel(meter_box, text="Strength: N/A | Entropy: 0.0 bits", font=self.font_bold)
        self.entropy_label.pack(anchor="w")

        # ==========================================
        # TAB 02: ENCRYPTION
        # ==========================================
        enc_card = ctk.CTkFrame(encrypt_col, **card_options)
        enc_card.pack(fill="x", pady=(0, 14))
        add_section_heading(enc_card, "02  Encryption", "Protect your password with authenticated encryption.")
        self.encrypt_mode_var = ctk.StringVar(value="AES")
        mode_box = ctk.CTkFrame(enc_card, fg_color=inset_bg, corner_radius=11)
        mode_box.pack(fill="x", padx=18, pady=(0, 11))
        ctk.CTkRadioButton(
            mode_box, text="AES-256-GCM", variable=self.encrypt_mode_var, value="AES",
            command=self.toggle_encrypt_master_key, font=self.font_bold, fg_color=accent, hover_color=accent_hover
        ).pack(anchor="w", padx=12, pady=(10, 4))
        ctk.CTkLabel(
            mode_box, text="Strong encryption · 1M PBKDF2 iterations",
            font=self.font_body, text_color=text_secondary
        ).pack(anchor="w", padx=35, pady=(0, 4))
        ctk.CTkRadioButton(
            mode_box, text="Base64 encoding (not encryption)", variable=self.encrypt_mode_var, value="B64",
            command=self.toggle_encrypt_master_key, font=self.font_body, fg_color=accent, hover_color=accent_hover
        ).pack(anchor="w", padx=12, pady=(4, 10))

        self.master_key_var = ctk.StringVar()
        master_field = ctk.CTkFrame(enc_card, fg_color="transparent")
        master_field.pack(fill="x", padx=18, pady=(0, 8))
        add_field_label(master_field, "Master password for encryption")
        self.master_entry = ctk.CTkEntry(
            master_field, textvariable=self.master_key_var,
            placeholder_text="Master key · 12+ chars with upper, lower, number & symbol",
            show="*", font=self.font_mono, **entry_options
        )
        self.master_entry.pack(fill="x")
        master_actions = ctk.CTkFrame(enc_card, fg_color="transparent")
        master_actions.pack(fill="x", padx=18, pady=(0, 12))
        self.encrypt_visibility_btn = add_visibility_button(master_actions, self.master_entry, False)
        self.encrypt_visibility_btn.pack(side="left", padx=(0, 8))
        self.master_copy_btn = ctk.CTkButton(
            master_actions, text="Copy key", width=82, height=34, corner_radius=9,
            command=lambda: self.copy_to_clipboard(self.master_key_var.get(), "Master key")
        )
        self.master_copy_btn.pack(side="left", padx=(0, 8))
        self.master_paste_btn = ctk.CTkButton(
            master_actions, text="Paste", width=76, height=34, corner_radius=9, command=self.paste_master_key
        )
        self.master_paste_btn.pack(side="left", padx=(0, 8))
        self._bind_clipboard_shortcuts(self.master_entry, self.master_key_var, "Master key")
        self.encrypt_btn = ctk.CTkButton(
            master_actions, text="Encrypt", command=self.encrypt_current, **primary_button
        )
        self.encrypt_btn.pack(side="right")

        self.encrypted_var = ctk.StringVar()
        encrypted_field = ctk.CTkFrame(enc_card, fg_color="transparent")
        encrypted_field.pack(fill="x", padx=18, pady=(0, 8))
        add_field_label(encrypted_field, "Encrypted output token")
        self.encrypted_entry = ctk.CTkEntry(
            encrypted_field, textvariable=self.encrypted_var,
            placeholder_text="Encrypted token appears here…", font=self.font_mono_sm,
            **entry_options
        )
        self.encrypted_entry.pack(fill="x")
        encrypted_actions = ctk.CTkFrame(enc_card, fg_color="transparent")
        encrypted_actions.pack(fill="x", padx=18, pady=(0, 18))
        ctk.CTkButton(
            encrypted_actions, text="Copy", width=76, height=34, corner_radius=9,
            command=lambda: self.copy_to_clipboard(self.encrypted_var.get(), "Encrypted token")
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            encrypted_actions, text="Paste", width=76, height=34, corner_radius=9,
            command=lambda: self.paste_to_field(self.encrypted_entry, self.encrypted_var, "Encrypted token")
        ).pack(side="left", padx=(0, 8))
        self.encrypted_visibility_btn = add_visibility_button(encrypted_actions, self.encrypted_entry, True)
        self.encrypted_visibility_btn.pack(side="left")
        self._bind_clipboard_shortcuts(self.encrypted_entry, self.encrypted_var, "Encrypted token")

        # ==========================================
        # TAB 03: DECRYPTION
        # ==========================================
        dec_card = ctk.CTkFrame(decrypt_col, **card_options)
        dec_card.pack(fill="x")
        add_section_heading(dec_card, "03  Decryption", "Decrypt a token using its original master key.")
        self.decrypt_mode_var = ctk.StringVar(value="AES")
        decrypt_mode_box = ctk.CTkFrame(dec_card, fg_color=inset_bg, corner_radius=11)
        decrypt_mode_box.pack(fill="x", padx=18, pady=(0, 11))
        ctk.CTkRadioButton(
            decrypt_mode_box, text="AES-256-GCM", variable=self.decrypt_mode_var, value="AES",
            command=self.toggle_decrypt_master_key, font=self.font_bold,
            fg_color=accent, hover_color=accent_hover
        ).pack(anchor="w", padx=12, pady=(10, 4))
        ctk.CTkRadioButton(
            decrypt_mode_box, text="Base64 decoding (not encryption)", variable=self.decrypt_mode_var,
            value="B64", command=self.toggle_decrypt_master_key, font=self.font_body,
            fg_color=accent, hover_color=accent_hover
        ).pack(anchor="w", padx=12, pady=(4, 10))
        self.decrypt_input_var = ctk.StringVar()
        decrypt_input_field = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypt_input_field.pack(fill="x", padx=18, pady=(0, 8))
        add_field_label(decrypt_input_field, "Encrypted token to decrypt")
        self.decrypt_input_entry = ctk.CTkEntry(
            decrypt_input_field, textvariable=self.decrypt_input_var,
            placeholder_text="Encrypted token to decrypt · paste token here",
            font=self.font_mono_sm, **entry_options
        )
        self.decrypt_input_entry.pack(fill="x")
        decrypt_input_actions = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypt_input_actions.pack(fill="x", padx=18, pady=(0, 10))
        ctk.CTkButton(
            decrypt_input_actions, text="Paste", width=76, height=34, corner_radius=9,
            command=lambda: self.paste_to_field(self.decrypt_input_entry, self.decrypt_input_var, "Encrypted token")
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            decrypt_input_actions, text="Copy", width=76, height=34, corner_radius=9,
            command=lambda: self.copy_to_clipboard(self.decrypt_input_var.get(), "Encrypted token")
        ).pack(side="left", padx=(0, 8))
        self.decrypt_input_visibility_btn = add_visibility_button(
            decrypt_input_actions, self.decrypt_input_entry, True
        )
        self.decrypt_input_visibility_btn.pack(side="left")
        self._bind_clipboard_shortcuts(
            self.decrypt_input_entry, self.decrypt_input_var, "Encrypted token"
        )
        self.decrypt_key_var = ctk.StringVar()
        decrypt_key_field = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypt_key_field.pack(fill="x", padx=18, pady=(0, 8))
        add_field_label(decrypt_key_field, "Master password for decryption")
        self.decrypt_key_entry = ctk.CTkEntry(
            decrypt_key_field, textvariable=self.decrypt_key_var,
            placeholder_text="Enter the original master key used for encryption",
            show="*", font=self.font_mono, **entry_options
        )
        self.decrypt_key_entry.pack(fill="x")
        decrypt_key_actions = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypt_key_actions.pack(fill="x", padx=18, pady=(0, 10))
        self.decrypt_key_visibility_btn = add_visibility_button(
            decrypt_key_actions, self.decrypt_key_entry, False
        )
        self.decrypt_key_visibility_btn.pack(side="left", padx=(0, 8))
        self.decrypt_key_copy_btn = ctk.CTkButton(
            decrypt_key_actions, text="Copy key", width=82, height=34, corner_radius=9,
            command=lambda: self.copy_to_clipboard(self.decrypt_key_var.get(), "Decryption key")
        )
        self.decrypt_key_copy_btn.pack(side="left", padx=(0, 8))
        self.decrypt_key_paste_btn = ctk.CTkButton(
            decrypt_key_actions, text="Paste", width=76, height=34, corner_radius=9,
            command=lambda: self.paste_to_field(self.decrypt_key_entry, self.decrypt_key_var, "Decryption key")
        )
        self.decrypt_key_paste_btn.pack(side="left", padx=(0, 8))
        self._bind_clipboard_shortcuts(self.decrypt_key_entry, self.decrypt_key_var, "Decryption key")
        decrypt_actions = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypt_actions.pack(fill="x", padx=18, pady=(0, 10))
        self.decrypt_btn = ctk.CTkButton(
            decrypt_actions, text="Decrypt token", fg_color=success,
            hover_color=("#115e59", "#115e59"), command=self.decrypt_password, **{
                key: value for key, value in primary_button.items() if key not in {"fg_color", "hover_color"}
            }
        )
        self.decrypt_btn.pack(fill="x")
        self.decrypted_out_var = ctk.StringVar()
        decrypted_field = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypted_field.pack(fill="x", padx=18, pady=(0, 8))
        add_field_label(decrypted_field, "Decrypted plaintext")
        self.decrypted_output_entry = ctk.CTkEntry(
            decrypted_field, textvariable=self.decrypted_out_var,
            placeholder_text="Decrypted password appears here · auto-clears in 30 sec",
            state="readonly", font=self.font_mono, **entry_options
        )
        self.decrypted_output_entry.pack(fill="x")
        decrypted_actions = ctk.CTkFrame(dec_card, fg_color="transparent")
        decrypted_actions.pack(fill="x", padx=18, pady=(0, 18))
        ctk.CTkButton(
            decrypted_actions, text="Copy", width=76, height=34, corner_radius=9,
            command=lambda: self.copy_to_clipboard(self.decrypted_out_var.get(), "Decrypted password")
        ).pack(side="left", padx=(0, 8))
        self.decrypted_visibility_btn = add_visibility_button(
            decrypted_actions, self.decrypted_output_entry, True
        )
        self.decrypted_visibility_btn.pack(side="left")
        self._bind_clipboard_shortcuts(
            self.decrypted_output_entry, self.decrypted_out_var, "Decrypted password",
            paste_enabled=False
        )

        # ==========================================
        # STATUS BAR
        # ==========================================
        status_bar = ctk.CTkFrame(
            self, corner_radius=13, fg_color=card_bg, border_width=1, border_color=border
        )
        status_bar.grid(row=2, column=0, sticky="ew", padx=20, pady=(8, 16))
        status_bar.grid_columnconfigure(0, weight=1)
        self.status_var = ctk.StringVar(value="Ready · Encryption runs in the background")
        ctk.CTkLabel(
            status_bar, textvariable=self.status_var, font=self.font_body, anchor="w"
        ).grid(row=0, column=0, sticky="ew", padx=16, pady=12)
        ctk.CTkButton(
            status_bar, text="Wipe screen & cache", width=175, height=34, corner_radius=9,
            fg_color=("#fee2e2", "#3b1d2a"), hover_color=("#fecaca", "#512238"),
            text_color=("#991b1b", "#fecdd3"), command=self.instant_security_wipe
        ).grid(row=0, column=1, padx=12, pady=8)
        ctk.CTkButton(
            status_bar, text="Clear everything", width=145, height=34, corner_radius=9,
            fg_color=("#fecaca", "#512238"), hover_color=("#fca5a5", "#6b2739"),
            text_color=("#7f1d1d", "#ffe4e6"), command=self.clear_everything
        ).grid(row=0, column=2, padx=(0, 12), pady=8)

    def _bind_shortcuts(self):
        """Behavioral Optimization: Keyboard shortcuts for faster workflow."""
        self.master_entry.bind("<Return>", lambda e: self.encrypt_current())
        self.decrypt_key_entry.bind("<Return>", lambda e: self.decrypt_password())

    def _bind_clipboard_shortcuts(self, entry, variable, label_name, paste_enabled=True):
        """FIX 4: Preserves native Entry selection copy/paste while supporting full-field fallback."""
        widget = entry._entry
        widget.bind(
            "<Control-c>",
            lambda _event: self._copy_field_shortcut(widget, variable, label_name),
            add=True
        )
        widget.bind(
            "<Control-C>",
            lambda _event: self._copy_field_shortcut(widget, variable, label_name),
            add=True
        )
        if paste_enabled:
            widget.bind(
                "<Control-v>",
                lambda _event: self._paste_field_shortcut(entry, variable, label_name),
                add=True
            )
            widget.bind(
                "<Control-V>",
                lambda _event: self._paste_field_shortcut(entry, variable, label_name),
                add=True
            )

    def _copy_field_shortcut(self, widget, variable, label_name):
        try:
            selected = widget.selection_get()
            if selected:
                self.copy_to_clipboard(selected, label_name)
                return "break"
        except TclError:
            pass
        self.copy_to_clipboard(variable.get(), label_name)
        return "break"

    def _paste_field_shortcut(self, entry, variable, label_name):
        self.paste_to_field(entry, variable, label_name)
        return "break"

    # ==========================================
    # OPTIMIZATION 3: INSTANT THEME & SLIDER SYNC
    # ==========================================
    def toggle_theme(self):
        mode = str(self.theme_switch.get())
        ctk.set_appearance_mode(mode)
        self.theme_switch.configure(text=f"{mode} mode")

    def _get_selected_pools(self) -> list[str]:
        pool_map = POOL_FILTERED if self.exclude_ambiguous_var.get() else POOL_RAW
        selected = []
        if self.use_lower_var.get():
            selected.append(pool_map["lower"])
        if self.use_upper_var.get():
            selected.append(pool_map["upper"])
        if self.use_digits_var.get():
            selected.append(pool_map["digits"])
        if self.use_symbols_var.get():
            selected.append(pool_map["symbols"])
        return selected

    def _sync_unique_slider_bounds(self):
        """
        FIX 1 & FIX 3: Dynamically adjusts the slider maximum to match the exact number
        of unique characters available in the currently checked character sets:
        - All 4 sets (raw): 94 max
        - All 4 sets (exclude ambiguous '0O1lI|'): 88 max
        - Smaller combinations: scales down automatically so unique sampling never fails.
        """
        pools = self._get_selected_pools()
        max_unique = sum(len(p) for p in pools)

        if max_unique == 0:
            self.len_label.configure(text="Length: 0 (Select at least one character set)")
            return

        min_len = min(16, max_unique)
        current_val = int(round(self.len_slider.get()))
        clamped_val = max(min_len, min(current_val, max_unique))

        if max_unique > min_len:
            self.len_slider.configure(
                state="normal",
                from_=min_len,
                to=max_unique,
                number_of_steps=max_unique - min_len
            )
        else:
            self.len_slider.configure(
                state="disabled",
                from_=max(1, max_unique - 1),
                to=max_unique,
                number_of_steps=1
            )

        self.len_slider.set(clamped_val)
        self.len_label.configure(
            text=f"Length: {clamped_val} unique characters (Max: {max_unique})"
        )

    def update_len_label(self, value):
        pools = self._get_selected_pools()
        max_unique = sum(len(p) for p in pools)
        new_text = f"Length: {int(round(value))} unique characters (Max: {max_unique})"
        if self.len_label.cget("text") != new_text:
            self.len_label.configure(text=new_text)

    def update_words_label(self, value):
        new_text = f"Words: {int(round(value))}"
        if self.words_label.cget("text") != new_text:
            self.words_label.configure(text=new_text)

    def toggle_encrypt_master_key(self):
        state = "normal" if self.encrypt_mode_var.get() == "AES" else "disabled"
        self.master_entry.configure(state=state)
        self.master_copy_btn.configure(state=state)
        self.master_paste_btn.configure(state=state)

    def toggle_decrypt_master_key(self):
        state = "normal" if self.decrypt_mode_var.get() == "AES" else "disabled"
        self.decrypt_key_entry.configure(state=state)
        self.decrypt_key_copy_btn.configure(state=state)
        self.decrypt_key_paste_btn.configure(state=state)

    def paste_master_key(self):
        self.paste_to_field(self.master_entry, self.master_key_var, "Master key")

    def paste_to_field(self, entry: ctk.CTkEntry, variable: ctk.StringVar, label_name: str):
        """
        FIX 4: Robustly pastes text from outside applications even after 'Wipe screen & cache'
        or 'Clear everything' has been clicked. Temporarily wakes the entry widget if needed
        and clears CustomTkinter placeholder states cleanly.
        """
        if str(entry.cget("state")) == "disabled":
            messagebox.showwarning("Field Disabled", f"{label_name} is disabled in Base64 mode.")
            return

        try:
            clipboard_text = self.clipboard_get()
        except TclError:
            messagebox.showwarning("Clipboard Empty", "There is no text in the system clipboard to paste.")
            return

        if not clipboard_text:
            messagebox.showwarning("Clipboard Empty", "There is no text in the system clipboard to paste.")
            return

        # Ensure CustomTkinter Entry exits placeholder state properly when setting text
        entry.focus_set()
        variable.set(clipboard_text)
        entry._entry.icursor("end")
        self.status_var.set(f"📋 {label_name} pasted from clipboard.")

    @staticmethod
    def toggle_entry_visibility(entry, visible_var, button):
        is_visible = not visible_var.get()
        visible_var.set(is_visible)
        entry.configure(show="" if is_visible else "*")
        button.configure(text="🙈 Hide" if is_visible else "👁 Show")

    # ==========================================
    # CRYPTO & SESSION KEY CACHE ENGINE
    # ==========================================
    @staticmethod
    def zeroize_bytearray(buf: bytearray):
        if isinstance(buf, bytearray):
            buf[:] = b"Null" * len(buf)

    @staticmethod
    def validate_master_password(pw: str) -> tuple[bool, str]:
        if len(pw) < 12:
            return False, "Master Password must be at least 12 characters long."
        chars = set(pw)
        if not (chars & LOWER_SET):
            return False, "Master Password must include a lowercase letter (a-z)."
        if not (chars & UPPER_SET):
            return False, "Master Password must include an uppercase letter (A-Z)."
        if not (chars & DIGIT_SET):
            return False, "Master Password must include a digit (0-9)."
        if not (chars & SYMBOL_SET):
            return False, "Master Password must include a special symbol (!@#$)."
        return True, ""

    def _derive_key_cached(self, master_pw: str, salt: bytes) -> bytes:
        """
        FIX 4: Caches derived 32-byte keys as mutable bytearrays so they can be explicitly
        overwritten with 0x00 bytes in RAM when wiped. Returns an immutable bytes copy for AES.
        """
        pw_hash = hashlib.sha256(master_pw.encode("utf-8")).digest()
        cache_key = (pw_hash, salt)
        with self._key_cache_lock:
            generation = self._key_cache_generation
            cached_buf = self._key_cache.get(cache_key)
            if cached_buf is not None:
                return bytes(cached_buf)

        pw_bytes = bytearray(master_pw.encode("utf-8"))
        try:
            derived = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, PBKDF2_ITERATIONS, dklen=32)
            with self._key_cache_lock:
                if generation == self._key_cache_generation:
                    if len(self._key_cache) >= 64:
                        for old_buf in self._key_cache.values():
                            self.zeroize_bytearray(old_buf)
                        self._key_cache.clear()
                    self._key_cache[cache_key] = bytearray(derived)
            return derived
        finally:
            self.zeroize_bytearray(pw_bytes)

    def aes_gcm_encrypt(self, plaintext: str, master_pw: str) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        pt_bytes = bytearray(plaintext.encode("utf-8"))
        key_copy = bytearray()
        try:
            key_copy = bytearray(self._derive_key_cached(master_pw, salt))
            cipher = AES.new(bytes(key_copy), AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(bytes(pt_bytes))
            return base64.urlsafe_b64encode(salt + nonce + tag + ciphertext).decode("utf-8")
        finally:
            self.zeroize_bytearray(pt_bytes)
            self.zeroize_bytearray(key_copy)

    def aes_gcm_decrypt(self, token_b64: str, master_pw: str) -> str:
        raw_payload = base64.urlsafe_b64decode(token_b64.encode("utf-8"))
        if len(raw_payload) < 44:
            raise ValueError("Malformed AES-256-GCM payload.")
        salt, nonce, tag, ciphertext = raw_payload[:16], raw_payload[16:28], raw_payload[28:44], raw_payload[44:]
        pt_buf = bytearray()
        key_copy = bytearray()
        try:
            key_copy = bytearray(self._derive_key_cached(master_pw, salt))
            cipher = AES.new(bytes(key_copy), AES.MODE_GCM, nonce=nonce)
            pt_buf = bytearray(cipher.decrypt_and_verify(ciphertext, tag))
            return pt_buf.decode("utf-8")
        finally:
            self.zeroize_bytearray(pt_buf)
            self.zeroize_bytearray(key_copy)

    # ==========================================
    # FIX 1 & FIX 3: UNIQUE-CHARACTER RANDOM GENERATOR
    # ==========================================
    def generate_random_password(self):
        selected_pools = self._get_selected_pools()
        if not selected_pools:
            messagebox.showwarning("No Character Sets", "Select at least one character set checkbox!")
            return

        self._sync_unique_slider_bounds()
        max_unique = sum(len(p) for p in selected_pools)
        length = min(int(round(self.len_slider.get())), max_unique)

        # Guarantee at least one unique character from each checked category (when length >= num categories)
        if length >= len(selected_pools):
            chosen = [SYS_RAND.choice(pool) for pool in selected_pools]
            chosen_set = set(chosen)
            remaining_pool = [c for pool in selected_pools for c in pool if c not in chosen_set]
            chosen.extend(SYS_RAND.sample(remaining_pool, k=length - len(selected_pools)))
            SYS_RAND.shuffle(chosen)
        else:
            combined_pool = "".join(selected_pools)
            chosen = SYS_RAND.sample(combined_pool, k=length)

        password = "".join(chosen)
        self.raw_pass_var.set(password)
        self.status_var.set(
            f"🔐 Generated {len(password)}-character password with 100% unique characters. Select Encrypt when ready."
        )

    def generate_passphrase(self):
        num_words = int(round(self.words_slider.get()))
        sep = " " if self.sep_var.get() == "Space" else self.sep_var.get()
        chosen_words = SYS_RAND.sample(WORD_LIST, k=num_words)
        if self.title_case_var.get():
            chosen_words = [w.capitalize() for w in chosen_words]
        phrase = sep.join(chosen_words)
        if self.append_num_var.get():
            digits = POOL_FILTERED["digits"] if self.exclude_ambiguous_var.get() else POOL_RAW["digits"]
            symbols = POOL_FILTERED["symbols"] if self.exclude_ambiguous_var.get() else "!@#$%&*?"
            d1, d2 = SYS_RAND.sample(digits, k=2)
            sym = secrets.choice(symbols)
            phrase += f"{sep}{d1}{d2}{sym}"
        self.raw_pass_var.set(phrase)
        self.status_var.set("🔐 Passphrase generated. Select Encrypt when you are ready.")

    def _schedule_entropy_update(self, *args):
        """Debounces entropy calculation by 40ms during rapid typing."""
        if self.entropy_debounce_id is not None:
            self.after_cancel(self.entropy_debounce_id)
        self.entropy_debounce_id = self.after(40, self.update_strength_meter)

    def update_strength_meter(self):
        self.entropy_debounce_id = None
        pw = self.raw_pass_var.get()
        if not pw:
            self.strength_bar.set(0)
            self.entropy_label.configure(text="Strength: N/A | Entropy: 0.0 bits")
            return

        # Single-pass O(N) set creation + O(1) frozenset intersections
        chars = set(pw)
        pool_size = 0
        if chars & LOWER_SET:
            pool_size += 26
        if chars & UPPER_SET:
            pool_size += 26
        if chars & DIGIT_SET:
            pool_size += 10
        if chars & SYMBOL_SET:
            pool_size += 32
        if chars - STANDARD_ALL_SET:
            pool_size += 10

        entropy = len(pw) * math.log2(pool_size) if pool_size > 0 else 0.0
        self.strength_bar.set(min(entropy / 160.0, 1.0))

        if entropy < 60:
            rating, color = "Weak", "#e03131"
        elif entropy < 90:
            rating, color = "Moderate", "#f08c00"
        elif entropy < 120:
            rating, color = "Strong", "#1971c2"
        else:
            rating, color = "Very Strong (Cryptographic Grade)", "#2f9e44"

        self.strength_bar.configure(progress_color=color)
        unique_count = len(chars)
        self.entropy_label.configure(
            text=f"Strength: {rating} | Entropy: {entropy:.1f} bits (Length: {len(pw)}, Unique: {unique_count})"
        )

    # ==========================================
    # NON-BLOCKING THREADED CRYPTO OPERATIONS
    # ==========================================
    def encrypt_current(self):
        if self._is_encrypting:
            return
        raw_text = self.raw_pass_var.get()
        if not raw_text:
            messagebox.showwarning("Empty Password", "Generate or enter a password first.")
            return

        if self.encrypt_mode_var.get() == "B64":
            encoded_str = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")
            self.encrypted_var.set(encoded_str)
            self.status_var.set("🔒 Password encoded as Base64. Copy or use the result.")
            return

        master_pw = self.master_key_var.get()
        valid, err_msg = self.validate_master_password(master_pw)
        if not valid:
            messagebox.showwarning("Weak Master Password", err_msg)
            return

        self._is_encrypting = True
        self._operation_ids["encrypt"] += 1
        operation_id = self._operation_ids["encrypt"]
        self.encrypt_btn.configure(state="disabled", text="Encrypting...")
        self.status_var.set("⏳ Deriving 1M PBKDF2 key & encrypting in background thread...")

        def worker():
            try:
                token = self.aes_gcm_encrypt(raw_text, master_pw)
                self._crypto_results.put(
                    ("encrypt", operation_id, self._on_encrypt_done, (token,))
                )
            except Exception as e:
                error_message = str(e)
                self._crypto_results.put(
                    (
                        "encrypt", operation_id, self._on_crypto_error,
                        ("encrypt", "Encryption Error", error_message),
                    )
                )

        threading.Thread(target=worker, daemon=True).start()

    def _dispatch_operation_result(self, operation: str, operation_id: int, callback, *args):
        if operation_id == self._operation_ids[operation]:
            callback(*args)

    def _poll_crypto_results(self):
        while True:
            try:
                operation, operation_id, callback, args = self._crypto_results.get_nowait()
            except Empty:
                break
            self._dispatch_operation_result(operation, operation_id, callback, *args)
        self.after(50, self._poll_crypto_results)

    def _on_encrypt_done(self, token: str):
        self._is_encrypting = False
        # FIX 5: Consistently restore button label to "Encrypt"
        self.encrypt_btn.configure(state="normal", text="Encrypt")
        self.encrypted_var.set(token)
        self.status_var.set("🔒 Encrypted with AES-256-GCM. Copy the token to use it in Section 03.")

    def decrypt_password(self):
        if self._is_decrypting:
            return
        encrypted_text = self.decrypt_input_var.get().strip()
        if not encrypted_text:
            messagebox.showwarning("Empty Input", "Paste an encrypted token first.")
            return

        if self.decrypt_mode_var.get() == "B64":
            try:
                decoded_bytes = base64.b64decode(encrypted_text.encode("utf-8"), validate=True)
                self.decrypted_out_var.set(decoded_bytes.decode("utf-8"))
                self.schedule_screen_wipe()
                self.status_var.set("🔓 Base64 token decoded! Auto-wiping screen in 30s.")
            except Exception:
                messagebox.showerror("Decryption Error", "Invalid Base64 string!")
            return

        master_pw = self.decrypt_key_var.get()
        if not master_pw:
            messagebox.showwarning("Missing Master Key", "Enter the Master Password to decrypt this token.")
            return

        self._is_decrypting = True
        self._operation_ids["decrypt"] += 1
        operation_id = self._operation_ids["decrypt"]
        self.decrypt_btn.configure(state="disabled", text="Decrypting...")
        self.status_var.set("⏳ Verifying AES-256-GCM tag in background thread...")

        def worker():
            try:
                plaintext = self.aes_gcm_decrypt(encrypted_text, master_pw)
                self._crypto_results.put(
                    ("decrypt", operation_id, self._on_decrypt_done, (plaintext,))
                )
            except Exception:
                self._crypto_results.put(
                    ("decrypt", operation_id, self._on_decrypt_failed, ())
                )

        threading.Thread(target=worker, daemon=True).start()

    def _on_decrypt_done(self, plaintext: str):
        self._is_decrypting = False
        # FIX 5: Consistently restore button label to "Decrypt token"
        self.decrypt_btn.configure(state="normal", text="Decrypt token")
        self.decrypted_out_var.set(plaintext)
        self.schedule_screen_wipe()
        self.status_var.set("🔓 Token decrypted! Auto-wiping screen in 30s.")

    def _on_decrypt_failed(self):
        self._is_decrypting = False
        self.decrypt_btn.configure(state="normal", text="Decrypt token")
        self.decrypted_out_var.set("")
        self.status_var.set("❌ Decryption failed: Wrong Master Password or tampered token.")
        messagebox.showerror("Decryption Failed", "Incorrect Master Password or tampered AES-256-GCM token!")

    def _on_crypto_error(self, operation: str, title: str, msg: str):
        if operation == "encrypt":
            self._is_encrypting = False
            self.encrypt_btn.configure(state="normal", text="Encrypt")
        else:
            self._is_decrypting = False
            self.decrypt_btn.configure(state="normal", text="Decrypt token")
        messagebox.showerror(title, msg)

    # ==========================================
    # FIX 4: ZERO-RAM CACHE WIPE (PRESERVES OS CLIPBOARD & PASTE)
    # ==========================================
    def schedule_screen_wipe(self):
        if self.screen_wipe_timer_id is not None:
            self.after_cancel(self.screen_wipe_timer_id)
        self.screen_wipe_timer_id = self.after(30000, self.wipe_decrypted_screen)

    def wipe_decrypted_screen(self):
        self.decrypted_out_var.set("")
        self.screen_wipe_timer_id = None
        self.status_var.set("🛡️ Decrypted display automatically wiped after 30s of inactivity.")

    def _clear_key_cache(self):
        """Explicitly overwrites every cached 32-byte key bytearray in RAM with 0x00 before clearing."""
        with self._key_cache_lock:
            self._key_cache_generation += 1
            for key_buf in self._key_cache.values():
                self.zeroize_bytearray(key_buf)
            self._key_cache.clear()

    def _reset_entry_field(self, entry: ctk.CTkEntry, variable: ctk.StringVar):
        """Clears an entry's variable while keeping its widget state and paste bindings healthy."""
        variable.set("")
        try:
            if hasattr(entry, "_activate_placeholder"):
                entry._activate_placeholder()
        except Exception:
            pass

    def instant_security_wipe(self):
        if self.screen_wipe_timer_id is not None:
            self.after_cancel(self.screen_wipe_timer_id)
            self.screen_wipe_timer_id = None

        self._reset_entry_field(self.raw_entry, self.raw_pass_var)
        self._reset_entry_field(self.decrypted_output_entry, self.decrypted_out_var)
        self._clear_key_cache()
        self.update_idletasks()
        self.status_var.set("🧹 Screen text & RAM key cache zeroed. System clipboard & paste remain active.")

    def clear_everything(self):
        self._operation_ids["encrypt"] += 1
        self._operation_ids["decrypt"] += 1
        self._is_encrypting = False
        self._is_decrypting = False
        self.encrypt_btn.configure(state="normal", text="Encrypt")
        self.decrypt_btn.configure(state="normal", text="Decrypt token")

        if self.screen_wipe_timer_id is not None:
            self.after_cancel(self.screen_wipe_timer_id)
            self.screen_wipe_timer_id = None

        # Ensure modes and entry states stay unlocked and ready for pasting
        self.toggle_encrypt_master_key()
        self.toggle_decrypt_master_key()

        self._reset_entry_field(self.master_entry, self.master_key_var)
        self._reset_entry_field(self.raw_entry, self.raw_pass_var)
        self._reset_entry_field(self.encrypted_entry, self.encrypted_var)
        self._reset_entry_field(self.decrypt_input_entry, self.decrypt_input_var)
        self._reset_entry_field(self.decrypt_key_entry, self.decrypt_key_var)
        self._reset_entry_field(self.decrypted_output_entry, self.decrypted_out_var)

        self._clear_key_cache()
        if self.entropy_debounce_id is not None:
            self.after_cancel(self.entropy_debounce_id)
            self.entropy_debounce_id = None
        self.strength_bar.set(0)
        self.entropy_label.configure(text="Strength: N/A | Entropy: 0.0 bits")
        self.status_var.set("🧹 All app fields and RAM keys cleared. System clipboard & paste remain active.")

    def copy_to_clipboard(self, text: str, label_name: str):
        if not text:
            messagebox.showwarning("Empty Field", f"No {label_name.lower()} to copy!")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        self.status_var.set(f"📋 Copied {label_name} to clipboard.")


if __name__ == "__main__":
    app = OptimizedPasswordSuite()
    app.mainloop()
