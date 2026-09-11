"""Simple local password notebook with an encrypted local vault."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
import json
import os
import secrets
import string
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, ttk
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

APP_DIR = Path(__file__).resolve().parent / "password_vault_data"
SETTINGS_FILE = APP_DIR / "settings.json"
VAULT_FILE = APP_DIR / "vault.json"
AUTO_LOCK_MS = 5 * 60 * 1000
CLIPBOARD_CLEAR_MS = 25 * 1000
BACKGROUND = "#070b08"
PANEL = "#0e1710"
PANEL_ACTIVE = "#15241a"
GREEN = "#39ff88"
GREEN_SOFT = "#9fffc2"
GREEN_DARK = "#1f9e55"
MUTED = "#77a587"
MONO_FONT = "Cascadia Mono"


class PasswordVault(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LOCAL MANAGER PASSWORDS")
        self.geometry("880x540")
        self.minsize(700, 440)
        self.records, self.selected_index = [], None
        self.fernet = None
        self.unlocked = self.password_visible = False
        self.auto_lock_job = self.clipboard_clear_job = None
        self.clipboard_value = None
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.configure(background=BACKGROUND)
        self.setup_theme()
        self.bind_all("<KeyPress>", self.record_activity, add="+")
        self.bind_all("<ButtonPress>", self.record_activity, add="+")
        self.bind_all("<Control-f>", self.focus_search)
        self.bind_all("<Control-s>", self.hotkey_save)
        self.bind_all("<Control-n>", self.hotkey_new)
        APP_DIR.mkdir(exist_ok=True)
        self.show_login()

    def setup_theme(self):
        """Apply a terminal-like dark palette to every Tk/ttk widget."""
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BACKGROUND, foreground=GREEN_SOFT, font=(MONO_FONT, 10))
        style.configure("TFrame", background=BACKGROUND)
        style.configure("TLabel", background=BACKGROUND, foreground=GREEN_SOFT)
        style.configure("Title.TLabel", background=BACKGROUND, foreground=GREEN, font=(MONO_FONT, 16, "bold"))
        style.configure("Hint.TLabel", background=BACKGROUND, foreground=MUTED)
        style.configure("TButton", background=PANEL, foreground=GREEN, bordercolor=GREEN_DARK, lightcolor=GREEN_DARK, darkcolor=BACKGROUND, padding=(10, 6), font=(MONO_FONT, 9, "bold"))
        style.map("TButton", background=[("active", PANEL_ACTIVE), ("pressed", GREEN_DARK)], foreground=[("active", "#ffffff"), ("pressed", "#ffffff")])
        style.configure("TEntry", fieldbackground="#050906", foreground=GREEN, insertcolor=GREEN, bordercolor=GREEN_DARK, lightcolor=GREEN_DARK, padding=6)
        style.map("TEntry", bordercolor=[("focus", GREEN)])
        style.configure("TSpinbox", fieldbackground="#050906", foreground=GREEN, insertcolor=GREEN, bordercolor=GREEN_DARK, padding=5)
        style.configure("Treeview", background="#080d09", fieldbackground="#080d09", foreground=GREEN_SOFT, bordercolor=GREEN_DARK, rowheight=29, font=(MONO_FONT, 10))
        style.configure("Treeview.Heading", background=PANEL, foreground=GREEN, bordercolor=GREEN_DARK, font=(MONO_FONT, 9, "bold"), padding=7)
        style.map("Treeview", background=[("selected", GREEN_DARK)], foreground=[("selected", "#ffffff")])
        style.configure("TLabelframe", background=BACKGROUND, foreground=GREEN, bordercolor=GREEN_DARK, relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=BACKGROUND, foreground=GREEN, font=(MONO_FONT, 10, "bold"))
        style.configure("TCheckbutton", background=BACKGROUND, foreground=GREEN_SOFT, font=(MONO_FONT, 10))
        style.map("TCheckbutton", foreground=[("active", GREEN)])
        style.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BACKGROUND, bordercolor=BACKGROUND, arrowcolor=GREEN)

    def clear_window(self):
        for child in self.winfo_children():
            child.destroy()

    @staticmethod
    def read_json(path):
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    @staticmethod
    def write_json(path, data):
        """Atomically replace a JSON file only after a complete write."""
        temporary = path.with_name(f".{path.name}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as file:
                json.dump(data, file, ensure_ascii=False, indent=2)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def make_fernet(password, salt):
        """Derive a Fernet encryption key from the master password."""
        kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
        return Fernet(urlsafe_b64encode(kdf.derive(password.encode("utf-8"))))

    @staticmethod
    def encrypted_document(fernet, records):
        plaintext = json.dumps(records, ensure_ascii=False).encode("utf-8")
        return {"version": 2, "ciphertext": fernet.encrypt(plaintext).decode("ascii")}

    def write_vault(self):
        self.write_json(VAULT_FILE, self.encrypted_document(self.fernet, self.records))

    def read_encrypted_vault(self, fernet):
        document = self.read_json(VAULT_FILE)
        if document.get("version") != 2 or not isinstance(document.get("ciphertext"), str):
            raise ValueError("Unknown vault format")
        records = json.loads(fernet.decrypt(document["ciphertext"].encode("ascii")))
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError("Invalid record list")
        return records

    def show_login(self):
        self.unlocked = False
        if self.auto_lock_job:
            self.after_cancel(self.auto_lock_job)
            self.auto_lock_job = None
        self.clear_window()
        configured = SETTINGS_FILE.exists()
        frame = ttk.Frame(self, padding=35)
        frame.place(relx=.5, rely=.5, anchor="center")
        ttk.Label(frame, text="vault@local:~$ unlock", style="Title.TLabel").grid(row=0, column=0, columnspan=2, pady=(0, 8))
        ttk.Label(frame, text="Введите мастер-пароль" if configured else "Создайте мастер-пароль", style="Hint.TLabel").grid(row=1, column=0, columnspan=2, pady=(0, 4))
        ttk.Label(frame, text="Автоблокировка — через 5 минут бездействия." if configured else "Придумайте пароль для входа в приложение.", style="Hint.TLabel").grid(row=2, column=0, columnspan=2, pady=(0, 18))
        ttk.Label(frame, text="master_password:").grid(row=3, column=0, sticky="w", pady=5)
        self.master_password = ttk.Entry(frame, width=32, show="*")
        self.master_password.grid(row=3, column=1, pady=5)
        self.master_password.focus()
        self.master_password.bind("<Return>", lambda _event: self.login())
        if not configured:
            ttk.Label(frame, text="repeat_password:").grid(row=4, column=0, sticky="w", pady=5)
            self.master_password_repeat = ttk.Entry(frame, width=32, show="*")
            self.master_password_repeat.grid(row=4, column=1, pady=5)
            self.master_password_repeat.bind("<Return>", lambda _event: self.login())
        ttk.Button(frame, text="[ ВОЙТИ ]" if configured else "[ СОЗДАТЬ ХРАНИЛИЩЕ ]", command=self.login).grid(row=5, column=0, columnspan=2, pady=(18, 0))
        self.geometry("470x270")

    def login(self):
        entered = self.master_password.get()
        if not entered:
            messagebox.showwarning("Пароль", "Введите мастер-пароль.")
            return
        try:
            if SETTINGS_FILE.exists():
                settings = self.read_json(SETTINGS_FILE)
                if settings.get("version") == 2:
                    salt = urlsafe_b64decode(settings["salt"].encode("ascii"))
                    self.fernet = self.make_fernet(entered, salt)
                    self.records = self.read_encrypted_vault(self.fernet)
                elif "master_password" in settings:
                    self.migrate_plaintext_vault(entered, settings)
                else:
                    raise ValueError("Unknown settings format")
            else:
                if entered != self.master_password_repeat.get():
                    messagebox.showerror("Пароль", "Пароли не совпадают.")
                    return
                salt = os.urandom(16)
                self.fernet = self.make_fernet(entered, salt)
                self.records = []
                self.write_vault()
                self.write_json(SETTINGS_FILE, {"version": 2, "salt": urlsafe_b64encode(salt).decode("ascii")})
        except InvalidToken:
            messagebox.showerror("Доступ запрещён", "Неверный мастер-пароль или повреждён файл хранилища.")
            self.master_password.delete(0, tk.END)
            return
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
            messagebox.showerror("Ошибка", f"Не удалось открыть зашифрованное хранилище:\n{error}")
            return
        self.unlocked = True
        self.last_activity = self.tk.call("clock", "milliseconds")
        self.show_vault()
        self.schedule_auto_lock()

    def migrate_plaintext_vault(self, entered, settings):
        """Convert the previous plaintext format after verifying its password."""
        if entered != settings["master_password"]:
            raise InvalidToken
        records = self.read_json(VAULT_FILE)
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError("Invalid legacy record list")
        salt = os.urandom(16)
        fernet = self.make_fernet(entered, salt)
        self.records, self.fernet = records, fernet
        try:
            self.write_vault()
            self.write_json(SETTINGS_FILE, {"version": 2, "salt": urlsafe_b64encode(salt).decode("ascii")})
        except OSError:
            self.write_json(VAULT_FILE, records)
            raise
        messagebox.showinfo("Готово", "Существующие записи зашифрованы.")

    def show_vault(self):
        self.clear_window()
        self.geometry("880x540")
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=3); root.columnconfigure(1, weight=2); root.rowconfigure(2, weight=1)
        ttk.Label(root, text="vault@local:~$ passwords", style="Title.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        buttons = ttk.Frame(root); buttons.grid(row=0, column=1, sticky="e")
        for text, command in (("КЛЮЧ", self.change_master_password), ("LOCK", self.lock_now), ("+ НОВАЯ", self.new_record), ("УДАЛИТЬ", self.delete_record)):
            ttk.Button(buttons, text=text, command=command).pack(side="left", padx=3)
        search = ttk.Frame(root); search.grid(row=1, column=0, sticky="ew", padx=(0, 12), pady=(0, 8))
        ttk.Label(search, text="search >").pack(side="left")
        self.search_var = tk.StringVar(); self.search_var.trace_add("write", lambda *_: self.refresh_tree())
        self.search_entry = ttk.Entry(search, textvariable=self.search_var); self.search_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        list_frame = ttk.Frame(root); list_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 12)); list_frame.columnconfigure(0, weight=1); list_frame.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(list_frame, columns=("site", "login"), show="headings", selectmode="browse")
        self.tree.heading("site", text="Сайт / название"); self.tree.heading("login", text="Логин")
        self.tree.column("site", width=240); self.tree.column("login", width=170)
        bar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview); self.tree.configure(yscrollcommand=bar.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); bar.grid(row=0, column=1, sticky="ns"); self.tree.bind("<<TreeviewSelect>>", self.select_record)
        form = ttk.LabelFrame(root, text="Карточка", padding=12); form.grid(row=1, column=1, rowspan=2, sticky="nsew"); form.columnconfigure(1, weight=1)
        self.site_entry = self.form_field(form, "Сайт / название:", 0)
        self.url_entry = self.form_field(form, "URL:", 1); ttk.Button(form, text="Открыть", command=self.open_url).grid(row=1, column=2, padx=(5, 0))
        self.login_entry = self.form_field(form, "Логин:", 2)
        self.password_entry = self.form_field(form, "Пароль:", 3, show="*")
        self.show_password_button = ttk.Button(form, text="Показать", command=self.toggle_password); self.show_password_button.grid(row=3, column=2, padx=(5, 0))
        ttk.Button(form, text="Сгенерировать пароль", command=self.show_generator).grid(row=4, column=0, columnspan=3, sticky="ew", pady=(4, 3))
        ttk.Label(form, text="Заметка:").grid(row=5, column=0, sticky="nw", pady=5)
        self.notes = tk.Text(form, height=7, width=30, wrap="word", background="#050906", foreground=GREEN_SOFT, insertbackground=GREEN, selectbackground=GREEN_DARK, selectforeground="#ffffff", relief="solid", borderwidth=1, highlightthickness=1, highlightbackground=GREEN_DARK, highlightcolor=GREEN, font=(MONO_FONT, 10)); self.notes.grid(row=5, column=1, columnspan=2, sticky="nsew", pady=5)
        ttk.Button(form, text="Скопировать логин", command=lambda: self.copy_to_clipboard(self.login_entry.get(), "Логин")).grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 3))
        ttk.Button(form, text="Скопировать пароль", command=lambda: self.copy_to_clipboard(self.password_entry.get(), "Пароль")).grid(row=7, column=0, columnspan=3, sticky="ew", pady=3)
        ttk.Button(form, text="Сохранить", command=self.save_record).grid(row=8, column=0, columnspan=3, sticky="ew", pady=(3, 0))
        self.refresh_tree()

    def form_field(self, parent, label, row, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, show=show); entry.grid(row=row, column=1, sticky="ew", pady=5)
        return entry

    def refresh_tree(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        query = self.search_var.get().strip().casefold()
        for index, record in enumerate(self.records):
            site, login = record.get("site", ""), record.get("login", "")
            if not query or query in site.casefold() or query in login.casefold(): self.tree.insert("", "end", iid=str(index), values=(site, login))

    def select_record(self, _event=None):
        selected = self.tree.selection()
        if selected:
            self.selected_index = int(selected[0]); self.fill_form(self.records[self.selected_index])

    def fill_form(self, record):
        self.hide_password()
        for entry, key in ((self.site_entry, "site"), (self.url_entry, "url"), (self.login_entry, "login"), (self.password_entry, "password")):
            entry.delete(0, tk.END); entry.insert(0, record.get(key, ""))
        self.notes.delete("1.0", tk.END); self.notes.insert("1.0", record.get("notes", ""))

    def new_record(self, _event=None):
        self.selected_index = None; self.fill_form({}); self.site_entry.focus()
        return "break"

    def save_record(self, _event=None):
        site = self.site_entry.get().strip()
        if not site:
            messagebox.showwarning("Карточка", "Укажите сайт или название записи."); return "break"
        record = {"site": site, "url": self.url_entry.get().strip(), "login": self.login_entry.get().strip(), "password": self.password_entry.get(), "notes": self.notes.get("1.0", "end-1c").strip()}
        if self.selected_index is None: self.records.append(record)
        else: self.records[self.selected_index] = record
        try: self.write_vault()
        except OSError as error:
            messagebox.showerror("Ошибка сохранения", f"Не удалось сохранить запись:\n{error}"); return "break"
        self.refresh_tree(); self.new_record(); return "break"

    def delete_record(self):
        if self.selected_index is None:
            messagebox.showinfo("Удаление", "Сначала выберите запись."); return
        if not messagebox.askyesno("Удаление", "Удалить выбранную запись?"): return
        del self.records[self.selected_index]
        try: self.write_vault()
        except OSError as error:
            messagebox.showerror("Ошибка сохранения", f"Не удалось удалить запись:\n{error}"); return
        self.selected_index = None; self.refresh_tree(); self.new_record()

    def toggle_password(self):
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "*")
        self.show_password_button.configure(text="Скрыть" if self.password_visible else "Показать")

    def hide_password(self):
        self.password_visible = False
        if hasattr(self, "password_entry"): self.password_entry.configure(show="*")
        if hasattr(self, "show_password_button"): self.show_password_button.configure(text="Показать")

    def show_generator(self):
        dialog = tk.Toplevel(self); dialog.title("Генератор пароля"); dialog.resizable(False, False); dialog.transient(self); dialog.grab_set()
        frame = ttk.Frame(dialog, padding=18); frame.pack(fill="both", expand=True)
        length, upper, digits, symbols = tk.IntVar(value=16), tk.BooleanVar(value=True), tk.BooleanVar(value=True), tk.BooleanVar(value=True)
        ttk.Label(frame, text="Длина:").grid(row=0, column=0, sticky="w", pady=(0, 8)); ttk.Spinbox(frame, from_=4, to=128, textvariable=length, width=8).grid(row=0, column=1, sticky="w", pady=(0, 8))
        for row, text, variable in ((1, "Заглавные буквы (A–Z)", upper), (2, "Цифры (0–9)", digits), (3, "Символы (!@#...)", symbols)):
            ttk.Checkbutton(frame, text=text, variable=variable).grid(row=row, column=0, columnspan=2, sticky="w")
        def generate():
            try: size = length.get()
            except tk.TclError: size = 0
            groups = [string.ascii_lowercase] + ([string.ascii_uppercase] if upper.get() else []) + ([string.digits] if digits.get() else []) + (["!@#$%^&*_-+=?"] if symbols.get() else [])
            if not 4 <= size <= 128 or size < len(groups):
                messagebox.showwarning("Генератор", "Выберите длину от 4 до 128, достаточную для наборов символов.", parent=dialog); return
            alphabet = "".join(groups); result = [secrets.choice(group) for group in groups]
            result += [secrets.choice(alphabet) for _ in range(size - len(result))]; secrets.SystemRandom().shuffle(result)
            self.password_entry.delete(0, tk.END); self.password_entry.insert(0, "".join(result)); self.hide_password(); dialog.destroy()
        ttk.Button(frame, text="Сгенерировать", command=generate).grid(row=4, column=0, columnspan=2, sticky="ew", pady=(14, 0)); dialog.bind("<Return>", lambda _event: generate())

    def copy_to_clipboard(self, value, label):
        if not value:
            messagebox.showinfo("Буфер обмена", f"{label} пуст."); return
        if self.clipboard_clear_job: self.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear(); self.clipboard_append(value); self.update()
        self.clipboard_value = value; self.clipboard_clear_job = self.after(CLIPBOARD_CLEAR_MS, self.clear_clipboard_if_unchanged)
        messagebox.showinfo("Буфер обмена", f"{label} скопирован. Буфер будет очищен через 25 секунд.")

    def clear_clipboard_if_unchanged(self):
        try:
            if self.clipboard_get() == self.clipboard_value: self.clipboard_clear()
        except tk.TclError: pass
        self.clipboard_value = self.clipboard_clear_job = None

    def clear_our_clipboard(self):
        if self.clipboard_clear_job:
            self.after_cancel(self.clipboard_clear_job)
        self.clear_clipboard_if_unchanged()

    def open_url(self):
        url = self.url_entry.get().strip()
        if not url: messagebox.showinfo("URL", "Введите адрес сайта."); return
        url = url if "://" in url else f"https://{url}"
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            messagebox.showerror("URL", "Разрешены только корректные адреса http:// или https://.")
            return
        webbrowser.open_new_tab(url)

    def change_master_password(self):
        dialog = tk.Toplevel(self); dialog.title("Смена мастер-пароля"); dialog.resizable(False, False); dialog.transient(self); dialog.grab_set()
        frame = ttk.Frame(dialog, padding=18); frame.pack(fill="both", expand=True); entries = {}
        for row, (key, label) in enumerate((("current", "Текущий пароль:"), ("new", "Новый пароль:"), ("repeat", "Повторите новый:"))):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4); entries[key] = ttk.Entry(frame, width=30, show="*"); entries[key].grid(row=row, column=1, pady=4)
        def save_new():
            new = entries["new"].get()
            if not new: messagebox.showwarning("Пароль", "Новый пароль не может быть пустым.", parent=dialog); return
            if new != entries["repeat"].get(): messagebox.showerror("Пароль", "Новые пароли не совпадают.", parent=dialog); return
            try:
                settings = self.read_json(SETTINGS_FILE)
                old_salt = urlsafe_b64decode(settings["salt"].encode("ascii"))
                if settings.get("version") != 2:
                    raise ValueError("Unknown settings format")
                old_fernet = self.make_fernet(entries["current"].get(), old_salt)
                old_fernet.decrypt(self.encrypted_document(self.fernet, self.records)["ciphertext"].encode("ascii"))
            except InvalidToken:
                messagebox.showerror("Пароль", "Текущий пароль введён неверно.", parent=dialog); return
            except (OSError, KeyError, ValueError, json.JSONDecodeError):
                messagebox.showerror("Ошибка", "Не удалось прочитать настройки.", parent=dialog); return
            try:
                new_salt = os.urandom(16)
                new_fernet = self.make_fernet(new, new_salt)
                old_document = self.read_json(VAULT_FILE)
                self.write_json(VAULT_FILE, self.encrypted_document(new_fernet, self.records))
                self.write_json(SETTINGS_FILE, {"version": 2, "salt": urlsafe_b64encode(new_salt).decode("ascii")})
                self.fernet = new_fernet
            except OSError as error:
                try: self.write_json(VAULT_FILE, old_document)
                except (OSError, UnboundLocalError): pass
                messagebox.showerror("Ошибка", f"Не удалось сохранить настройки:\n{error}", parent=dialog); return
            dialog.destroy(); messagebox.showinfo("Готово", "Мастер-пароль изменён.")
        ttk.Button(frame, text="Сохранить", command=save_new).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0)); entries["current"].focus(); dialog.bind("<Return>", lambda _event: save_new())

    def record_activity(self, _event=None):
        if self.unlocked: self.last_activity = self.tk.call("clock", "milliseconds")

    def schedule_auto_lock(self): self.auto_lock_job = self.after(10_000, self.check_auto_lock)
    def check_auto_lock(self):
        if not self.unlocked: return
        if self.tk.call("clock", "milliseconds") - self.last_activity >= AUTO_LOCK_MS: self.lock_now(auto=True)
        else: self.schedule_auto_lock()
    def lock_now(self, auto=False):
        self.hide_password(); self.clear_our_clipboard(); self.records = []; self.selected_index = None; self.fernet = None; self.show_login()
        if auto: messagebox.showinfo("Автоблокировка", "Приложение заблокировано после 5 минут бездействия.")
    def focus_search(self, _event=None):
        if self.unlocked: self.search_entry.focus(); self.search_entry.select_range(0, tk.END)
        return "break"
    def hotkey_save(self, _event=None): return self.save_record() if self.unlocked else "break"
    def hotkey_new(self, _event=None): return self.new_record() if self.unlocked else "break"


if __name__ == "__main__":
    PasswordVault().mainloop()
