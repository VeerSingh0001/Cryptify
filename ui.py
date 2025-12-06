import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import oqs
import gc
import sys
import os
from pathlib import Path

from PIL import Image

# --- Import Logic Classes ---
from decryption import MLKEMDecryptor
from encryption import MLKEMCrypto
from key_manager import KeyManager
from utils import _to_bytearray, secure_erase

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


class ConsoleRedirector:
    """Redirects stdout/stderr to a text widget. Thread-Safe."""

    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.lock = threading.Lock()

    def write(self, str_val):
        with self.lock:
            try:
                self.text_widget.configure(state="normal")
                self.text_widget.insert("end", str_val)
                self.text_widget.see("end")
                self.text_widget.configure(state="disabled")
            except:
                pass

    def flush(self):
        sys.__stdout__.flush()


class MLKEMGui(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CRYPTIFY - Lock it down")
        self.geometry("1100x800")

        # Initialize Logic Classes
        self.km = KeyManager()
        self.crypto = MLKEMCrypto()
        self.decryptor = MLKEMDecryptor()

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_area()
        self.setup_console()

        self.show_frame("home")

    def setup_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(12, weight=1)

        logo_img = ctk.CTkImage(light_image=Image.open("logo.png"),
                                dark_image=Image.open("logo.png"),
                                size=(100, 50))  # Change (Width, Height) as needed

        # Create the label with the image
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="", image=logo_img)
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        buttons = [
            ("Generate Keypair", self.view_generate),
            ("Export Public Key", self.view_export),
            ("Import Public Key", self.view_import),
            ("Encrypt File(s)", self.view_encrypt_unified),  # MERGED BUTTON
            ("Decrypt File(s)", self.view_decrypt),
            ("Delete My Key", self.view_delete_key),
            ("Delete Recipient", self.view_delete_recipient),
        ]

        for i, (text, command) in enumerate(buttons, start=1):
            btn = ctk.CTkButton(self.sidebar_frame, text=text, command=command,
                                fg_color="transparent", text_color=("gray10", "#DCE4EE"),
                                anchor="w", hover_color=("gray70", "gray30"))
            btn.grid(row=i, column=0, padx=20, pady=5, sticky="ew")

        self.exit_btn = ctk.CTkButton(self.sidebar_frame, text="Exit", command=self.quit_app,
                                      fg_color="#A83232", hover_color="#821D1D")
        self.exit_btn.grid(row=13, column=0, padx=20, pady=20, sticky="s")

    def setup_main_area(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=10)
        self.grid_rowconfigure(0, weight=3)

    def setup_console(self):
        self.console_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("gray85", "gray17"))
        self.console_frame.grid(row=1, column=1, sticky="nsew", padx=20, pady=(0, 20))
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(self.console_frame, text="System Log / Output:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(5, 0))

        self.log_box = ctk.CTkTextbox(self.console_frame, font=("Consolas", 12))
        self.log_box.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_box.configure(state="disabled")

        self.redirector = ConsoleRedirector(self.log_box)
        sys.stdout = self.redirector
        sys.stderr = self.redirector

    def clear_console(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("0.0", "end")
        self.log_box.configure(state="disabled")

    def quit_app(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        self.quit()

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # ========================== VIEWS ==========================

    def show_frame(self, view_name):
        self.clear_frame()
        self.clear_console()

    def view_generate(self):
        self.show_frame("generate")
        self._header("Generate New Keypair")
        self._entry("key_id", "Enter Key ID")
        self._entry("password", "Set Password", show="*")

        def _run():
            kid = self.entries["key_id"].get().strip()
            pwd = self.entries["password"].get()
            if not kid or len(pwd) < 8:
                messagebox.showerror("Error", "Check ID/Password")
                return

            def _thread():
                try:
                    print(f"[*] Generating {kid}...")
                    with oqs.KeyEncapsulation("Kyber768") as kem:
                        pk = kem.generate_keypair()
                        sk = kem.export_secret_key()
                    path = self.km.save_keypair(pk, sk, kid, pwd)
                    secure_erase(_to_bytearray(sk))
                    print(f"[+] Saved: {path}")
                    messagebox.showinfo("Success", f"Generated: {path}")
                except Exception as e:
                    print(f"[!] Error: {e}")

            threading.Thread(target=_thread).start()

        ctk.CTkButton(self.main_frame, text="Generate Keypair", command=_run, fg_color="#2CC985").pack(pady=20, fill="x", padx=100)

    def view_export(self):
        self.show_frame("export")
        self._header("Export Public Key")
        my_keys = [k['id'] for k in self.km.list_keys()]
        ctk.CTkLabel(self.main_frame, text="Select Key ID:", anchor="w").pack(fill="x", padx=50)
        self.export_key_combo = ctk.CTkComboBox(self.main_frame, values=my_keys)
        self.export_key_combo.pack(fill="x", padx=50, pady=5)
        self._entry("password", "Key Password", show="*")
        self._entry("outfile", "Output Filename (Optional)")

        def _run():
            kid = self.export_key_combo.get().strip()
            pwd = self.entries["password"].get()
            out = self.entries["outfile"].get().strip()
            if not out: out = f"{kid}_public.json"
            threading.Thread(target=lambda: self._thread_export(kid, pwd, out)).start()

        ctk.CTkButton(self.main_frame, text="Export Key", command=_run).pack(pady=20)

    def _thread_export(self, kid, pwd, out):
        try:
            path = self.km.export_public_key(kid, pwd, out)
            print(f"[+] Exported: {path}")
            messagebox.showinfo("Success", f"Exported: {path}")
        except Exception as e:
            print(f"[!] Error: {e}")

    def view_import(self):
        self.show_frame("import")
        self._header("Import Recipient Key")
        self._file_picker("pub_file", "Select Public Key (.json)")
        self._entry("recip_name", "Recipient Name")

        def _run():
            fpath = self.entries["pub_file"].get().strip()
            name = self.entries["recip_name"].get().strip()
            if not Path(fpath).exists(): return
            threading.Thread(target=lambda: self._thread_import(fpath, name)).start()

        ctk.CTkButton(self.main_frame, text="Import Key", command=_run).pack(pady=20)

    def _thread_import(self, fpath, name):
        try:
            self.km.import_public_key(fpath, name)
            print(f"[+] Imported: {name}")
            messagebox.showinfo("Success", f"Imported: {name}")
        except Exception as e:
            print(f"[!] Error: {e}")

    # --- UNIFIED ENCRYPT VIEW ---
    def view_encrypt_unified(self):
        self.show_frame("encrypt_unified")
        self._header("Batch Encrypt Files")

        # 1. Mode Selection
        ctk.CTkLabel(self.main_frame, text="Encryption Mode:", anchor="w").pack(fill="x", padx=50)
        self.enc_mode_combo = ctk.CTkComboBox(self.main_frame, values=["Encrypt for Self", "Encrypt for Recipient"], command=self._update_enc_ui)
        self.enc_mode_combo.pack(fill="x", padx=50, pady=(0, 15))
        self.enc_mode_combo.set("Encrypt for Self")  # Default

        # 2. Dynamic Input Frame (Holds Key/Pwd or Recipient)
        self.dynamic_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.dynamic_frame.pack(fill="x", padx=0, pady=0)

        # 3. File Inputs (Common)
        self._file_picker("input_file", "Select File(s)")
        self._entry("output_file", "Output Filename (Single file only)")

        # 4. Action Button
        ctk.CTkButton(self.main_frame, text="Start Encryption", command=self.action_encrypt_dispatch, fg_color="#3B8ED0").pack(pady=20)

        # Initialize the dynamic part
        self._update_enc_ui("Encrypt for Self")

    def _update_enc_ui(self, choice):
        """Swaps widgets based on dropdown selection."""
        # Clear previous dynamic widgets
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()

        if choice == "Encrypt for Self":
            # Show My Key ID + Password
            my_keys = [k['id'] for k in self.km.list_keys()]
            ctk.CTkLabel(self.dynamic_frame, text="Select Your Key ID:", anchor="w").pack(fill="x", padx=50)
            self.enc_key_combo = ctk.CTkComboBox(self.dynamic_frame, values=my_keys)
            self.enc_key_combo.pack(fill="x", padx=50, pady=5)

            ctk.CTkLabel(self.dynamic_frame, text="Key Password:", anchor="w").pack(fill="x", padx=50)
            self.enc_pwd_entry = ctk.CTkEntry(self.dynamic_frame, placeholder_text="Password", show="*")
            self.enc_pwd_entry.pack(fill="x", padx=50, pady=5)

        else:  # Encrypt for Recipient
            # Show Recipient List
            recipients = [r['recipient'] for r in self.km.list_public_keys()]
            ctk.CTkLabel(self.dynamic_frame, text="Select Recipient:", anchor="w").pack(fill="x", padx=50)
            self.enc_recip_combo = ctk.CTkComboBox(self.dynamic_frame, values=recipients)
            self.enc_recip_combo.pack(fill="x", padx=50, pady=5)

    def view_decrypt(self):
        self.show_frame("decrypt")
        self._header("Batch Decrypt")
        self._file_picker("input_file", "Select Encrypted File(s)")
        my_keys = [k['id'] for k in self.km.list_keys()]
        ctk.CTkLabel(self.main_frame, text="Select Your Key ID:", anchor="w").pack(fill="x", padx=50)
        self.decrypt_key_combo = ctk.CTkComboBox(self.main_frame, values=my_keys)
        self.decrypt_key_combo.pack(fill="x", padx=50, pady=5)
        self._entry("password", "Key Password", show="*")
        self._entry("output_file", "Output Filename (Single file only)")

        ctk.CTkButton(self.main_frame, text="Decrypt Files", command=self.action_decrypt, fg_color="#E04F5F").pack(pady=20)

    def view_delete_key(self):
        self.show_frame("del_key")
        self._header("Delete Personal Key")
        keys = [k['id'] for k in self.km.list_keys()]
        ctk.CTkLabel(self.main_frame, text="Select Key ID:", anchor="w").pack(fill="x", padx=50)
        self.del_key_combo = ctk.CTkComboBox(self.main_frame, values=keys)
        self.del_key_combo.pack(fill="x", padx=50, pady=5)

        def _run():
            kid = self.del_key_combo.get()
            if kid and messagebox.askyesno("Confirm", f"Delete {kid}?"):
                if self.km.delete_keypair(kid):
                    print("[+] Deleted")
                    self.view_delete_key()
                else:
                    messagebox.showerror("Error", "Not Found")

        ctk.CTkButton(self.main_frame, text="DELETE", command=_run, fg_color="#A83232").pack(pady=20)

    def view_delete_recipient(self):
        self.show_frame("del_recip")
        self._header("Delete Recipient Key")
        keys = [k['recipient'] for k in self.km.list_public_keys()]
        ctk.CTkLabel(self.main_frame, text="Select Recipient:", anchor="w").pack(fill="x", padx=50)
        self.del_recip_combo = ctk.CTkComboBox(self.main_frame, values=keys)
        self.del_recip_combo.pack(fill="x", padx=50, pady=5)

        def _run():
            name = self.del_recip_combo.get()
            if name and messagebox.askyesno("Confirm", f"Delete {name}?"):
                if self.km.delete_public_key(name):
                    print("[+] Deleted")
                    self.view_delete_recipient()
                else:
                    messagebox.showerror("Error", "Not Found")

        ctk.CTkButton(self.main_frame, text="DELETE", command=_run, fg_color="#A83232").pack(pady=20)

    # ========================== ACTIONS (DISPATCHER) ==========================

    def action_encrypt_dispatch(self):
        """Decides which encryption logic to run based on the dropdown."""
        mode = self.enc_mode_combo.get()
        if mode == "Encrypt for Self":
            self._run_enc_self()
        else:
            self._run_enc_recip()

    def _run_enc_self(self):
        # Gather inputs from dynamic fields
        try:
            kid = self.enc_key_combo.get().strip()
            pwd = self.enc_pwd_entry.get()
        except AttributeError:
            messagebox.showerror("Error", "Please select a key.")
            return

        raw = self.entries["input_file"].get().strip()
        user_out = self.entries["output_file"].get().strip()
        if not raw:
            messagebox.showerror("Error", "No files selected.")
            return

        infiles = [f.strip() for f in raw.split(" ; ") if f.strip()]
        total = len(infiles)

        def _thread():
            try:
                print(f"[*] Loading Key: {kid}...")
                public_key, _ = self.km.load_keypair(kid, pwd)

                print(f"[*] Processing {total} file(s) for SELF...")
                success = 0

                for idx, infile in enumerate(infiles, 1):
                    try:
                        p_in = Path(infile)
                        if not p_in.exists(): continue

                        enc_dir = p_in.parent / "encrypted_files"
                        enc_dir.mkdir(parents=True, exist_ok=True)

                        if total == 1 and user_out:
                            outfile = str(enc_dir / user_out)
                        else:
                            outfile = str(enc_dir / (p_in.name + ".enc"))

                        print(f"[{idx}/{total}] Encrypting {p_in.name}...")
                        pkg = self.crypto.encrypt_data_for_self(infile, outfile, public_key)
                        pkg['recipient'] = 'self'
                        pkg['for_key_id'] = kid
                        self.crypto.reencrypt_data(data=pkg, key=public_key, outfile=outfile)

                        gc.collect()
                        print(f"   -> Saved: {Path(outfile).name}")
                        success += 1
                    except Exception as e:
                        print(f"[!] Failed {p_in.name}: {e}")

                print(f"[*] Finished. Success: {success}/{total}")
                messagebox.showinfo("Done", f"Processed {success}/{total} files.")

            except Exception as e:
                print(f"[!] Critical Error: {e}")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=_thread).start()

    def _run_enc_recip(self):
        try:
            name = self.enc_recip_combo.get().strip()
        except AttributeError:
            messagebox.showerror("Error", "Please select a recipient.")
            return

        raw = self.entries["input_file"].get().strip()
        user_out = self.entries["output_file"].get().strip()
        if not raw:
            messagebox.showerror("Error", "No files selected.")
            return

        infiles = [f.strip() for f in raw.split(" ; ") if f.strip()]
        total = len(infiles)

        def _thread():
            try:
                print(f"[*] Loading Public Key: {name}...")
                public_key = self.km.get_public_key(name)

                print(f"[*] Processing {total} file(s) for RECIPIENT...")
                success = 0

                for idx, infile in enumerate(infiles, 1):
                    try:
                        p_in = Path(infile)
                        if not p_in.exists(): continue

                        enc_dir = p_in.parent / "encrypted_files"
                        enc_dir.mkdir(parents=True, exist_ok=True)

                        if total == 1 and user_out:
                            outfile = str(enc_dir / user_out)
                        else:
                            outfile = str(enc_dir / (p_in.name + ".enc"))

                        print(f"[{idx}/{total}] Encrypting {p_in.name}...")
                        pkg = self.crypto.encrypt_data_for_recipient(infile, public_key)
                        pkg['recipient'] = name
                        self.crypto.reencrypt_data(data=pkg, key=public_key, outfile=outfile)

                        gc.collect()
                        print(f"   -> Saved: {Path(outfile).name}")
                        success += 1
                    except Exception as e:
                        print(f"[!] Failed {p_in.name}: {e}")

                print(f"[*] Finished. Success: {success}/{total}")
                messagebox.showinfo("Done", f"Processed {success}/{total} files.")

            except Exception as e:
                print(f"[!] Error: {e}")

        threading.Thread(target=_thread).start()

    def action_decrypt(self):
        kid = self.decrypt_key_combo.get().strip()
        pwd = self.entries["password"].get()
        raw = self.entries["input_file"].get().strip()
        user_out = self.entries["output_file"].get().strip()
        if not raw: return

        infiles = [f.strip() for f in raw.split(" ; ") if f.strip()]
        total = len(infiles)

        def _run_sequential():
            try:
                print(f"[*] Loading Private Key: {kid}...")
                public_key, secret_key = self.km.load_keypair(kid, pwd)

                print(f"[*] Processing {total} file(s) sequentially...")
                success = 0

                for idx, infile in enumerate(infiles, 1):
                    try:
                        p_in = Path(infile)
                        if not p_in.exists(): continue

                        # Create Decrypted Folder
                        dec_dir = p_in.parent / "decrypted_files"
                        dec_dir.mkdir(parents=True, exist_ok=True)

                        # Determine Output Name
                        if total == 1 and user_out:
                            outfile = str(dec_dir / user_out)
                        else:
                            fname = p_in.name.replace(".enc", "")
                            if fname == p_in.name: fname += ".dec"
                            outfile = str(dec_dir / fname)

                        print(f"[{idx}/{total}] Decrypting {p_in.name}...")
                        pkg = self.decryptor.decrypt_file(infile, public_key)
                        self.decryptor.decrypt_package(pkg, infile, outfile, secret_key)

                        gc.collect()
                        print(f"   -> Restored: {Path(outfile).name}")
                        success += 1
                    except Exception as e:
                        print(f"[!] Failed {p_in.name}: {e}")

                secure_erase(_to_bytearray(secret_key))
                print(f"[*] Finished. Success: {success}/{total}")
                messagebox.showinfo("Done", f"Processed {success}/{total} files.")

            except Exception as e:
                print(f"[!] Decrypt Init Error: {e}")
                messagebox.showerror("Error", str(e))

        threading.Thread(target=_run_sequential).start()

    # --- HELPERS ---
    def _header(self, text):
        ctk.CTkLabel(self.main_frame, text=text, font=("Arial", 24, "bold")).pack(pady=(10, 30))
        self.entries = {}

    def _entry(self, key, placeholder, show=None):
        ctk.CTkLabel(self.main_frame, text=placeholder + ":", anchor="w").pack(fill="x", padx=50)
        e = ctk.CTkEntry(self.main_frame, placeholder_text=placeholder, show=show)
        e.pack(fill="x", padx=50, pady=5)
        self.entries[key] = e
        return e

    def _file_picker(self, key, placeholder):
        f = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        f.pack(fill="x", padx=50, pady=10)
        e = ctk.CTkEntry(f, placeholder_text=placeholder)
        e.pack(side="left", fill="x", expand=True, padx=(0, 10))

        def pick():
            fs = filedialog.askopenfilenames()
            if fs:
                e.delete(0, "end")
                e.insert(0, " ; ".join(fs))

        ctk.CTkButton(f, text="Browse", width=80, command=pick, fg_color="#E59400").pack(side="right")
        self.entries[key] = e


if __name__ == "__main__":
    if not hasattr(oqs, 'KeyEncapsulation'):
        print("ERROR: liboqs-python not installed.")
        sys.exit(1)
    app = MLKEMGui()
    app.mainloop()