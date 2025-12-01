import tkinter as tk
from tkinter import messagebox
import os
# Imports the external logic files
import storage
import encryption
import password_logic


# ----------------------------- LOGIN SCREEN -----------------------------
def login_screen():
    win = tk.Tk()
    win.title("Master Access")
    win.geometry("450x300")
    win.configure(bg="#212121") 
    win.resizable(False, False)

    card = tk.Frame(
        win,
        bg="#333333",
        padx=35,
        pady=35,
        relief="groove", 
        bd=0
    )
    card.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(
        card,
        text="🔐 Master Password",
        font=("Arial", 20, "bold"),
        bg="#333333",
        fg="#E0E0E0"
    ).pack(pady=(5, 15))

    pwd_entry = tk.Entry(
        card,
        font=("Arial", 14),
        show="•",
        width=30,
        relief="flat",
        fg="#FFFFFF",
        bg="#424242",
        insertbackground="#FFFFFF",
        bd=2,
        highlightbackground="#D32F2F",
        highlightcolor="#D32F2F",
        highlightthickness=1
    )
    pwd_entry.pack(pady=10, ipady=6)
    
    btn_frame = tk.Frame(card, bg="#333333")
    btn_frame.pack(pady=15)

    def styled_btn(parent, text, cmd):
        return tk.Button(
            parent,
            text=text,
            font=("Arial", 12, "bold"),
            fg="white",
            bg="#D32F2F",
            activebackground="#A02222",
            cursor="hand2",
            relief="flat",
            width=20,
            height=1,
            command=cmd
        )

    if not storage.master_exists():

        def create_master():
            p = pwd_entry.get()
            if len(p) < 4:
                messagebox.showerror("Error", "Password must be at least 4 characters.")
                return
            storage.create_master_password(p)
            messagebox.showinfo("Success", "Master Password Created!\nRestart App.")
            win.destroy()

        styled_btn(btn_frame, "Create Password", create_master).pack()

    else:

        def unlock():
            p = pwd_entry.get()
            if storage.verify_master_password(p):
                win.destroy()
                main_app()
            else:
                messagebox.showerror("Error", "Wrong Password.")

        styled_btn(btn_frame, "Unlock", unlock).pack()
        win.bind('<Return>', lambda event: unlock())


    win.mainloop()


# ----------------------------- MAIN APP -----------------------------
def main_app():
    root = tk.Tk()
    root.title("SecurePass Manager")
    root.geometry("1000x600")
    root.configure(bg="#F5F5F5")

    sidebar = tk.Frame(root, width=220, bg="#212121")
    sidebar.pack(side="left", fill="y")
    
    tk.Label(
        sidebar,
        text="SecurePass",
        font=("Arial", 18, "bold"),
        fg="#D32F2F",
        bg="#212121"
    ).pack(pady=(30, 15))

    content = tk.Frame(root, bg="#FFFFFF")
    content.pack(side="right", fill="both", expand=True)

    def clear_content():
        for w in content.winfo_children():
            w.destroy()

    def sidebar_button(text, command):
        btn = tk.Button(
            sidebar,
            text=f"  {text}",
            anchor="w",
            font=("Arial", 14),
            fg="#CCCCCC",
            bg="#212121",
            activebackground="#3A3A3A",
            activeforeground="white",
            bd=0,
            height=2,
            relief="flat",
            command=command
        )
        btn.pack(fill="x", pady=2)

    # ---------------- DASHBOARD ----------------
    def page_dashboard():
        clear_content()

        tk.Label(
            content,
            text="Dashboard Overview",
            font=("Arial", 28, "bold"),
            bg="white",
            fg="#222222"
        ).pack(pady=(40, 20))

        total = len(storage.get_all_entries())

        box = tk.Frame(content, bg="#F0F0F0", bd=0, relief="flat")
        box.pack(pady=30, ipadx=40, ipady=30)

        tk.Label(
            box,
            text="Total Saved Entries:",
            font=("Arial", 16),
            bg="#F0F0F0",
            fg="#555555"
        ).pack()
        
        tk.Label(
            box,
            text=f"🔑 {total}",
            font=("Arial", 36, "bold"),
            bg="#F0F0F0",
            fg="#D32F2F"
        ).pack(pady=(5, 0))

    # ---------------- ADD NEW ----------------
    def page_add():
        clear_content()

        tk.Label(
            content,
            text="➕ Add New Password",
            font=("Arial", 28, "bold"),
            bg="white",
            fg="#222222"
        ).pack(pady=(40, 20))

        form_container = tk.Frame(content, bg="#FFFFFF", padx=30, pady=20, relief="flat")
        form_container.pack(pady=10)

        def create_input(text, parent):
            tk.Label(parent, text=text, font=("Arial", 13, "bold"), bg="white", fg="#444444").pack(pady=(10, 2), anchor="w")
            entry = tk.Entry(parent, width=45, font=("Arial", 14), bg="#F5F5F5", relief="flat", bd=2, insertbackground="#222")
            entry.pack(pady=3, ipady=4)
            return entry

        entry_website = create_input("Website/Service:", form_container)
        entry_username = create_input("Username/Email:", form_container)

        tk.Label(form_container, text="Password:", font=("Arial", 13, "bold"), bg="white", fg="#444444").pack(pady=(10, 2), anchor="w")

        pass_frame = tk.Frame(form_container, bg="white")
        pass_frame.pack()

        entry_password = tk.Entry(pass_frame, width=32, font=("Arial", 14), bg="#F5F5F5", relief="flat", bd=2, insertbackground="#222")
        entry_password.pack(side="left", padx=(0, 10), ipady=4)

        def copy_pwd():
            pwd = entry_password.get()
            if pwd == "":
                messagebox.showerror("Error", "No password to copy.")
                return
            root.clipboard_clear()
            root.clipboard_append(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        tk.Button(
            pass_frame,
            text="Copy",
            bg="#D32F2F",
            fg="white",
            font=("Arial", 11, "bold"),
            padx=10,
            relief="flat",
            activebackground="#A02222",
            command=copy_pwd
        ).pack(side="left")

        def generate_pwd():
            pwd = password_logic.generate_password(16) 
            entry_password.delete(0, tk.END)
            entry_password.insert(0, pwd)

        tk.Button(
            form_container,
            text="Generate Strong Password",
            bg="#3A3A3A",
            fg="white",
            font=("Arial", 12, "bold"),
            pady=8,
            relief="flat",
            activebackground="#555555",
            command=generate_pwd
        ).pack(pady=15, fill="x", ipadx=10)

        def save_password():
            website = entry_website.get().strip()
            username = entry_username.get().strip()
            password = entry_password.get().strip()

            if website == "" or username == "" or password == "":
                messagebox.showerror("Error", "All fields must be filled.")
                return

            enc = encryption.encrypt(password) 
            storage.add_entry(website, username, enc)
            messagebox.showinfo("Saved", "Password Saved Successfully!")
            
            entry_website.delete(0, tk.END)
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)

        tk.Button(
            form_container,
            text="Save Entry",
            bg="#1E88E5",
            fg="white",
            font=("Arial", 14, "bold"),
            padx=30,
            pady=8,
            relief="flat",
            activebackground="#1565C0",
            command=save_password
        ).pack(pady=(20, 10), fill="x")

    # ---------------- VIEW PASSWORDS ----------------
    def page_passwords():
        clear_content()

        tk.Label(
            content,
            text="👁️ Saved Passwords",
            font=("Arial", 28, "bold"),
            bg="white",
            fg="#222222"
        ).pack(pady=(40, 20))

        list_frame = tk.Frame(content)
        list_frame.pack(pady=10)

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL)
        
        listbox = tk.Listbox(
            list_frame,
            width=80,
            height=14,
            font=("Courier New", 12),
            bg="#FFFFFF",
            fg="#222222",
            relief="flat",
            bd=2,
            selectbackground="#D32F2F",
            selectforeground="white",
            yscrollcommand=scrollbar.set
        )
        listbox.pack(side="left", fill="y", padx=(0, 5))
        scrollbar.config(command=listbox.yview)
        scrollbar.pack(side="right", fill="y")
        
        data = storage.get_all_entries()

        header = f" {'ID':<5} | {'WEBSITE':<20} | {'USERNAME':<25} | PASSWORD"
        listbox.insert(tk.END, header)
        listbox.insert(tk.END, "-" * 75)
        
        for item in data:
            dec = encryption.decrypt(item["password"])
            text = f" {item['id']:<5} | {item['website']:<20} | {item['username']:<25} | {dec}"
            listbox.insert(tk.END, text)

        def delete_selected():
            sel = listbox.curselection()
            if not sel or sel[0] < 2:
                messagebox.showerror("Error", "Select a valid entry to delete.")
                return

            selected_line = listbox.get(sel[0])
            try:
                entry_id = selected_line.strip().split("|")[0].strip() 
                
                if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete entry ID {entry_id}?"):
                    storage.delete_entry(entry_id)
                    messagebox.showinfo("Deleted", f"Entry ID {entry_id} deleted.")
                    page_passwords()
            except IndexError:
                 messagebox.showerror("Error", "Could not parse entry ID.")


        tk.Button(
            content,
            text="🗑️ Delete Selected Entry",
            bg="#D32F2F",
            fg="white",
            font=("Arial", 13, "bold"),
            padx=15,
            pady=8,
            relief="flat",
            activebackground="#A02222",
            command=delete_selected
        ).pack(pady=20)

    # ---------------- SIDEBAR BUTTONS ----------------
    sidebar_button("🏠 Dashboard", page_dashboard)
    sidebar_button("➕ Add New", page_add)
    sidebar_button("🔑 View Passwords", page_passwords)

    page_dashboard()
    root.mainloop()


# ----------------------------- RUN APP -----------------------------
login_screen()