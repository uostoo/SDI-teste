import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress

def calcular():
    try:
        ip = ip_entry.get()
        mascara = mascara_entry.get().lstrip("/")
        rede = ipaddress.IPv4Network(f"{ip}/{mascara}", strict=False)

        endereco_rede = str(rede.network_address)
        primeiro_host = str(list(rede.hosts())[0])
        ultimo_host = str(list(rede.hosts())[-1])
        broadcast = str(rede.broadcast_address)
        classe = determinar_classe(ip)

        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            public_private = "Privado"
        else:
            public_private = "Público"

        prefixo_classe = {"A": 8, "B": 16, "C": 24}.get(classe, rede.prefixlen)  
        sub_redes = 2 ** (rede.prefixlen - prefixo_classe) if prefixo_classe < rede.prefixlen else 1
        hosts_por_rede = (2 ** (32 - rede.prefixlen)) - 2

        result_rede.config(text=endereco_rede)
        result_primeiro.config(text=primeiro_host)
        result_ultimo.config(text=ultimo_host)
        result_broadcast.config(text=broadcast)
        result_classe.config(text=classe)
        result_privado.config(text=public_private)
        result_subredes.config(text=sub_redes)
        result_hosts.config(text=hosts_por_rede)
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao calcular: {e}")


def determinar_classe(ip):
    primeiro_octeto = int(ip.split(".")[0])
    if 1 <= primeiro_octeto <= 127:
        return "A"
    elif 128 <= primeiro_octeto <= 191:
        return "B"
    elif 192 <= primeiro_octeto <= 223:
        return "C"
    else:
        return "Desconhecida"

def formatar_mascara(event):
    entrada = mascara_entry.get()
    entrada = ''.join(filter(str.isdigit, entrada))  
    mascara_entry.delete(0, tk.END)
    mascara_entry.insert(0, f"/{entrada[:2]}")  

root = tk.Tk()
root.title("Calculadora de Sub-redes")
root.geometry("480x580")
root.resizable(False, False)
root.configure(bg="#F2F4F3")  

style = ttk.Style()
style.theme_use("clam")

style.configure(
    "TLabel",
    font=("Segoe UI", 12),
    foreground="#2F4858",
    background="#F2F4F3"
)
style.configure(
    "TButton",
    font=("Segoe UI", 12, "bold"),
    foreground="#ffffff",
    background="#4AAD52",
    padding=10,
    borderwidth=0
)
style.map(
    "TButton",
    background=[("active", "#3A9341")],
    relief=[("pressed", "sunken")]
)
style.configure("TEntry", font=("Segoe UI", 12), padding=5)

title = tk.Label(
    root,
    text="Calculadora de Sub-redes",
    font=("Segoe UI", 18, "bold"),
    bg="#F2F4F3",
    fg="#2F4858"
)
title.pack(pady=20)

frame_inputs = tk.Frame(root, bg="#F2F4F3")
frame_inputs.pack(fill="x", padx=30, pady=5)

tk.Label(frame_inputs, text="Endereço IP:", bg="#F2F4F3", fg="#2F4858", font=("Segoe UI", 12)).grid(row=0, column=0, sticky="e", padx=5, pady=10)
ip_entry = ttk.Entry(frame_inputs)
ip_entry.grid(row=0, column=1, pady=10)

tk.Label(frame_inputs, text="Máscara de Sub-rede:", bg="#F2F4F3", fg="#2F4858", font=("Segoe UI", 12)).grid(row=1, column=0, sticky="e", padx=5, pady=10)
mascara_entry = ttk.Entry(frame_inputs)
mascara_entry.grid(row=1, column=1, pady=10)
mascara_entry.bind("<KeyRelease>", formatar_mascara)

ttk.Button(frame_inputs, text="Calcular", command=calcular).grid(row=2, column=0, columnspan=2, pady=8)

frame_results = tk.Frame(root, bg="#F2F4F3")
frame_results.pack(fill="x", padx=30, pady=10)

def criar_campo_resultado(frame, texto, row, cor="#2F4858"):
    tk.Label(frame, text=texto + ":", bg="#F2F4F3", fg=cor, font=("Segoe UI", 12)).grid(row=row, column=0, sticky="e", padx=5, pady=5)
    label = tk.Label(frame, text="", font=("Segoe UI", 12), bg="#F2F4F3", fg=cor, anchor="w")
    label.grid(row=row, column=1, sticky="w", padx=5, pady=5)
    return label

result_rede = criar_campo_resultado(frame_results, "Endereço de Rede", 0)
result_primeiro = criar_campo_resultado(frame_results, "Primeiro Host", 1)
result_ultimo = criar_campo_resultado(frame_results, "Último Host", 2)
result_broadcast = criar_campo_resultado(frame_results, "Endereço de Broadcast", 3)
result_classe = criar_campo_resultado(frame_results, "Classe do Endereço", 4)
result_privado = criar_campo_resultado(frame_results, "Endereço Público/Privado", 5)
result_subredes = criar_campo_resultado(frame_results, "Quantidade de Sub-redes", 6)
result_hosts = criar_campo_resultado(frame_results, "Hosts por Sub-rede", 7)

footer = tk.Label(
    root,
    text="Desenvolvido por uostoC",
    font=("Segoe UI", 10, "italic"),
    bg="#F2F4F3",
    fg="#2F4858"
)
footer.pack(side="bottom", pady=10)

root.mainloop()
