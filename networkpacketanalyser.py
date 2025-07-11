import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import time
import os
from datetime import datetime

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Network Packet Analyzer")
        self.root.geometry("800x600")
        self.root.configure(bg="#1e1e1e")
        self.sniffing = False
        self.auto_save_file = None

        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.root, text="Network Packet Analyzer", font=("Helvetica", 20, "bold"),
                         bg="#1e1e1e", fg="#61dafb")
        title.pack(pady=10)

        control_frame = tk.Frame(self.root, bg="#1e1e1e")
        control_frame.pack(pady=5)

        tk.Label(control_frame, text="Protocol Filter:", bg="#1e1e1e", fg="white").grid(row=0, column=0, padx=5)
        self.protocol_var = tk.StringVar(value="ALL")
        protocol_menu = ttk.Combobox(control_frame, textvariable=self.protocol_var,
                                     values=["ALL", "TCP", "UDP"], width=10, state="readonly")
        protocol_menu.grid(row=0, column=1, padx=5)

        self.start_btn = tk.Button(control_frame, text="▶ Start Sniffing", bg="#28a745", fg="white",
                                   font=("Helvetica", 10, "bold"), command=self.start_sniffing)
        self.start_btn.grid(row=0, column=2, padx=10)

        self.stop_btn = tk.Button(control_frame, text="■ Stop", bg="#dc3545", fg="white",
                                  font=("Helvetica", 10, "bold"), command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=3, padx=5)

        self.save_btn = tk.Button(control_frame, text="💾 Save Log", command=self.save_log, state=tk.DISABLED)
        self.save_btn.grid(row=0, column=4, padx=5)

        self.output_area = scrolledtext.ScrolledText(self.root, bg="#2d2d2d", fg="#dcdcdc",
                                                     font=("Consolas", 11), wrap=tk.WORD)
        self.output_area.pack(expand=True, fill="both", padx=10, pady=10)
        self.output_area.config(state=tk.DISABLED)

    def update_output(self, text):
        self.output_area.config(state=tk.NORMAL)
        self.output_area.insert(tk.END, text + "\n")
        self.output_area.see(tk.END)
        self.output_area.config(state=tk.DISABLED)

        # Auto-save to file
        if self.auto_save_file:
            try:
                with open(self.auto_save_file, "a", encoding="utf-8") as f:
                    f.write(text + "\n")
            except Exception as e:
                print(f"Auto-save error: {e}")

    def packet_callback(self, packet):
        if IP in packet:
            proto = "OTHER"
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"

            filter_proto = self.protocol_var.get()
            if filter_proto != "ALL" and proto != filter_proto:
                return

            ip_layer = packet[IP]
            payload = str(bytes(packet.payload))[:100]

            text = (f"[{time.strftime('%H:%M:%S')}] {proto} Packet:\n"
                    f"  From: {ip_layer.src}  ->  To: {ip_layer.dst}\n"
                    f"  Payload: {payload}...\n")
            self.root.after(0, self.update_output, text)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda _: not self.sniffing, store=0)

    def start_sniffing(self):
        self.output_area.config(state=tk.NORMAL)
        self.output_area.delete('1.0', tk.END)
        self.output_area.insert(tk.END, "[✓] Packet sniffing started...\n")
        self.output_area.config(state=tk.DISABLED)

        # Set up auto-save filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.auto_save_file = os.path.join(os.getcwd(), f"packets_{timestamp}.txt")

        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.DISABLED)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.NORMAL)
        self.update_output("[✖] Sniffing stopped.")

    def save_log(self):
        content = self.output_area.get('1.0', tk.END).strip()
        if content:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt")])
            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    messagebox.showinfo("Saved", "Log saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file:\n{e}")
        else:
            messagebox.showwarning("Empty", "No data to save.")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
