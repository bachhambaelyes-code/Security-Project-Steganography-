import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import hashlib
from datetime import datetime
import numpy as np
from math import log2

class HidyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hidy - Secure Image Steganography")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Modern color scheme
        self.bg_color = "#2d2d2d"
        self.fg_color = "#ffffff"
        self.accent_color = "#4e8cff"
        self.secondary_color = "#3d3d3d"
        self.success_color = "#4CAF50"
        self.warning_color = "#FF9800"
        self.error_color = "#F44336"
        
        # Configure root window
        self.root.configure(bg=self.bg_color)
        
        # Style configuration
        self.setup_styles()
        
        # Variables
        self.input_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.secret_message = tk.StringVar()
        self.decoded_message = tk.StringVar()
        self.encode_password = tk.StringVar()
        self.decode_password = tk.StringVar()
        self.detect_image_path = tk.StringVar()
        self.detection_results = tk.StringVar()
        self.auto_save = tk.BooleanVar(value=True)
        
        # Create GUI elements
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background=self.bg_color, foreground=self.fg_color)
        
        # Button styles
        style.configure('TButton', 
                       background=self.accent_color,
                       foreground=self.fg_color,
                       borderwidth=1,
                       focusthickness=3,
                       focuscolor='none',
                       font=('Segoe UI', 10),
                       padding=6)
        style.map('TButton',
                background=[('active', self.accent_color), ('pressed', '#3a6fd5')])
        
        # Entry styles
        style.configure('TEntry',
                      fieldbackground=self.secondary_color,
                      foreground=self.fg_color,
                      insertcolor=self.fg_color,
                      borderwidth=1,
                      relief='flat',
                      padding=5)
        
        # Label styles
        style.configure('TLabel',
                      background=self.bg_color,
                      foreground=self.fg_color,
                      font=('Segoe UI', 9))
        
        # Notebook styles
        style.configure('TNotebook',
                      background=self.bg_color,
                      borderwidth=0)
        style.configure('TNotebook.Tab',
                      background=self.secondary_color,
                      foreground=self.fg_color,
                      padding=[10, 5],
                      font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                background=[('selected', self.accent_color)],
                foreground=[('selected', self.fg_color)])
        
        # Frame styles
        style.configure('TLabelframe',
                      background=self.bg_color,
                      foreground=self.fg_color,
                      borderwidth=1,
                      relief='flat')
        style.configure('TLabelframe.Label',
                      background=self.bg_color,
                      foreground=self.accent_color)
        
        # Checkbutton styles
        style.configure('TCheckbutton',
                      background=self.bg_color,
                      foreground=self.fg_color,
                      indicatorbackground=self.secondary_color,
                      indicatormargin=3)
        style.map('TCheckbutton',
                indicatorbackground=[('selected', self.accent_color)])

    def create_widgets(self):
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # App title
        title_label = ttk.Label(header_frame, 
                              text="Hidy", 
                              font=('Segoe UI', 20, 'bold'),
                              foreground=self.accent_color)
        title_label.pack(side=tk.LEFT)
        
        # Subtitle
        subtitle_label = ttk.Label(header_frame,
                                 text="Secure Image Steganography Tool",
                                 font=('Segoe UI', 10),
                                 foreground="#aaaaaa")
        subtitle_label.pack(side=tk.LEFT, padx=10, pady=(5, 0))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Encode Tab
        self.encode_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encode_tab, text="  Encode  ")
        self.create_encode_tab()
        
        # Decode Tab
        self.decode_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.decode_tab, text="  Decode  ")
        self.create_decode_tab()
        
        # Detect Tab
        self.detect_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.detect_tab, text="  Detect  ")
        self.create_detect_tab()
        
        # About Tab
        self.about_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.about_tab, text="  About  ")
        self.create_about_tab()

    def create_encode_tab(self):
        # Main content frame
        content_frame = ttk.Frame(self.encode_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel (form)
        left_panel = ttk.Frame(content_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        # Input Image Selection
        input_frame = ttk.Frame(left_panel)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Input Image", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        
        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, pady=2)
        
        ttk.Entry(input_entry_frame, textvariable=self.input_image_path, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(input_entry_frame, text="Browse", command=self.browse_input_image, style='Accent.TButton').pack(side=tk.LEFT, padx=(5, 0))
        
        # Secret Message
        message_frame = ttk.Frame(left_panel)
        message_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(message_frame, text="Secret Message", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        ttk.Entry(message_frame, textvariable=self.secret_message).pack(fill=tk.X, pady=2)
        
        # Password Protection
        password_frame = ttk.Frame(left_panel)
        password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_frame, text="Password (optional)", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        ttk.Entry(password_frame, textvariable=self.encode_password, show="•").pack(fill=tk.X, pady=2)
        
        # Save options
        save_frame = ttk.LabelFrame(left_panel, text="Save Options", padding=10)
        save_frame.pack(fill=tk.X, pady=10)
        
        ttk.Checkbutton(save_frame, 
                       text="Auto-save to Downloads folder",
                       variable=self.auto_save,
                       command=self.toggle_save_options).pack(anchor=tk.W)
        
        self.manual_save_frame = ttk.Frame(save_frame)
        ttk.Label(self.manual_save_frame, text="Custom save location:").pack(anchor=tk.W)
        
        manual_entry_frame = ttk.Frame(self.manual_save_frame)
        manual_entry_frame.pack(fill=tk.X, pady=2)
        
        ttk.Entry(manual_entry_frame, textvariable=self.output_image_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(manual_entry_frame, text="Browse", command=self.browse_output_image).pack(side=tk.LEFT, padx=(5, 0))
        
        # Encode Button
        encode_btn = ttk.Button(left_panel, 
                              text="Encode Message", 
                              command=self.encode_message,
                              style='Accent.TButton')
        encode_btn.pack(fill=tk.X, pady=(10, 0))
        
        # Right panel (preview)
        right_panel = ttk.LabelFrame(content_frame, text="Image Preview", padding=10)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.preview_frame = ttk.Frame(right_panel)
        self.preview_frame.pack(fill=tk.BOTH, expand=True)
        
        # Initialize save options
        self.toggle_save_options()

    def create_decode_tab(self):
        # Main content frame
        content_frame = ttk.Frame(self.decode_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel (form)
        left_panel = ttk.Frame(content_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        # Input Image Selection
        input_frame = ttk.Frame(left_panel)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Encoded Image", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        
        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, pady=2)
        
        ttk.Entry(input_entry_frame, textvariable=self.input_image_path, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(input_entry_frame, text="Browse", command=self.browse_input_image, style='Accent.TButton').pack(side=tk.LEFT, padx=(5, 0))
        
        # Password Protection
        password_frame = ttk.Frame(left_panel)
        password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_frame, text="Password (if used)", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        ttk.Entry(password_frame, textvariable=self.decode_password, show="•").pack(fill=tk.X, pady=2)
        
        # Decoded Message
        message_frame = ttk.Frame(left_panel)
        message_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(message_frame, text="Decoded Message", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        
        message_entry_frame = ttk.Frame(message_frame)
        message_entry_frame.pack(fill=tk.X, pady=2)
        
        ttk.Entry(message_entry_frame, textvariable=self.decoded_message, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(message_entry_frame, text="Copy", command=self.copy_decoded_message).pack(side=tk.LEFT, padx=(5, 0))
        
        # Decode Button
        decode_btn = ttk.Button(left_panel, 
                              text="Decode Message", 
                              command=self.decode_message,
                              style='Accent.TButton')
        decode_btn.pack(fill=tk.X, pady=(10, 0))
        
        # Right panel (preview)
        right_panel = ttk.LabelFrame(content_frame, text="Image Preview", padding=10)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.decode_preview_frame = ttk.Frame(right_panel)
        self.decode_preview_frame.pack(fill=tk.BOTH, expand=True)

    def create_detect_tab(self):
        # Main content frame
        content_frame = ttk.Frame(self.detect_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel (form)
        left_panel = ttk.Frame(content_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        
        # Image Selection
        input_frame = ttk.Frame(left_panel)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Image to Analyze", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        
        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, pady=2)
        
        ttk.Entry(input_entry_frame, textvariable=self.detect_image_path, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(input_entry_frame, text="Browse", command=self.browse_detect_image, style='Accent.TButton').pack(side=tk.LEFT, padx=(5, 0))
        
        # Analyze Button
        analyze_btn = ttk.Button(left_panel, 
                               text="Analyze Image", 
                               command=self.analyze_image,
                               style='Accent.TButton')
        analyze_btn.pack(fill=tk.X, pady=(10, 0))
        
        # Results Frame
        results_frame = ttk.LabelFrame(left_panel, text="Analysis Results", padding=10)
        results_frame.pack(fill=tk.X, pady=10)
        
        self.detection_text = tk.Text(results_frame, wrap=tk.WORD, width=60, height=15, 
                                    bg=self.secondary_color, fg=self.fg_color, 
                                    font=('Consolas', 9), padx=5, pady=5)
        scrollbar = ttk.Scrollbar(results_frame, command=self.detection_text.yview)
        self.detection_text.configure(yscrollcommand=scrollbar.set)
        
        self.detection_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right panel (preview)
        right_panel = ttk.LabelFrame(content_frame, text="Image Preview", padding=10)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.detect_preview_frame = ttk.Frame(right_panel)
        self.detect_preview_frame.pack(fill=tk.BOTH, expand=True)

    def create_about_tab(self):
        about_frame = ttk.Frame(self.about_tab)
        about_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # App logo placeholder
        logo_frame = ttk.Frame(about_frame)
        logo_frame.pack(pady=(0, 20))
        
        # App name
        ttk.Label(logo_frame, 
                text="Hidy",
                font=('Segoe UI', 24, 'bold'),
                foreground=self.accent_color).pack()
        
        # Version
        ttk.Label(logo_frame,
                text="Secure Image Steganography Tool v2.1",
                font=('Segoe UI', 10),
                foreground="#aaaaaa").pack()
        
        # Separator
        ttk.Separator(about_frame).pack(fill=tk.X, pady=10)
        
        # About text
        about_text = """Hidy is an advanced steganography application that allows you to:
        
• Hide secret messages within images with encryption
• Detect hidden messages in images
• Automatically save encoded images
• Extract hidden messages with password protection

Features:
🔒 Secure encryption options
📁 Auto-save to Downloads folder
🖼️ High-quality image previews
🔍 Advanced steganalysis detection

Security:
• Uses LSB steganography
• Optional password protection
• Encrypted messages appear as random data

System Requirements:
• Python 3.8+
• Windows/macOS/Linux
• Pillow library

Developed with Python and Tkinter
© 2023 Hidy - All rights reserved
"""
        ttk.Label(about_frame, 
                text=about_text, 
                justify=tk.LEFT,
                font=('Segoe UI', 9)).pack(anchor=tk.W)

    def toggle_save_options(self):
        if self.auto_save.get():
            self.manual_save_frame.pack_forget()
            self.output_image_path.set("")
        else:
            self.manual_save_frame.pack(fill=tk.X, pady=(5, 0))
        
    def browse_input_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp"), ("All files", "*.*")]
        )
        if file_path:
            self.input_image_path.set(file_path)
            self.show_image_preview(file_path)
            
    def browse_output_image(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~/Downloads")
        )
        if file_path:
            self.output_image_path.set(file_path)
            
    def browse_detect_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp"), ("All files", "*.*")]
        )
        if file_path:
            self.detect_image_path.set(file_path)
            self.show_detect_preview(file_path)
            
    def get_downloads_path(self):
        """Get the user's Downloads folder path"""
        home = os.path.expanduser("~")
        return os.path.join(home, "Downloads")
            
    def generate_output_filename(self):
        """Generate a unique filename in Downloads folder"""
        downloads_path = self.get_downloads_path()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(self.input_image_path.get()))[0]
        return os.path.join(downloads_path, f"hidy_{base_name}_{timestamp}.png")
            
    def show_image_preview(self, image_path):
        try:
            # Clear previous previews
            for widget in self.preview_frame.winfo_children():
                widget.destroy()
            for widget in self.decode_preview_frame.winfo_children():
                widget.destroy()
                
            # Load and resize image
            img = Image.open(image_path)
            img.thumbnail((450, 450))
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(img)
            
            # Show in appropriate frame
            if self.notebook.index(self.notebook.select()) == 0:  # Encode tab
                label = ttk.Label(self.preview_frame, image=photo)
                label.image = photo  # Keep reference
                label.pack(expand=True)
            else:  # Decode tab
                label = ttk.Label(self.decode_preview_frame, image=photo)
                label.image = photo  # Keep reference
                label.pack(expand=True)
                
        except Exception as e:
            messagebox.showerror("Error", f"Could not load image: {str(e)}", parent=self.root)
            
    def show_detect_preview(self, image_path):
        try:
            # Clear previous preview
            for widget in self.detect_preview_frame.winfo_children():
                widget.destroy()
                
            # Load and resize image
            img = Image.open(image_path)
            img.thumbnail((450, 450))
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(img)
            
            # Show in preview frame
            label = ttk.Label(self.detect_preview_frame, image=photo)
            label.image = photo  # Keep reference
            label.pack(expand=True)
                
        except Exception as e:
            messagebox.showerror("Error", f"Could not load image: {str(e)}", parent=self.root)
            
    def xor_crypt(self, message, password):
        """Simple XOR encryption/decryption"""
        if not password:
            return message
            
        # Use SHA-256 hash of password for consistent key length
        key = hashlib.sha256(password.encode()).digest()
        return bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])
            
    def encode_message(self):
        if not self.input_image_path.get():
            messagebox.showerror("Error", "Please select an input image", parent=self.root)
            return
            
        if not self.secret_message.get():
            messagebox.showerror("Error", "Please enter a secret message", parent=self.root)
            return
            
        try:
            img = Image.open(self.input_image_path.get())
        except IOError:
            messagebox.showerror("Error", "Could not open the image file", parent=self.root)
            return
            
        # Determine output path
        if self.auto_save.get():
            output_path = self.generate_output_filename()
        else:
            if not self.output_image_path.get():
                messagebox.showerror("Error", "Please specify an output image path", parent=self.root)
                return
            output_path = self.output_image_path.get()
            
        message = self.secret_message.get()
        password = self.encode_password.get()
        
        # Encrypt the message if password is provided
        if password:
            try:
                message_bytes = message.encode('utf-8')
                encrypted_bytes = self.xor_crypt(message_bytes, password)
                message = encrypted_bytes.hex()  # Convert to hex string for storage
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}", parent=self.root)
                return
        
        binary_msg = ''.join([format(ord(c), '08b') for c in message])
        binary_msg += '1111111111111110'  # End of message marker
        
        if len(binary_msg) > img.width * img.height * 3:
            messagebox.showerror("Error", "Message too large for the selected image", parent=self.root)
            return
            
        pixels = img.load()
        data_index = 0
        
        for i in range(img.height):
            for j in range(img.width):
                pixel = list(pixels[j, i])
                
                for color in range(3):  # R, G, B
                    if data_index < len(binary_msg):
                        pixel[color] = pixel[color] & ~1 | int(binary_msg[data_index])
                        data_index += 1
                
                pixels[j, i] = tuple(pixel)
                
                if data_index >= len(binary_msg):
                    break
            if data_index >= len(binary_msg):
                break
        
        try:
            img.save(output_path, "PNG")
            messagebox.showinfo("Success", 
                              f"Message successfully encoded in image\n\nSaved to:\n{output_path}", 
                              parent=self.root)
            self.show_image_preview(output_path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not save image: {str(e)}", parent=self.root)
            
    def decode_message(self):
        if not self.input_image_path.get():
            messagebox.showerror("Error", "Please select an encoded image", parent=self.root)
            return
            
        try:
            img = Image.open(self.input_image_path.get())
        except IOError:
            messagebox.showerror("Error", "Could not open the image file", parent=self.root)
            return
            
        pixels = img.load()
        binary_msg = ''
        
        for i in range(img.height):
            for j in range(img.width):
                pixel = pixels[j, i]
                
                for color in range(3):  # R, G, B
                    binary_msg += str(pixel[color] & 1)
                    
                    if len(binary_msg) > 16 and binary_msg[-16:] == '1111111111111110':
                        break
                else:
                    continue
                break
            else:
                continue
            break
        
        binary_msg = binary_msg[:-16]
        message = ''
        
        for i in range(0, len(binary_msg), 8):
            byte = binary_msg[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        
        # Check if message is encrypted (hex string)
        try:
            # If the message is a hex string (likely encrypted)
            if all(c in "0123456789abcdef" for c in message.lower()):
                password = self.decode_password.get()
                if password:
                    try:
                        encrypted_bytes = bytes.fromhex(message)
                        decrypted_bytes = self.xor_crypt(encrypted_bytes, password)
                        message = decrypted_bytes.decode('utf-8')
                    except Exception as e:
                        messagebox.showerror("Error", "Failed to decrypt message. Wrong password?", parent=self.root)
                        return
                else:
                    messagebox.showwarning("Warning", "This message appears encrypted but no password was provided", parent=self.root)
        except:
            pass
        
        self.decoded_message.set(message)
        self.show_image_preview(self.input_image_path.get())
        
    def analyze_image(self):
        if not self.detect_image_path.get():
            messagebox.showerror("Error", "Please select an image to analyze", parent=self.root)
            return
            
        try:
            img = Image.open(self.detect_image_path.get())
            img_array = np.array(img)
            
            # Perform steganalysis
            lsb_analysis = self.analyze_lsb_patterns(img_array)
            entropy = self.calculate_entropy(img_array)
            chi_square = self.custom_chi_square_test(img_array)
            rs_analysis = self.rs_analysis(img_array)
            
            # Compile results
            result_text = "=== STEGANALYSIS RESULTS ===\n\n"
            result_text += f"1. LSB Analysis:\n{lsb_analysis}\n\n"
            result_text += f"2. Entropy: {entropy:.4f} (7.4-7.8 is normal for images)\n\n"
            result_text += f"3. Chi-Square Test:\n{chi_square}\n\n"
            result_text += f"4. RS Analysis:\n{rs_analysis}\n\n"
            
            # Overall assessment
            confidence = self.calculate_confidence(lsb_analysis, entropy, chi_square, rs_analysis)
            result_text += f"CONCLUSION: {confidence}"
            
            self.detection_text.delete(1.0, tk.END)
            self.detection_text.insert(tk.END, result_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}", parent=self.root)

    def analyze_lsb_patterns(self, img_array):
        """Analyze LSB patterns for anomalies using statistical analysis"""
        # Convert to grayscale if color
        if len(img_array.shape) == 3:
            img_array = img_array.mean(axis=2).astype(np.uint8)
        
        # Extract LSBs
        lsb = img_array & 1
        
        # Calculate randomness metrics
        flat = lsb.flatten()
        transitions = sum(flat[i] != flat[i+1] for i in range(len(flat)-1))
        randomness = transitions / len(flat)
        
        # Calculate ratio of 0s to 1s
        ratio = np.sum(lsb) / lsb.size
        
        # Evaluate patterns
        analysis = ""
        if randomness > 0.6:
            analysis += "• High LSB randomness (suspicious)\n"
        elif randomness > 0.5:
            analysis += "• Moderate LSB randomness (possibly modified)\n"
        else:
            analysis += "• Normal LSB patterns\n"
            
        analysis += f"• Transition rate: {randomness:.4f} (expected ~0.5 for unmodified)\n"
        analysis += f"• 1s ratio: {ratio:.4f} (expected ~0.5 for unmodified)"
        
        return analysis

    def calculate_entropy(self, img_array):
        """Calculate image entropy (measure of randomness)"""
        if len(img_array.shape) == 3:
            img_array = img_array.mean(axis=2).astype(np.uint8)
            
        hist = np.histogram(img_array, bins=256, range=(0, 255))[0]
        hist = hist[hist > 0]
        prob = hist / hist.sum()
        return -np.sum(prob * np.log2(prob))

    def custom_chi_square_test(self, img_array):
        """Custom implementation of chi-square test without scipy"""
        if len(img_array.shape) == 3:
            img_array = img_array[:,:,0]  # Use red channel
            
        # Get LSBs
        lsb = img_array & 1
        
        # Calculate observed and expected frequencies
        observed = np.bincount(lsb.flatten(), minlength=2)
        expected = np.array([lsb.size/2, lsb.size/2])
        
        # Calculate chi-square statistic manually
        chi_val = np.sum((observed - expected)**2 / expected)
        
        # Simple p-value approximation
        # This is a simplified approach - not as accurate as scipy's implementation
        if chi_val > 10:
            p_val = 0.001
        elif chi_val > 6:
            p_val = 0.01
        elif chi_val > 3:
            p_val = 0.05
        else:
            p_val = 0.5
            
        # Interpret results
        analysis = ""
        if p_val < 0.01:
            analysis += "• Significant deviation (p < 0.01)\n"
            analysis += "  Strong evidence of hidden data\n"
        elif p_val < 0.05:
            analysis += "• Moderate deviation (p < 0.05)\n"
            analysis += "  Possible hidden data\n"
        else:
            analysis += "• No significant deviation\n"
            analysis += "  No strong evidence of hidden data\n"
            
        analysis += f"• Approx p-value: {p_val:.4f}\n"
        analysis += f"• Chi-square: {chi_val:.2f}"
        
        return analysis

    def rs_analysis(self, img_array):
        """RS Steganalysis - detects LSB steganography"""
        if len(img_array.shape) == 3:
            img_array = img_array[:,:,0]  # Use red channel
            
        # Split into groups
        groups = img_array.reshape(-1, 3)
        
        # Calculate discrimination function
        f = np.abs(groups[:,1] - groups[:,0]) + np.abs(groups[:,1] - groups[:,2])
        
        # Count regular and singular groups
        R = np.sum(f[1:] > f[:-1])
        S = np.sum(f[1:] < f[:-1])
        
        # Calculate relative sizes
        total = R + S
        if total == 0:
            return "• RS Analysis: Inconclusive (not enough data)"
            
        r = R / total
        s = S / total
        
        # Interpret results
        analysis = ""
        if abs(r - s) < 0.1:
            analysis += "• RS Analysis: Normal image\n"
        elif r > s:
            analysis += "• RS Analysis: Possible LSB steganography detected\n"
        else:
            analysis += "• RS Analysis: Unusual patterns detected\n"
            
        analysis += f"• Regular groups: {R} ({r:.2%})\n"
        analysis += f"• Singular groups: {S} ({s:.2%})"
        
        return analysis

    def calculate_confidence(self, lsb_analysis, entropy, chi_square, rs_analysis):
        """Calculate overall confidence level based on all tests"""
        # Count suspicious indicators
        suspicious = 0
        
        # Check LSB analysis
        if "High LSB randomness" in lsb_analysis:
            suspicious += 2
        elif "Moderate LSB randomness" in lsb_analysis:
            suspicious += 1
            
        # Check entropy
        if entropy > 7.7 or entropy < 7.4:
            suspicious += 1
            
        # Check chi-square
        if "Strong evidence" in chi_square:
            suspicious += 2
        elif "Possible hidden" in chi_square:
            suspicious += 1
            
        # Check RS analysis
        if "Possible LSB" in rs_analysis:
            suspicious += 2
        elif "Unusual patterns" in rs_analysis:
            suspicious += 1
            
        # Determine conclusion
        if suspicious >= 5:
            return "HIGH CONFIDENCE - Likely contains hidden data (confidence: 85%)"
        elif suspicious >= 3:
            return "MODERATE CONFIDENCE - Possibly contains hidden data (confidence: 65%)"
        elif suspicious >= 1:
            return "LOW CONFIDENCE - Slight indications of hidden data (confidence: 35%)"
        else:
            return "NO EVIDENCE - No signs of hidden data detected (confidence: 90% normal)"

    def copy_decoded_message(self):
        if self.decoded_message.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.decoded_message.get())
            messagebox.showinfo("Copied", "Message copied to clipboard", parent=self.root)

if __name__ == "__main__":
    root = tk.Tk()
    
    # Set window icon
    try:
        root.iconbitmap(default='icon.ico')  # Provide your own icon file
    except:
        pass
    
    # Create custom style
    style = ttk.Style()
    style.theme_use('clam')
    
    # Configure accent button style
    style.configure('Accent.TButton', 
                  background='#4e8cff',
                  foreground='white',
                  font=('Segoe UI', 10, 'bold'),
                  padding=8)
    style.map('Accent.TButton',
             background=[('active', '#3a6fd5'), ('pressed', '#2a5bbf')])
    
    app = HidyApp(root)
    root.mainloop()
