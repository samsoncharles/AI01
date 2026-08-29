import time
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--window-size=1920,1080')

driver = webdriver.Chrome(options=options)

base_dir = "/home/samson/combined2/AI1/code_base"

# 1. Dashboard
print("Capturing dashboard...")
driver.get("http://127.0.0.1:5000/")
time.sleep(2)
driver.save_screenshot(os.path.join(base_dir, "dashboard.png"))

# 2. History
print("Capturing history table...")
driver.get("http://127.0.0.1:5000/history")
time.sleep(2)
driver.save_screenshot(os.path.join(base_dir, "history.png"))

# 3. Results page
print("Capturing results page...")
driver.get("http://127.0.0.1:5000/results/46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb")
time.sleep(2)
driver.save_screenshot(os.path.join(base_dir, "results.png"))

# 4. Architecture SVG to PNG
print("Capturing architecture SVG...")
driver.get("file:///home/samson/combined2/AI1/ai_malware_system_architecture.svg")
time.sleep(2)
# Set window size to match SVG aspect ratio if needed
driver.set_window_size(1200, 1600)
time.sleep(1)
driver.save_screenshot(os.path.join(base_dir, "architecture.png"))

driver.quit()
print("All screenshots captured successfully.")
