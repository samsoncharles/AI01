import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--window-size=1920,1080')

try:
    driver = webdriver.Chrome(options=options)
    driver.get("http://127.0.0.1:5000/results/46ced738ab9a9a37df3e36c6a8603742f26783f0be2fa845bdec10b5ddb50bfb")
    time.sleep(3)

    # Force open the chat using Javascript to ensure it works in headless mode
    driver.execute_script("document.getElementById('globalChatToggle').click();")
    time.sleep(2)
    
    # Send a quick message to populate chat
    driver.execute_script("document.getElementById('globalChatInput').value = 'Hello';")
    driver.execute_script("document.getElementById('globalChatForm').dispatchEvent(new Event('submit'));")
    time.sleep(3)

    driver.save_screenshot("chatbot.png")
    print("Screenshot saved to chatbot.png")
    driver.quit()
except Exception as e:
    print(f"Error: {e}")
