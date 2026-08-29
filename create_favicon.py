from PIL import Image, ImageDraw

def create_favicon():
    size = (32, 32)
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw a blue shield-like shape
    draw.polygon([(16, 2), (28, 8), (28, 20), (16, 30), (4, 20), (4, 8)], fill='#3b82f6')
    
    # Draw a white V inside
    draw.line([(10, 12), (16, 22)], fill='white', width=3)
    draw.line([(16, 22), (22, 12)], fill='white', width=3)
    
    img.save('static/favicon.ico')
    img.save('static/favicon.png')

if __name__ == '__main__':
    create_favicon()

