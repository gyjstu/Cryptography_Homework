from PIL import Image

test=Image.open('test_ecb.jpg')
test_rgba=test.convert('RGBA')
test_rgba.save('test.rgba')