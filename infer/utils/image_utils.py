"""
Utils for various image manipulations
"""

from PIL import Image

def resize_image(image: Image,
                 max_width: int,
                 max_height: int) -> Image.Image:
    """
    Ensures the image dimensions don't 
    exceed given limits
    """
    width, height = image.size

    if width > max_width:
        height = int(max_width / width * height)
        width = max_width

    if height > max_height:
        width = int (max_height / height * width)
        height = max_height

    image = image.resize((width, height))

    return image