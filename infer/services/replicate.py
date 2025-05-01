import replicate
from PIL import Image


def erase_bg(image: Image.Image) -> Image.Image:
    """
    Function takes a PILLOW image as input
    and returns 

    Args:
        - 
    Returns: 
        - 
    """
    return image.convert("L")
