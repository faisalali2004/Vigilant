import logging

def get_logger(verbose=False):
    logger = logging.getLogger("lightscan")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    return logger

def get_child_logger(parent, name):
    return parent.getChild(name)
