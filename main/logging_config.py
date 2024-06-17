import logging

def setup_logger(name=None):
    logging.basicConfig(
        filename='sniffer.log',
        format='%(asctime)s %(threadName)s %(levelname)-8s %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S',
        filemode='w+'
    )

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    return logger


setup_logger()



