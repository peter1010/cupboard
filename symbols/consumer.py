"""The proxy consumer of data imported into the data model.

It takes the data and
writes to the model database. It is mainly used when parsing input data"""

class Consumer:
    def __init__(self):
        pass

    def set_data_source(self, pathname):
        """Set source of the data consumed"""
        self.pathname = pathname

    def add_symbol(self):
        pass

    def add_code(self):
        pass

DefaultConsumer = Consumer()
