"""The proxy consumer of data imported into the data model.

It takes the data and
writes to the model database. It is mainly used when parsing input data"""

class Consumer:
    def __init__(self, db_conn):
        self.db_conn = db_conn

    def set_data_source(self, pathname):
        """Set source of the data consumed"""
        self.pathname = pathname

    def add_symbol(name, sym):
        c = self.db_conn.cursor()
        c.execute("INSERT INTO symbols VALUES(?,?,?,?,?)",
            sym.name,
            sym.offset,
        )
        self.db_conn.commit()

    def add_code(self):
        pass

DefaultConsumer = Consumer(None)
