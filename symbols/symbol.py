class Symbol:
    def __init__(self, name, value, size, info):
        self.name = name
        self.value = value
        self.size = size
        self.info = info
        self.offset = None
        self.rel_typ = 0

    def __str__(self):
        return "{} {} {} {} {} {}".format(
            self.name,
            self.value,
            self.size,
            self.info,
            self.offset,
            self.rel_typ
        )
