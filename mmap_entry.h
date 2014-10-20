#ifndef _MMAP_ENTRY_H_
#define _MMAP_ENTRY_H_

/**
 * Structure containing a parsed text line from the memory map proc file
 */
class Map_entry
{
public:
    Map_entry();
    ~Map_entry();

    static Map_entry * parse_map_entry(const char * linebuf);

    bool is_executable() const 
        {return ((m_permissions & PROT_EXEC) != 0);};

    bool is_readable() const 
        {return ((m_permissions & PROT_READ) != 0);};

    bool is_writable() const 
        {return ((m_permissions & PROT_WRITE) != 0);};
    
    bool is_accessable() const 
        {return ((m_permissions & (PROT_WRITE | PROT_READ)) != 0);};

    bool has_permissions() const {return (m_permissions != 0);};

    bool copy_pathname(char * buffer, int max_len) const;

    bool same_pathname(const Map_entry * other) const;
    
    const char * pathname() const {return m_pathname;};

    bool match_library(const char * to_find) const;

    bool contains(MemPtr_t value) const
        {return ((value < m_end_address) && (value >= m_start_address));};
    
    int open_elf() const;

    void debug_print() const;

    int offset(MemPtr_t value) {return value - m_start_address; };

    MemPtr_t foffset2addr(int foffset) const
        {return m_start_address + foffset - m_offset_into_file; };

private:
    MemPtr_t m_start_address;
    MemPtr_t m_end_address;
    int m_permissions;                  /* r/w/x/p */
    unsigned long m_offset_into_file;   /* if region mapped from file, the offset into file */
    char * m_pathname;                  /* if region mapped from file, the file pathname */
};

#endif
