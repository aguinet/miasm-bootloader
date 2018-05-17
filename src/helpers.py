# Here, we consider that we manipulate 16 bit registers

# High 8 bits
def get_xh(reg_val):
    return (reg_val & 0xFF00)>>8

def set_xh(reg_val, set_val):
    return (reg_val & 0x00FF) | ((set_val & 0x00FF) << 8)

# Low 8 bits
def get_xl(reg_val):
    return (reg_val & 0x00FF)

def set_xl(reg_val, set_val):
    return (reg_val & 0xFF00) | (set_val & 0x00FF)

# Set 2x8bits
def set_16bit_reg(low, high):
    return (low & 0xFF) | ((high & 0xFF) << 8)
