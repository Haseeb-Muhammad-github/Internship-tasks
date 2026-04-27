# Sniffer.py - Detailed Explanation with Dry Runs

## 1. `map('{:02x}'.format, bytes_addr)`

### How it Works:

This function converts a sequence of bytes into hexadecimal format.

**Breaking it down:**
- **`map(function, iterable)`** – Applies a function to each element in an iterable
- **`'{:02x}'.format`** – A formatting function where:
  - `:02x` = format specifier meaning "convert to hexadecimal (x), with minimum 2 digits (02), padding with zeros if needed"
  - `{:02x}` formats a single integer value
- **`bytes_addr`** – A sequence of bytes (e.g., `b'\xaa\xbb\xcc\xdd\xee\xff'`)

**Result:** Returns a map object (iterator) containing hex strings

### Dry Run Example:

```python
bytes_addr = b'\xaa\xbb\xcc\xdd\xee\xff'  # 6 bytes of MAC address

# Step-by-step execution:
# Each byte is converted individually:
# 0xaa (170) → 'aa'
# 0xbb (187) → 'bb'
# 0xcc (204) → 'cc'
# 0xdd (221) → 'dd'
# 0xee (238) → 'ee'
# 0xff (255) → 'ff'

bytes_str = map('{:02x}'.format, bytes_addr)
result = list(bytes_str)  # ['aa', 'bb', 'cc', 'dd', 'ee', 'ff']

# Then joined with colons:
mac_address = ':'.join(result).upper()
# Final: 'AA:BB:CC:DD:EE:FF'
```

**Key Points:**
- The `02` ensures single-digit hex values get padded (e.g., `5` becomes `05`)
- Without padding, byte `5` would become just `5` instead of `05`

---

## 2. `struct.unpack('! 8x B B 2x 4s 4s', data[:20])`

### How it Works:

This unpacks the first 20 bytes of an IPv4 packet header.

**Format String Breakdown:**
- `!` = Network byte order (big-endian, standard for network protocols)
- `8x` = Skip 8 bytes (version, header length, DSCP, ECN, total length fields)
- `B` = Unsigned char (1 byte) → **TTL field**
- `B` = Unsigned char (1 byte) → **Protocol field**
- `2x` = Skip 2 bytes (checksum)
- `4s` = 4-byte string → **Source IP address (as raw bytes)**
- `4s` = 4-byte string → **Destination IP address (as raw bytes)**

**IPv4 Header Structure (20 bytes minimum):**
```
Byte 0-3:   Version(4b) + Header Length(4b) + DSCP(6b) + ECN(2b) + Total Length(16b)
Byte 4-7:   Identification(16b) + Flags(3b) + Fragment Offset(13b)
Byte 8-9:   [SKIPPED - 8x covers bytes 0-7]
Byte 9:     TTL ← extracted (B)
Byte 10:    Protocol ← extracted (B)
Byte 11-12: Header Checksum [SKIPPED - 2x]
Byte 13-16: Source IP ← extracted (4s)
Byte 17-20: Destination IP ← extracted (4s)
```

### Dry Run Example:

```python
# Sample IPv4 packet (first 20 bytes):
data = bytes([
    0x45, 0x00,              # Version/Length + DSCP/ECN (Bytes 0-1) [SKIPPED via 8x]
    0x00, 0x34,              # Total Length (Bytes 2-3) [SKIPPED]
    0x1c, 0x46,              # Identification (Bytes 4-5) [SKIPPED]
    0x40, 0x00,              # Flags/Fragment (Bytes 6-7) [SKIPPED]
    0x40,                    # TTL = 64 (Byte 8) ← Extracted as B
    0x06,                    # Protocol = 6 (TCP) (Byte 9) ← Extracted as B
    0x78, 0x24,              # Checksum (Bytes 10-11) [SKIPPED via 2x]
    0xc0, 0xa8, 0x01, 0x01,  # Source IP = 192.168.1.1 (Bytes 12-15) ← Extracted as 4s
    0xc0, 0xa8, 0x01, 0x02   # Dest IP = 192.168.1.2 (Bytes 16-19) ← Extracted as 4s
]) + b'\x00' * some_extra_bytes

# Unpacking:
ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

# Results:
# ttl = 64 (integer)
# proto = 6 (integer, meaning TCP)
# src = b'\xc0\xa8\x01\x01' (4 raw bytes)
# target = b'\xc0\xa8\x01\x02' (4 raw bytes)

# Then converted to IP format using ipv4():
# ipv4(src) = '192.168.1.1'
# ipv4(target) = '192.168.1.2'
```

---

## Side-by-Side Comparison in Code Context

From your `sniffer.py`:

```python
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4              # Extract upper 4 bits
    header_length = (version_header_length & 15) * 4  # Extract lower 4 bits × 4
    
    # ↓ This line uses struct.unpack
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
    # ↑ ipv4(src) uses the map function to convert bytes to dotted notation
```

The `map()` function works inside `ipv4()` to convert the 4 raw bytes (e.g., `b'\xc0\xa8\x01\x01'`) into `'192.168.1.1'`.
