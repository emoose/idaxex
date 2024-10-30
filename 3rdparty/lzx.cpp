/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>

#include "../3rdparty/mspack/lzx.h"
#include "../3rdparty/mspack/mspack.h"

 // BitScanForward (bsf).
 // Search the value from least significant bit (LSB) to the most significant bit
 // (MSB) for a set bit (1).
 // Returns false if no bits are set and the output index is invalid.
#ifdef _WIN32
inline bool bit_scan_forward(uint32_t v, uint32_t* out_first_set_index) {
    return _BitScanForward(reinterpret_cast<unsigned long*>(out_first_set_index),
        v) != 0;
}
inline bool bit_scan_forward(uint64_t v, uint32_t* out_first_set_index) {
    return _BitScanForward64(
        reinterpret_cast<unsigned long*>(out_first_set_index), v) != 0;
}
#else
inline bool bit_scan_forward(uint32_t v, uint32_t* out_first_set_index) {
    int i = ffs(v);
    *out_first_set_index = i - 1;
    return i != 0;
}
inline bool bit_scan_forward(uint64_t v, uint32_t* out_first_set_index) {
    int i = __builtin_ffsll(v);
    *out_first_set_index = i - 1;
    return i != 0;
}
#endif  // _WIN32

typedef struct mspack_memory_file_t {
    mspack_system sys;
    void* buffer;
    off_t buffer_size;
    off_t offset;
} mspack_memory_file;

mspack_memory_file* mspack_memory_open(mspack_system* sys, void* buffer,
    const size_t buffer_size) {
    if (buffer_size >= INT_MAX) {
        return NULL;
    }
    auto memfile =
        (mspack_memory_file*)std::calloc(1, sizeof(mspack_memory_file));
    if (!memfile) {
        return NULL;
    }
    memfile->buffer = buffer;
    memfile->buffer_size = (off_t)buffer_size;
    memfile->offset = 0;
    return memfile;
}

void mspack_memory_close(mspack_memory_file* file) {
    auto memfile = (mspack_memory_file*)file;
    std::free(memfile);
}

int mspack_memory_read(mspack_file* file, void* buffer, int chars) {
    auto memfile = (mspack_memory_file*)file;
    const off_t remaining = memfile->buffer_size - memfile->offset;
    const off_t total = std::min(static_cast<off_t>(chars), remaining);
    std::memcpy(buffer, (uint8_t*)memfile->buffer + memfile->offset, total);
    memfile->offset += total;
    return (int)total;
}

int mspack_memory_write(mspack_file* file, void* buffer, int chars) {
    auto memfile = (mspack_memory_file*)file;
    const off_t remaining = memfile->buffer_size - memfile->offset;
    const off_t total = std::min(static_cast<off_t>(chars), remaining);
    std::memcpy((uint8_t*)memfile->buffer + memfile->offset, buffer, total);
    memfile->offset += total;
    return (int)total;
}

void* mspack_memory_alloc(mspack_system* sys, size_t chars) {
    return std::calloc(chars, 1);
}

void mspack_memory_free(void* ptr) { std::free(ptr); }

void mspack_memory_copy(void* src, void* dest, size_t chars) {
    std::memcpy(dest, src, chars);
}

mspack_system* mspack_memory_sys_create() {
    auto sys = (mspack_system*)std::calloc(1, sizeof(mspack_system));
    if (!sys) {
        return NULL;
    }
    sys->read = mspack_memory_read;
    sys->write = mspack_memory_write;
    sys->alloc = mspack_memory_alloc;
    sys->free = mspack_memory_free;
    sys->copy = mspack_memory_copy;
    return sys;
}

void mspack_memory_sys_destroy(struct mspack_system* sys) { free(sys); }

int lzx_decompress(const void* lzx_data, size_t lzx_len, void* dest,
    size_t dest_len, uint32_t window_size, void* window_data,
    size_t window_data_len) {
    int result_code = 1;

    uint32_t window_bits;
    if (!bit_scan_forward(window_size, &window_bits)) {
        return result_code;
    }

    mspack_system* sys = mspack_memory_sys_create();
    mspack_memory_file* lzxsrc =
        mspack_memory_open(sys, (void*)lzx_data, lzx_len);
    mspack_memory_file* lzxdst = mspack_memory_open(sys, dest, dest_len);
    lzxd_stream* lzxd = lzxd_init(sys, (mspack_file*)lzxsrc, (mspack_file*)lzxdst,
        window_bits, 0, 0x8000, (off_t)dest_len, 0);

    if (lzxd) {
        if (window_data) {
            // zero the window and then copy window_data to the end of it
            auto padding_len = window_size - window_data_len;
            std::memset(&lzxd->window[0], 0, padding_len);
            std::memcpy(&lzxd->window[padding_len], window_data, window_data_len);
            // TODO(gibbed): should this be set regardless if source window data is
            // available or not?
            lzxd->ref_data_size = window_size;
        }

        result_code = lzxd_decompress(lzxd, (off_t)dest_len);

        lzxd_free(lzxd);
        lzxd = NULL;
    }

    if (lzxsrc) {
        mspack_memory_close(lzxsrc);
        lzxsrc = NULL;
    }

    if (lzxdst) {
        mspack_memory_close(lzxdst);
        lzxdst = NULL;
    }

    if (sys) {
        mspack_memory_sys_destroy(sys);
        sys = NULL;
    }

    return result_code;
}
