// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.encoding.unicode.utf8`
//!
//! Unicode UTF-8 text encoding.

const encoding = @import("../encoding.zig");
const unicode = @import("unicode.zig");

pub const Error = error{
    InvalidFirstByte,
};

/// Decodes only the first Unicode codepoint from the given reader.
pub fn decode(cp: *unicode.Codepoint, r: anytype) !u3 {
    var fb: [1]u8 = .{0};
    _ = try r.read(fb[0..]);
    const len = try lenFromByte(fb[0]);

    switch (len) {
        // 0b0_______
        1 => cp.val = fb[0],

        // 0b110_____ 0b10______
        2 => {
            var data: [2]u8 = .{ fb[0], 0 };
            _ = try r.read(data[1..]);

            cp.val |= data[0] & 0b000_11111;
            cp.val <<= 6;
            cp.val |= data[1] & 0b00_111111;
        },

        // 0b1110____ 0b10______ 0b10______
        3 => {
            var data: [3]u8 = .{ fb[0], 0, 0 };
            _ = try r.read(data[1..]);

            cp.val |= data[0] & 0b0000_1111;
            cp.val <<= 6;
            cp.val |= data[1] & 0b00_111111;
            cp.val <<= 6;
            cp.val |= data[2] & 0b00_111111;
        },

        // 0b11110___ 0b10______ 0b10______ 0b10______
        4 => {
            var data: [4]u8 = .{ fb[0], 0, 0, 0 };
            _ = try r.read(data[1..]);

            cp.val |= data[0] & 0b00000_111;
            cp.val <<= 6;
            cp.val |= data[1] & 0b00_111111;
            cp.val <<= 6;
            cp.val |= data[2] & 0b00_111111;
            cp.val <<= 6;
            cp.val |= data[3] & 0b00_111111;
        },

        else => unreachable,
    }

    return len;
}

/// Decodes only the first Unicode codepoint from the given data.
pub fn decodeBuf(cp: *unicode.Codepoint, data: []const u8) !u3 {
    const len = try lenFromBytes(data);

    switch (len) {
        // 0b0_______
        1 => cp.val = data[0],

        // 0b110_____ 0b10______
        2 => {
            cp.val |= data[0] & 0b000_11111;
            cp.val <<= 6;
            cp.val |= data[1] & 0b00_111111;
        },

        // 0b1110____ 0b10______ 0b10______
        3 => {
            cp.val |= data[0] & 0b0000_1111;
            cp.val <<= 6;
            cp.val |= data[1] & 0b00_111111;
            cp.val <<= 6;
            cp.val |= data[2] & 0b00_111111;
        },

        // 0b11110___ 0b10______ 0b10______ 0b10______
        4 => {
            cp.val |= data[0] & 0b00000_111;
            cp.val <<= 6;
            cp.val |= data[1] & 0b00_111111;
            cp.val <<= 6;
            cp.val |= data[2] & 0b00_111111;
            cp.val <<= 6;
            cp.val |= data[3] & 0b00_111111;
        },

        else => unreachable,
    }

    return len;
}

pub fn encode(w: anytype, cp: unicode.Codepoint) !u3 {
    const n = switch (lenFromCodepoint(cp)) {
        // 0b0_______
        1 => try w.write(&.{@intCast(cp.val)}),

        // 0b110_____ 0b10______
        2 => try w.write(&.{
            @intCast(0b110_00000 | (cp.val >> 6)),
            @intCast(0b10_000000 | (cp.val & 0b00_111111)),
        }),

        // 0b1110____ 0b10______ 0b10______
        3 => try w.write(&.{
            @intCast(0b1110_0000 | (cp.val >> 12)),
            @intCast(0b10_000000 | (cp.val >> 6 & 0b00_111111)),
            @intCast(0b10_000000 | (cp.val & 0b00_111111)),
        }),

        // 0b11110___ 0b10______ 0b10______ 0b10______
        4 => try w.write(&.{
            @intCast(0b11110_000 | (cp.val >> 18)),
            @intCast(0b10_000000 | (cp.val >> 12 & 0b00_111111)),
            @intCast(0b10_000000 | (cp.val >> 6 & 0b00_111111)),
            @intCast(0b10_000000 | (cp.val & 0b00_111111)),
        }),

        else => unreachable,
    };

    return @intCast(n);
}

pub fn encodeBuf(buf: []u8, cp: unicode.Codepoint) !u3 {
    const len = lenFromCodepoint(cp);

    if (buf.len < len)
        return encoding.Error.OutputTooSmall;

    switch (len) {
        // 0b0_______
        1 => buf[0] = @intCast(cp.val),

        // 0b110_____ 0b10______
        2 => {
            buf[0] = @intCast(0b110_00000 | (cp.val >> 6));
            buf[1] = @intCast(0b10_000000 | (cp.val & 0b00_111111));
        },

        // 0b1110____ 0b10______ 0b10______
        3 => {
            buf[0] = @intCast(0b1110_0000 | (cp.val >> 12));
            buf[1] = @intCast(0b10_000000 | (cp.val >> 6 & 0b00_111111));
            buf[2] = @intCast(0b10_000000 | (cp.val & 0b00_111111));
        },

        // 0b11110___ 0b10______ 0b10______ 0b10______
        4 => {
            buf[0] = @intCast(0b11110_000 | (cp.val >> 18));
            buf[1] = @intCast(0b10_000000 | (cp.val >> 12 & 0b00_111111));
            buf[2] = @intCast(0b10_000000 | (cp.val >> 6 & 0b00_111111));
            buf[3] = @intCast(0b10_000000 | (cp.val & 0b00_111111));
        },

        else => unreachable,
    }

    return len;
}

/// Calculates how many bytes were used for encoding a Unicode codepoint using
/// the given byte as first byte.
pub fn lenFromByte(b: u8) !u3 {
    // 1 byte - 0b0_______
    if (b <= 0b0111_1111) return 1;

    // 2 bytes - 0b110_____
    if (b <= 0b110_11111) return 2;

    // 3 bytes - 0b1110____
    if (b <= 0b1110_1111) return 3;

    // 4 bytes - 0b11110___
    if (b <= 0b11110_111) return 4;

    return Error.InvalidFirstByte;
}

/// Calculates how many bytes were used for encoding the first Unicode
/// codepoint from the given data.
pub fn lenFromBytes(data: []const u8) !u3 {
    if (data.len == 0) return 0;
    const len = try lenFromByte(data[0]);
    if (data.len < len) return encoding.Error.IncompleteInput;
    return len;
}

/// Calculates how many bytes are needed for encoding the given Unicode
/// codepoint.
pub fn lenFromCodepoint(cp: unicode.Codepoint) u3 {
    // Highest representable value with 7 bits. (ASCII compatibility)
    //
    // 0b0_______
    if (cp.val <= 0b0111_1111) return 1;

    // Highest representable value with 11 bits.
    //
    // 0b110_____ 0b10______
    //        5    +    6    = 11 bits
    if (cp.val <= 0b0111_1111_1111) return 2;

    // Highest representable value with 16 bits.
    //
    // 0b1110____ 0b10______ 0b10______
    //        4    +    6     +    6    = 16 bits
    if (cp.val <= 0b1111_1111_1111_1111) return 3;

    // Highest representable value with 21 bits.
    //
    // 0b11110___ 0b10______ 0b10______ 0b10______
    //         3   +    6     +    6     +    6    = 21 bits
    //if (cp.val <= 0b0001_1111_1111_1111_1111_1111) return 4;

    return 4;
}
