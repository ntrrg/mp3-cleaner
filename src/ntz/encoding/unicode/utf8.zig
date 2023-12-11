// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.encoding.unicode.utf8`
//!
//! Unicode UTF-8 text encoding.

const unicode = @import("unicode.zig");

/// Iterates over codepoints in UTF-8 encoded strings.
pub const Iterator = struct {
    const Self = @This();

    const Error =
        Self.CountError ||
        Self.GetError ||
        Self.GetBytesError ||
        Self.IndexError ||
        NextError ||
        NextByteError ||
        NextBytesError ||
        SkipError;

    data: []const u8,
    i: usize = 0,

    pub fn init(data: []const u8) Self {
        return .{ .data = data };
    }

    pub const CheckError = SkipError;

    /// Calculates the number of codepoints the iterator holds.
    pub fn check(it: Self) Self.CheckError!void {
        var it_cp = it;

        while (it_cp.skip()) {} else |err| {
            if (err != error.EndOfIteration) return err;
        }
    }

    pub const CountError = SkipError;

    /// Calculates the number of codepoints the iterator holds.
    pub fn count(it: Self) Self.CountError!usize {
        var it_cp = it;
        var n: usize = 0;

        while (it_cp.skip()) {
            n += 1;
        } else |err| {
            if (err != error.EndOfIteration) return err;
        }

        return n;
    }

    pub const GetError = Self.GetBytesError || DecodeError;

    /// Obtains the codepoint at index `idx`. Current iteration index is not
    /// modified.
    pub fn get(it: Self, idx: usize) Self.GetError!unicode.Codepoint {
        const data = try it.getBytes(idx);
        var cp = unicode.Codepoint{ .value = 0 };
        _ = try decode(null, &cp, data);
        return cp;
    }

    pub const GetBytesError = Self.IndexError;

    /// Obtains the codepoint at index `idx` as bytes. Current iteration index
    /// is not modified.
    pub fn getBytes(it: Self, idx: usize) Self.GetBytesError![]const u8 {
        const pos = try it.index(idx);
        return it.data[pos.i..pos.j];
    }

    pub const IndexError = error{
        OutOfRange,
    } || NextIndexError;

    pub const IndexResult = struct { i: usize, j: usize };

    /// Obtains the underlying starting and ending indexes of the codepoint at
    /// index `idx`.
    pub fn index(it: Self, idx: usize) Self.IndexError!IndexResult {
        if (idx > it.data.len) return error.OutOfRange;

        var it_cp = it;
        it_cp.i = 0;
        var n: usize = 0;

        while (it_cp.nextIndex()) |j| {
            if (n == idx) return .{ .i = it_cp.i, .j = j };
            it_cp.i = j;
            n += 1;
        } else |err| {
            if (err == error.EndOfIteration) return error.OutOfRange;
            return err;
        }
    }

    pub const NextError = NextBytesError || DecodeError;

    /// Obtains the next codepoint.
    pub fn next(it: *Self) NextError!unicode.Codepoint {
        const data = try it.nextBytes();
        var cp = unicode.Codepoint{ .value = 0 };
        _ = try decode(null, &cp, data);
        return cp;
    }

    pub const NextByteError = error{
        EndOfIteration,
    };

    /// Obtains the next byte. Use with caution, it may break valid codepoinds.
    pub fn nextByte(it: *Self) NextByteError!u8 {
        if (it.i >= it.data.len) return error.EndOfIteration;
        it.i += 1;
        return it.data[it.i - 1];
    }

    pub const NextBytesError = NextIndexError;

    /// Obtains the next codepoint as bytes.
    pub fn nextBytes(it: *Self) NextBytesError![]const u8 {
        const old_i = it.i;
        it.i = try it.nextIndex();
        return it.data[old_i..it.i];
    }

    pub const NextIndexError = error{
        EndOfIteration,
    } || DecodeLenError;

    /// Obtains the underlying starting index of the next codepoint.
    fn nextIndex(it: Self) NextIndexError!usize {
        if (it.i >= it.data.len) return error.EndOfIteration;
        return it.i + try decodeLen(it.data[it.i..]);
    }

    pub const SkipError = NextIndexError;

    /// Skips the next codepoint.
    pub fn skip(it: *Self) SkipError!void {
        it.i = try it.nextIndex();
    }
};

pub const CountError = Iterator.CountError;

/// Calculates the number of codepoints stored in `data`.
pub fn count(data: []const u8) CountError!usize {
    var it = Iterator.init(data);
    return it.count();
}

pub const DecodeDiagnostic = struct {
    /// Index where the error occurred.
    index: usize = 0,

    /// Expected number of bytes of invalid codepoint.
    len_expected: usize = 0,
};

pub const DecodeError = DecodeLenError || ValidateError;

/// Decodes the first codepoint from the given data and returns the number of
/// bytes used. If 0 is returned, it means `cp` had no modifications.
pub fn decode(
    diagnostic: ?*DecodeDiagnostic,
    cp: *unicode.Codepoint,
    data: []const u8,
) DecodeError!u3 {
    if (diagnostic) |diag| diag.index = 0;

    const len = try decodeLen(data);
    if (len == 0) return 0;

    const cp_data = data[0..len];
    try validate(diagnostic, cp_data);
    decodeValid(cp, cp_data);

    return len;
}

pub const ValidateError = error{
    IncompleteInput,
    InvalidFirstByte,
    InvalidIntermediateByte,
    TooManyBytes,
};

/// Checks if the given data may be a UTF-8 encoded codepoint, but doesn't try
/// to decode it.
pub fn validate(
    diagnostic: ?*DecodeDiagnostic,
    data: []const u8,
) ValidateError!void {
    if (data.len == 0) return error.IncompleteInput;
    const cp_len = try decodeLenFB(data[0]);

    errdefer {
        if (diagnostic) |diag| diag.len_expected = cp_len;
    }

    if (data.len < cp_len) {
        if (diagnostic) |diag| diag.index = 0;
        return error.IncompleteInput;
    } else if (data.len > cp_len) {
        if (diagnostic) |diag| diag.index = 0;
        return error.TooManyBytes;
    }

    if (!isFirstByte(data[0])) {
        if (diagnostic) |diag| diag.index = 0;
        return error.InvalidFirstByte;
    }

    if (data.len == 1) return;

    for (1..cp_len) |i| {
        if (data[i] & 0b11_000000 != 0b10_000000) {
            if (diagnostic) |diag| diag.index = i;
            return error.InvalidIntermediateByte;
        }
    }
}

pub const DecodeLenError = error{
    IncompleteInput,
} || DecodeLenFBError;

/// Calculates how many bytes are required for decoding the first codepoint
/// from the given data.
pub fn decodeLen(data: []const u8) DecodeLenError!u3 {
    if (data.len == 0) return 0;
    const len = try decodeLenFB(data[0]);
    if (data.len < len) return error.IncompleteInput;
    return len;
}

pub const DecodeLenFBError = error{
    InvalidFirstByte,
};

/// Calculates how many bytes are required for decoding a codepoint from its
/// first byte.
pub fn decodeLenFB(fb: u8) DecodeLenFBError!u3 {
    if (fb & 0b1_0000000 == 0b0000_0000) return 1; // 1 byte  - 0b0_______
    if (fb & 0b111_00000 == 0b110_00000) return 2; // 2 bytes - 0b110_____
    if (fb & 0b1111_0000 == 0b1110_0000) return 3; // 3 bytes - 0b1110____
    if (fb & 0b11111_000 == 0b11110_000) return 4; // 4 bytes - 0b11110___
    return error.InvalidFirstByte;
}

///// Decodes the first codepoint from the given reader and returns the number of
///// bytes read. If 0 is returned, it means `cp` had no modifications.
//pub fn decodeReader(cp: *unicode.Codepoint, r: anytype) !u3 {
//    var fb_buf: [1]u8 = .{0};
//    const fb_n = try r.read(fb_buf[0..1]);
//    if (fb_n == 0) return 0;
//
//    const fb = fb_buf[0];
//    const len = try decodeLenFB(fb);
//
//    switch (len) {
//        1 => try decode(cp, fb_buf[0..]),
//
//        2 => {
//            var buf: [2]u8 = .{ fb, 0 };
//            const n = try r.read(buf[1..]);
//            if (n < 1) return error.IncompleteInput;
//            try decode(cp, buf[0..len]);
//        },
//
//        3 => {
//            var buf: [3]u8 = .{ fb, 0, 0 };
//            const n = try r.read(buf[1..]);
//            if (n < 2) return error.IncompleteInput;
//            try decode(cp, buf[0..len]);
//        },
//
//        4 => {
//            var buf: [4]u8 = .{ fb, 0, 0, 0 };
//            const n = try r.read(buf[1..]);
//            if (n < 3) return error.IncompleteInput;
//            try decode(cp, buf[0..len]);
//        },
//
//        else => unreachable,
//    }
//
//    return len;
//}

/// Decodes a codepoint from the given bytes. Assumes `data` contains a valid
/// UTF-8 encoded codepoint.
fn decodeValid(cp: *unicode.Codepoint, data: []const u8) void {
    switch (data.len) {
        // 0b0_______
        1 => cp.value = data[0],

        // 0b110_____ 0b10______
        2 => {
            cp.value |= data[0] & 0b000_11111;
            cp.value <<= 6;
            cp.value |= data[1] & 0b00_111111;
        },

        // 0b1110____ 0b10______ 0b10______
        3 => {
            cp.value |= data[0] & 0b0000_1111;
            cp.value <<= 6;
            cp.value |= data[1] & 0b00_111111;
            cp.value <<= 6;
            cp.value |= data[2] & 0b00_111111;
        },

        // 0b11110___ 0b10______ 0b10______ 0b10______
        4 => {
            cp.value |= data[0] & 0b00000_111;
            cp.value <<= 6;
            cp.value |= data[1] & 0b00_111111;
            cp.value <<= 6;
            cp.value |= data[2] & 0b00_111111;
            cp.value <<= 6;
            cp.value |= data[3] & 0b00_111111;
        },

        else => unreachable,
    }
}

pub const EncodeError = error{
    OutputTooSmall,
};

/// Encodes a codepoint into the given buffer and returns the number of bytes
/// used.
pub fn encode(buf: []u8, cp: unicode.Codepoint) EncodeError!u3 {
    const len = encodeLen(cp);
    if (buf.len < len) return error.OutputTooSmall;

    switch (len) {
        // 0b0_______
        1 => buf[0] = @intCast(cp.value),

        // 0b110_____ 0b10______
        2 => {
            buf[0] = @intCast(0b110_00000 | (cp.value >> 6));
            buf[1] = @intCast(0b10_000000 | (cp.value & 0b00_111111));
        },

        // 0b1110____ 0b10______ 0b10______
        3 => {
            buf[0] = @intCast(0b1110_0000 | (cp.value >> 12));
            buf[1] = @intCast(0b10_000000 | (cp.value >> 6 & 0b00_111111));
            buf[2] = @intCast(0b10_000000 | (cp.value & 0b00_111111));
        },

        // 0b11110___ 0b10______ 0b10______ 0b10______
        4 => {
            buf[0] = @intCast(0b11110_000 | (cp.value >> 18));
            buf[1] = @intCast(0b10_000000 | (cp.value >> 12 & 0b00_111111));
            buf[2] = @intCast(0b10_000000 | (cp.value >> 6 & 0b00_111111));
            buf[3] = @intCast(0b10_000000 | (cp.value & 0b00_111111));
        },

        else => unreachable,
    }

    return len;
}

/// Calculates the number of bytes used for encoding a codepoint.
pub fn encodeLen(cp: unicode.Codepoint) u3 {
    // Highest representable value with 7 bits.
    //
    // 0b0_______
    if (cp.value <= 0b0111_1111) return 1;

    // Highest representable value with 11 bits.
    //
    // 0b110_____ 0b10______
    //        5    +    6    = 11 bits
    if (cp.value <= 0b0111_1111_1111) return 2;

    // Highest representable value with 16 bits.
    //
    // 0b1110____ 0b10______ 0b10______
    //        4    +    6     +    6    = 16 bits
    if (cp.value <= 0b1111_1111_1111_1111) return 3;

    // Highest representable value with 21 bits.
    //
    // 0b11110___ 0b10______ 0b10______ 0b10______
    //         3   +    6     +    6     +    6    = 21 bits
    //if (cp.value <= 0b0001_1111_1111_1111_1111_1111) return 4;

    return 4;
}

//pub fn encodeWriter(w: anytype, cp: unicode.Codepoint) !u3 {
//    const n = switch (lenFromCodepoint(cp)) {
//        // 0b0_______
//        1 => try w.write(&.{@intCast(cp.value)}),
//
//        // 0b110_____ 0b10______
//        2 => try w.write(&.{
//            @intCast(0b110_00000 | (cp.value >> 6)),
//            @intCast(0b10_000000 | (cp.value & 0b00_111111)),
//        }),
//
//        // 0b1110____ 0b10______ 0b10______
//        3 => try w.write(&.{
//            @intCast(0b1110_0000 | (cp.value >> 12)),
//            @intCast(0b10_000000 | (cp.value >> 6 & 0b00_111111)),
//            @intCast(0b10_000000 | (cp.value & 0b00_111111)),
//        }),
//
//        // 0b11110___ 0b10______ 0b10______ 0b10______
//        4 => try w.write(&.{
//            @intCast(0b11110_000 | (cp.value >> 18)),
//            @intCast(0b10_000000 | (cp.value >> 12 & 0b00_111111)),
//            @intCast(0b10_000000 | (cp.value >> 6 & 0b00_111111)),
//            @intCast(0b10_000000 | (cp.value & 0b00_111111)),
//        }),
//
//        else => unreachable,
//    };
//
//    return @intCast(n);
//}

pub const GetError = Iterator.GetError;

/// Obtains the codepoint at index `idx`.
pub fn get(data: []const u8, idx: usize) GetError!unicode.Codepoint {
    var it = Iterator.init(data);
    return it.get(idx);
}

pub const GetBytesError = Iterator.GetError;

/// Obtains the codepoint at index `idx` as bytes.
pub fn getBytes(data: []const u8, idx: usize) GetBytesError![]const u8 {
    var it = Iterator.init(data);
    return it.getBytes(idx);
}

pub const IndexError = Iterator.IndexError;

/// Obtains the underlying starting and ending indexes of the codepoint at
/// index `idx`.
pub fn index(data: []const u8, idx: usize) IndexError!Iterator.IndexResult {
    return Iterator.init(data).index(idx);
}

/// Checks if the given byte is the first byte of a codepoint.
pub fn isFirstByte(fb: u8) bool {
    if (fb & 0b1_0000000 == 0b0000_0000) return true;
    if (fb & 0b111_00000 == 0b110_00000) return true;
    if (fb & 0b1111_0000 == 0b1110_0000) return true;
    if (fb & 0b11111_000 == 0b11110_000) return true;
    return false;
}

/// Checks if the given byte is part of a codepoint.
pub fn isIntermediateByte(ib: u8) bool {
    if (ib & 0b11_000000 == 0b10_000000) return true;
    return false;
}
