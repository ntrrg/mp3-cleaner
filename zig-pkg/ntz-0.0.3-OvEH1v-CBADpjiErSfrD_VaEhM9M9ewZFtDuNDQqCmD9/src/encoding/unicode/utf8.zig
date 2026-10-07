// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.encoding.unicode.utf8`
//!
//! Unicode UTF-8 text encoding.

const types = @import("../../types/root.zig");
const bytes = types.bytes;
const iterators = types.iterators;
const unicode = @import("root.zig");

const ib_mask: u8 = 0b00_111111;
const ib_template: u8 = 0b10_000000;

fn fbMask(l: usize) u8 {
    return switch (l) {
        1 => 0b0_1111111,
        2 => 0b000_11111,
        3 => 0b0000_1111,
        4 => 0b00000_111,
        else => unreachable,
    };
}

fn fbTemplate(l: usize) u8 {
    return switch (l) {
        1 => 0b0_0000000,
        2 => 0b110_00000,
        3 => 0b1110_0000,
        4 => 0b11110_000,
        else => unreachable,
    };
}

// ///////////
// Encoding //
// ///////////

pub const EncodingError = EncodeError;

pub const EncodeError = error{
    OutOfMemory,
};

/// Encodes a codepoint into the given buffer and returns the number of bytes
/// used.
pub fn encode(buf: []u8, cp: unicode.Codepoint) EncodeError!u3 {
    const l = encodeLen(cp);
    if (buf.len < l) return error.OutOfMemory;

    var rsb: u5 = 6 * @as(u5, l - 1); // Right-shift bits.
    buf[0] = @intCast(cp.value >> rsb & fbMask(l) | fbTemplate(l));

    for (1..l) |i| {
        rsb = 6 * @as(u5, l - @as(u3, @truncate(i)) - 1);
        buf[i] = @intCast(ib_template | (cp.value >> rsb & ib_mask));
    }

    return l;
}

/// Calculates the number of bytes used for encoding a codepoint.
pub fn encodeLen(cp: unicode.Codepoint) u3 {
    // 0b0_______
    if (cp.value <= 0b0111_1111) return 1;

    // 0b110_____ 0b10______
    //        5    +    6    = 11 bits
    if (cp.value <= 0b0111_1111_1111) return 2;

    // 0b1110____ 0b10______ 0b10______
    //        4    +    6     +    6    = 16 bits
    if (cp.value <= 0b1111_1111_1111_1111) return 3;

    // 0b11110___ 0b10______ 0b10______ 0b10______
    //         3   +    6     +    6     +    6    = 21 bits
    if (cp.value <= 0b0001_1111_1111_1111_1111_1111) return 4;

    unreachable;
}

// ///////////
// Decoding //
// ///////////

pub const DecodingError =
    DecodeError ||
    DecodeLenError ||
    DecodeLenFBError ||
    ValidationError;

pub const ClearError = error{
    OutOfMemory,
};

/// Copies valid bytes from the given data to the given buffer.
pub fn clear(buf: []u8, data: []const u8) ClearError![]u8 {
    if (buf.len < data.len and buf.len < countBytes(data))
        return error.OutOfMemory;

    var i: usize = 0;
    var j: usize = 0;

    while (nextValidPositionAt(i, data)) |pos| {
        const l = bytes.copyLtr(buf[j..], data[pos.i..pos.j]);
        j += l;
        i = pos.j;
    }

    return buf[0..j];
}

/// Removes invalid bytes (if any) from the given data.
pub fn clearIn(data: []u8) []u8 {
    return clear(data, data) catch unreachable;
}

/// Returns the number of valid UTF-8 bytes in the given data.
pub fn countBytes(data: []const u8) usize {
    var i: usize = 0;
    var n: usize = 0;

    while (nextValidPositionAt(i, data)) |pos| {
        n += pos.j - pos.i;
        i = pos.j;
    }

    return n;
}

pub const DecodeError = error{
    EmptyInput,
} || DecodeLenError;

/// Decodes the first codepoint from the given data and returns the number of
/// bytes used.
///
/// This assumes data is UTF-8 encoded, see `validate` if validation is
/// required.
pub fn decode(cp: *unicode.Codepoint, data: []const u8) DecodeError!u3 {
    const l = try decodeLen(data);
    if (l == 0) return error.EmptyInput;

    cp.value |= data[0] & fbMask(l);

    for (1..l) |i| {
        cp.value <<= 6;
        cp.value |= data[i] & ib_mask;
    }

    return l;
}

pub const DecodeLenError = DecodeLenFBError;

/// Calculates how many bytes are required for decoding the first codepoint
/// from the given data.
pub fn decodeLen(data: []const u8) DecodeLenError!u3 {
    if (data.len == 0) return 0;
    return decodeLenFb(data[0]);
}

pub const DecodeLenFBError = error{
    InvalidFirstByte,
};

/// Calculates how many bytes are required for decoding a codepoint from its
/// first byte.
pub fn decodeLenFb(fb: u8) DecodeLenFBError!u3 {
    inline for (1..5) |i| if (fb & ~fbMask(i) == fbTemplate(i)) return i;
    return error.InvalidFirstByte;
}

/// Checks if the given byte is the first byte of a codepoint.
pub fn isFirstByte(fb: u8) bool {
    inline for (1..5) |i| if (fb & ~fbMask(i) == fbTemplate(i)) return true;
    return false;
}

/// Checks if the given byte is part of a codepoint.
pub fn isIntermediateByte(ib: u8) bool {
    if (ib & ~ib_mask == ib_template) return true;
    return false;
}

/// Checks if the given data is a valid UTF-8 string.
pub fn isValid(data: []const u8) bool {
    _ = validateAll(null, data) catch return false;
    return true;
}

pub const LenError = ValidateAllError;

/// Calculates the number of codepoints stored in `data`. Use `validateAll` for
/// detailed errors.
pub fn len(data: []const u8) LenError!usize {
    return validateAll(null, data);
}

pub const Position = struct { i: usize, j: usize };

/// Obtains the underlying starting and ending indexes of the next valid
/// codepoint.
pub fn nextValidPosition(data: []const u8) ?Position {
    return nextValidPositionAt(0, data);
}

/// Obtains the underlying starting and ending indexes of the next valid
/// codepoint. Starts looking from `idx`.
pub fn nextValidPositionAt(idx: usize, data: []const u8) ?Position {
    var i = idx;

    while (i < data.len) {
        const j = validate(null, data[i..]) catch {
            i += 1;
            continue;
        };

        return .{ .i = i, .j = i + j };
    }

    return null;
}

pub const ValidationError = ValidateError || ValidateAllError;

pub const ValidateDiagnostic = struct {
    /// Index where the error occurred.
    index: usize = 0,

    /// Expected number of bytes of invalid codepoint.
    expected_len: u3 = 0,
};

pub const ValidateError = error{
    EmptyInput,
    IncompleteInput,
    InvalidIntermediateByte,
} || DecodeLenError;

/// Checks if the given data starts with a UTF-8 encoded codepoint, but doesn't
/// try to decode it. If valid, returns how many bytes where checked.
pub fn validate(
    diagnostic: ?*ValidateDiagnostic,
    data: []const u8,
) ValidateError!u3 {
    const l = try decodeLen(data);
    if (l == 0) return error.EmptyInput;

    errdefer {
        if (diagnostic) |diag| diag.expected_len = l;
    }

    if (data.len < l) return error.IncompleteInput;

    for (1..l) |i| {
        if (!isIntermediateByte(data[i])) {
            if (diagnostic) |diag| diag.index = i;
            return error.InvalidIntermediateByte;
        }
    }

    return l;
}

pub const ValidateAllError = ValidateError;

/// Checks if the given data is a UTF-8 encoded string. If valid, returns how
/// many codepoints where checked.
pub fn validateAll(
    diagnostic: ?*ValidateDiagnostic,
    data: []const u8,
) ValidateAllError!usize {
    if (data.len == 0) return 0;

    var i: usize = 0;
    var n: usize = 0;

    while (validate(diagnostic, data[i..])) |l| {
        n += 1;
        i += l;
        if (i >= data.len) break;
    } else |err| {
        if (diagnostic) |diag| diag.index += i;
        return err;
    }

    return n;
}

// ////////////
// Iterators //
// ////////////

pub const IteratorError = error{
    InvalidPosition,
} || DecodeLenError || ValidateAllError;

fn iteratorNextIndex(data: *[]const u8, pos: Position) Position {
    const last = Position{ .i = data.len, .j = data.len +| 1 };
    if (pos.i >= data.len or pos.j > data.len) return last;
    const l = decodeLen(data.*[pos.j..]) catch return last;
    return .{ .i = pos.j, .j = pos.j +| l };
}

fn iteratorWithErrorNextIndex(data: *[]const u8, pos: Position) IteratorError!Position {
    if (pos.i > pos.j) return error.InvalidPosition;
    const last = Position{ .i = data.len, .j = data.len +| 1 };
    if (pos.i >= data.len or pos.j > data.len) return last;
    const l = try decodeLen(data.*[pos.j..]);
    return .{ .i = pos.j, .j = pos.j +| l };
}

// Bytes //

pub fn bytesIterator(data: []const u8) IteratorError!iterators.Iterator(
    []const u8,
    Position,
    []const u8,
    null,
    iteratorNextIndex,
    bytesIteratorGetItem,
) {
    _ = try validateAll(null, data);
    const l = try decodeLen(data);
    return .{ .ctx = data, .index = .{ .i = 0, .j = l } };
}

fn bytesIteratorGetItem(data: *[]const u8, pos: Position) ?[]const u8 {
    if (pos.i >= data.len or pos.j > data.len) return null;
    return data.*[pos.i..pos.j];
}

pub fn bytesIteratorWithError(data: []const u8) IteratorError!iterators.Iterator(
    []const u8,
    Position,
    []const u8,
    IteratorError,
    iteratorWithErrorNextIndex,
    bytesIteratorWithErrorGetItem,
) {
    _ = try validateAll(null, data);
    const l = try decodeLen(data);
    return .{ .ctx = data, .index = .{ .i = 0, .j = l } };
}

fn bytesIteratorWithErrorGetItem(data: *[]const u8, pos: Position) IteratorError!?[]const u8 {
    if (pos.i > pos.j) return error.InvalidPosition;
    if (pos.i >= data.len or pos.j > data.len) return null;
    return data.*[pos.i..pos.j];
}

// Codepoint //

pub fn iterator(data: []const u8) IteratorError!iterators.Iterator(
    []const u8,
    Position,
    unicode.Codepoint,
    null,
    iteratorNextIndex,
    iteratorGetItem,
) {
    _ = try validateAll(null, data);
    const l = try decodeLen(data);
    return .{ .ctx = data, .index = .{ .i = 0, .j = l } };
}

fn iteratorGetItem(data: *[]const u8, pos: Position) ?unicode.Codepoint {
    if (pos.i >= data.len) return null;
    var cp = unicode.Codepoint{ .value = 0 };
    _ = decode(&cp, data.*[pos.i..]) catch unreachable;
    return cp;
}

pub fn iteratorWithError(data: []const u8) IteratorError!iterators.Iterator(
    []const u8,
    Position,
    unicode.Codepoint,
    IteratorError,
    iteratorWithErrorNextIndex,
    iteratorWithErrorGetItem,
) {
    _ = try validateAll(null, data);
    const l = try decodeLen(data);
    return .{ .ctx = data, .index = .{ .i = 0, .j = l } };
}

fn iteratorWithErrorGetItem(data: *[]const u8, pos: Position) IteratorError!?unicode.Codepoint {
    if (pos.i > pos.j) return error.InvalidPosition;
    if (pos.i >= data.len) return null;
    var cp = unicode.Codepoint{ .value = 0 };
    _ = try decode(&cp, data.*[pos.i..]);
    return cp;
}
