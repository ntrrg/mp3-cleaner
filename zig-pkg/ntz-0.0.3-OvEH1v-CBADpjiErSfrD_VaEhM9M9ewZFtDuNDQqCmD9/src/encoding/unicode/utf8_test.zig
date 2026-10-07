// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const test_options = @import("test_options");

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const encoding = ntz.encoding;
const unicode = encoding.unicode;
const types = ntz.types;
const bytes = types.bytes;

const utf8 = unicode.utf8;

// Codepoints:
// - $ \x24 \u{0024}
// - ¢ \xC2\xA2 \u{00A2}
// - € \xE2\x82\xAC \u{20AC}
// - 💰 \xF0\x9F\x92\xB0 \u{1F4B0}

const all = "$¢€💰";
const dollar = '$';
const cent = '¢';
const euro = '€';
const bag = '💰';

const dollarStr = "$";
const centStr = "¢";
const euroStr = "€";
const bagStr = "💰";

const dollarCp = unicode.Codepoint{ .value = 0x24 };
const centCp = unicode.Codepoint{ .value = 0xA2 };
const euroCp = unicode.Codepoint{ .value = 0x20AC };
const bagCp = unicode.Codepoint{ .value = 0x1F4B0 };

test "ntz.encoding.unicode.utf8" {}

test "ntz.encoding.unicode.utf8: all codepoints" {
    if (!test_options.run_slow) return testing.skip();

    for (0..0x10FFFF) |i| {
        if (unicode.isSurrogateCharacter(i)) continue;

        var buf: [4]u8 = undefined;

        const want = try unicode.Codepoint.init(@intCast(i));
        const n = try utf8.encode(buf[0..], want);

        var got = unicode.Codepoint{ .value = 0 };
        _ = try utf8.decode(&got, buf[0..n]);

        try testing.expectEqual(want, got);
    }
}

// ///////////
// Encoding //
// ///////////

// encode //

test "ntz.encoding.unicode.utf8.encode" {
    var got: [4]u8 = undefined;

    var n = try utf8.encode(&got, dollarCp);
    try testing.expectEqualStrings(dollarStr, got[0..n]);
    try testing.expectEqual(n, 1);

    n = try utf8.encode(&got, centCp);
    try testing.expectEqualStrings(centStr, got[0..n]);
    try testing.expectEqual(n, 2);

    n = try utf8.encode(&got, euroCp);
    try testing.expectEqualStrings(euroStr, got[0..n]);
    try testing.expectEqual(n, 3);

    n = try utf8.encode(&got, bagCp);
    try testing.expectEqualStrings(bagStr, got[0..n]);
    try testing.expectEqual(n, 4);
}

test "ntz.encoding.unicode.utf8.encode: small buffer" {
    var got: [0]u8 = undefined;

    try testing.expectError(
        utf8.EncodeError.OutOfMemory,
        utf8.encode(&got, dollarCp),
    );
}

// encodeLen //

test "ntz.encoding.unicode.utf8.encodeLen" {
    // One byte.

    var in = try unicode.Codepoint.init(0);
    try testing.expectEqual(1, utf8.encodeLen(in));

    try testing.expectEqual(1, utf8.encodeLen(dollarCp));

    in = try unicode.Codepoint.init(0b0111_1111);
    try testing.expectEqual(1, utf8.encodeLen(in));

    // Two bytes.

    in = try unicode.Codepoint.init(0b1000_0000);
    try testing.expectEqual(2, utf8.encodeLen(in));

    try testing.expectEqual(2, utf8.encodeLen(centCp));

    in = try unicode.Codepoint.init(0b0111_1111_1111);
    try testing.expectEqual(2, utf8.encodeLen(in));

    // Three bytes.

    in = try unicode.Codepoint.init(0b1000_0000_0000);
    try testing.expectEqual(3, utf8.encodeLen(in));

    try testing.expectEqual(3, utf8.encodeLen(euroCp));

    in = try unicode.Codepoint.init(0b1111_1111_1111_1111);
    try testing.expectEqual(3, utf8.encodeLen(in));

    // Four bytes.

    in = try unicode.Codepoint.init(0b0001_0000_0000_0000_0000);
    try testing.expectEqual(4, utf8.encodeLen(in));

    try testing.expectEqual(4, utf8.encodeLen(bagCp));

    in = try unicode.Codepoint.init(0x10FFFF);
    try testing.expectEqual(4, utf8.encodeLen(in));
}

// ///////////
// Decoding //
// ///////////

// clear //

test "ntz.encoding.unicode.utf8.clear" {
    var in = "\xF0\x24\x80 \x80\xC2\xA2 \xC2\xE2\x82\xAC\xB0 \xF0\x9F\x92\xB0";
    const want = "\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0";
    var buf: [want.len]u8 = undefined;
    const got = try utf8.clear(&buf, in[0..]);
    try testing.expectEqualStrings(want, got);

    try testing.expectEqualStrings("", try utf8.clear(buf[0..0], ""));
    try testing.expectEqualStrings("", try utf8.clear(buf[0..4], "\xFF"));

    try testing.expectError(
        utf8.ClearError.OutOfMemory,
        utf8.clear(buf[0..1], "\xF0\x9F\x92\xB0"),
    );
}

// clearIn //

test "ntz.encoding.unicode.utf8.clearIn" {
    var in = bytes.mut("\xF0\x24\x80 \x80\xC2\xA2 \xC2\xE2\x82\xAC\xB0 \xF0\x9F\x92\xB0");
    const want = "\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0";
    const got = utf8.clearIn(in[0..]);
    try testing.expectEqualStrings(want, got);
}

// countBytes //

test "ntz.encoding.unicode.utf8.countBytes" {
    try testing.expectEqual(1, utf8.countBytes("\xFF\x24"));
    try testing.expectEqual(2, utf8.countBytes("\xFF\xC2\xA2"));
    try testing.expectEqual(3, utf8.countBytes("\xFF\xE2\x82\xAC"));
    try testing.expectEqual(4, utf8.countBytes("\xFF\xF0\x9F\x92\xB0"));

    try testing.expectEqual(
        utf8.countBytes("\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0"),
        13,
    );

    try testing.expectEqual(0, utf8.countBytes("\xF0"));
    try testing.expectEqual(0, utf8.countBytes("\xFF\xFF\xFF\xFF"));
    try testing.expectEqual(0, utf8.countBytes("\xF0\xFF\xFF\xFF"));
}

// decode //

test "ntz.encoding.unicode.utf8.decode" {
    var got = unicode.Codepoint{ .value = 0 };
    var n = try utf8.decode(&got, dollarStr);
    try testing.expectEqual(dollarCp, got);
    try testing.expectEqual(1, n);

    got = unicode.Codepoint{ .value = 0 };
    n = try utf8.decode(&got, centStr);
    try testing.expectEqual(centCp, got);
    try testing.expectEqual(2, n);

    got = unicode.Codepoint{ .value = 0 };
    n = try utf8.decode(&got, euroStr);
    try testing.expectEqual(euroCp, got);
    try testing.expectEqual(3, n);

    got = unicode.Codepoint{ .value = 0 };
    n = try utf8.decode(&got, bagStr);
    try testing.expectEqual(bagCp, got);
    try testing.expectEqual(4, n);
}

test "ntz.encoding.unicode.utf8.decode: empty" {
    var got = unicode.Codepoint{ .value = 0 };
    try testing.expectError(utf8.DecodeError.EmptyInput, utf8.decode(&got, ""));
}

// decodeLen //

test "ntz.encoding.unicode.utf8.decodeLen" {
    try testing.expectEqual(0, try utf8.decodeLen(""));
    try testing.expectEqual(1, try utf8.decodeLen(dollarStr));
    try testing.expectEqual(2, try utf8.decodeLen(centStr));
    try testing.expectEqual(3, try utf8.decodeLen(euroStr));
    try testing.expectEqual(4, try utf8.decodeLen(bagStr));

    try testing.expectEqual(1, try utf8.decodeLen("$¢€\u{1F4B0}"));
    try testing.expectEqual(2, try utf8.decodeLen("¢€\u{1F4B0}$"));
    try testing.expectEqual(3, try utf8.decodeLen("€\u{1F4B0}$¢"));
    try testing.expectEqual(4, try utf8.decodeLen("\u{1F4B0}$¢€"));
}

// decodeLenFb //

test "ntz.encoding.unicode.utf8.decodeLenFb" {
    try testing.expectEqual(1, try utf8.decodeLenFb(0));
    try testing.expectEqual(1, try utf8.decodeLenFb(0x24));
    try testing.expectEqual(1, try utf8.decodeLenFb(0b0111_1111));

    try testing.expectEqual(2, try utf8.decodeLenFb(0b110_00000));
    try testing.expectEqual(2, try utf8.decodeLenFb(0xC2));
    try testing.expectEqual(2, try utf8.decodeLenFb(0b110_11111));

    try testing.expectEqual(3, try utf8.decodeLenFb(0b1110_0000));
    try testing.expectEqual(3, try utf8.decodeLenFb(0xE2));
    try testing.expectEqual(3, try utf8.decodeLenFb(0b1110_1111));

    try testing.expectEqual(4, try utf8.decodeLenFb(0b11110_000));
    try testing.expectEqual(4, try utf8.decodeLenFb(0xF0));
    try testing.expectEqual(4, try utf8.decodeLenFb(0b11110_111));

    try testing.expectError(
        utf8.DecodeLenFBError.InvalidFirstByte,
        utf8.decodeLenFb(0b111110_11),
    );

    try testing.expectError(
        utf8.DecodeLenFBError.InvalidFirstByte,
        utf8.decodeLenFb(0b1111110_1),
    );

    try testing.expectError(
        utf8.DecodeLenFBError.InvalidFirstByte,
        utf8.decodeLenFb(0b1111_1110),
    );

    try testing.expectError(
        utf8.DecodeLenFBError.InvalidFirstByte,
        utf8.decodeLenFb(0b1111_1111),
    );
}

// isFirstByte //

test "ntz.encoding.unicode.utf8.isFirstByte" {
    try testing.expect(utf8.isFirstByte(0));
    try testing.expect(utf8.isFirstByte(0x24));
    try testing.expect(utf8.isFirstByte(0b0111_1111));

    try testing.expect(utf8.isFirstByte(0b110_00000));
    try testing.expect(utf8.isFirstByte(0xC2));
    try testing.expect(utf8.isFirstByte(0b110_11111));

    try testing.expect(utf8.isFirstByte(0b1110_0000));
    try testing.expect(utf8.isFirstByte(0xE2));
    try testing.expect(utf8.isFirstByte(0b1110_1111));

    try testing.expect(utf8.isFirstByte(0b11110_000));
    try testing.expect(utf8.isFirstByte(0xF0));
    try testing.expect(utf8.isFirstByte(0b11110_111));

    try testing.expect(!utf8.isFirstByte(0b10_000000));
    try testing.expect(!utf8.isFirstByte(0b111110_11));
    try testing.expect(!utf8.isFirstByte(0b1111110_1));
    try testing.expect(!utf8.isFirstByte(0b1111_1110));
    try testing.expect(!utf8.isFirstByte(0b1111_1111));
}

// isIntermediateByte //

test "ntz.encoding.unicode.utf8.isIntermediateByte" {
    try testing.expect(!utf8.isIntermediateByte(0b0111_1111));
    try testing.expect(utf8.isIntermediateByte(0b10_000000));
    try testing.expect(utf8.isIntermediateByte(0b10_111111));
    try testing.expect(!utf8.isIntermediateByte(0b11_000000));
}

// isValid //

test "ntz.encoding.unicode.utf8.isValid" {
    try testing.expect(utf8.isValid(""));
    try testing.expect(utf8.isValid(dollarStr));
    try testing.expect(utf8.isValid(centStr));
    try testing.expect(utf8.isValid(euroStr));
    try testing.expect(utf8.isValid(bagStr));
    try testing.expect(utf8.isValid(all));
    try testing.expect(utf8.isValid("\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0"));
    try testing.expect(!utf8.isValid("\x80\x80\x80\x80\x80"));
}

// len //

test "ntz.encoding.unicode.utf8.len" {
    try testing.expectEqual(0, try utf8.len(""));
    try testing.expectEqual(1, try utf8.len(dollarStr));
    try testing.expectEqual(1, try utf8.len(centStr));
    try testing.expectEqual(1, try utf8.len(euroStr));
    try testing.expectEqual(1, try utf8.len(bagStr));
    try testing.expectEqual(4, try utf8.len(all));

    try testing.expectEqual(15, try utf8.len("hello, world $!"));
    try testing.expectEqual(15, try utf8.len("hello, world ¢!"));
    try testing.expectEqual(15, try utf8.len("hello, world €!"));
    try testing.expectEqual(15, try utf8.len("hello, world \u{1F4B0}!"));
}

// nextValidPosition //
// nextValidPositionAt //

test "ntz.encoding.unicode.utf8.nextValidPosition" {
    try testing.expectEqualDeep(null, utf8.nextValidPosition(""));

    try testing.expectEqualDeep(
        utf8.Position{ .i = 0, .j = 1 },
        utf8.nextValidPosition(dollarStr),
    );

    try testing.expectEqualDeep(
        utf8.Position{ .i = 0, .j = 2 },
        utf8.nextValidPosition(centStr),
    );

    try testing.expectEqualDeep(
        utf8.Position{ .i = 0, .j = 3 },
        utf8.nextValidPosition(euroStr),
    );

    try testing.expectEqualDeep(
        utf8.Position{ .i = 0, .j = 4 },
        utf8.nextValidPosition(bagStr),
    );

    try testing.expectEqualDeep(null, utf8.nextValidPosition("\x80\x80\x80\x80\x80"));

    const in = "\xF0\x24\x80\x80\xC2\xA2\xC2\xE2\x82\xAC\xB0\xF0\x9F\x92\xB0";

    try testing.expectEqualDeep(
        utf8.Position{ .i = 1, .j = 2 },
        utf8.nextValidPosition(in),
    );

    try testing.expectEqualDeep(
        utf8.Position{ .i = 4, .j = 6 },
        utf8.nextValidPositionAt(2, in),
    );

    try testing.expectEqualDeep(
        utf8.Position{ .i = 7, .j = 10 },
        utf8.nextValidPositionAt(5, in),
    );

    try testing.expectEqualDeep(
        utf8.Position{ .i = 11, .j = 15 },
        utf8.nextValidPositionAt(8, in),
    );

    try testing.expectEqualDeep(null, utf8.nextValidPositionAt(12, in));
}

// validate //

test "ntz.encoding.unicode.utf8.validate" {
    try testing.expectEqual(1, try utf8.validate(null, dollarStr));
    try testing.expectEqual(2, try utf8.validate(null, centStr));
    try testing.expectEqual(3, try utf8.validate(null, euroStr));
    try testing.expectEqual(4, try utf8.validate(null, bagStr));
    try testing.expectEqual(1, try utf8.validate(null, "\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0"));
}

test "ntz.encoding.unicode.utf8.validate: invalid bytes" {
    var diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateError.EmptyInput,
        utf8.validate(&diag, ""),
    );

    try testing.expectEqual(0, diag.index);
    try testing.expectEqual(0, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateError.InvalidFirstByte,
        utf8.validate(&diag, "\xFF\x0F\x0F\x0F"),
    );

    try testing.expectEqual(0, diag.index);
    try testing.expectEqual(0, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateError.IncompleteInput,
        utf8.validate(&diag, "\xF0"),
    );

    try testing.expectEqual(0, diag.index);
    try testing.expectEqual(4, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateError.InvalidIntermediateByte,
        utf8.validate(&diag, "\xF0\x0F\x0F\x0F"),
    );

    try testing.expectEqual(1, diag.index);
    try testing.expectEqual(4, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateError.InvalidIntermediateByte,
        utf8.validate(&diag, "\xF0\x9F\x0F\x0F"),
    );

    try testing.expectEqual(2, diag.index);
    try testing.expectEqual(4, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateError.InvalidIntermediateByte,
        utf8.validate(&diag, "\xF0\x9F\x92\x0F"),
    );

    try testing.expectEqual(3, diag.index);
    try testing.expectEqual(4, diag.expected_len);
}

// validateAll //

test "ntz.encoding.unicode.utf8.validateAll" {
    try testing.expectEqual(0, try utf8.validateAll(null, ""));
    try testing.expectEqual(1, try utf8.validateAll(null, dollarStr));
    try testing.expectEqual(1, try utf8.validateAll(null, centStr));
    try testing.expectEqual(1, try utf8.validateAll(null, euroStr));
    try testing.expectEqual(1, try utf8.validateAll(null, bagStr));
    try testing.expectEqual(7, try utf8.validateAll(null, "\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0"));
}

test "ntz.encoding.unicode.utf8.validateAll: invalid bytes" {
    var diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateAllError.InvalidFirstByte,
        utf8.validateAll(&diag, " \xFF\x0F\x0F\x0F"),
    );

    try testing.expectEqual(1, diag.index);
    try testing.expectEqual(0, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateAllError.IncompleteInput,
        utf8.validateAll(&diag, " \xF0"),
    );

    try testing.expectEqual(1, diag.index);
    try testing.expectEqual(4, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateAllError.InvalidIntermediateByte,
        utf8.validateAll(&diag, " \xF0\x0F\x0F\x0F"),
    );

    try testing.expectEqual(2, diag.index);
    try testing.expectEqual(4, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateAllError.InvalidIntermediateByte,
        utf8.validateAll(&diag, " \xF0\x9F\x0F\x0F"),
    );

    try testing.expectEqual(3, diag.index);
    try testing.expectEqual(4, diag.expected_len);

    diag = utf8.ValidateDiagnostic{};

    try testing.expectError(
        utf8.ValidateAllError.InvalidIntermediateByte,
        utf8.validateAll(&diag, " \xF0\x9F\x92\x0F"),
    );

    try testing.expectEqual(4, diag.index);
    try testing.expectEqual(4, diag.expected_len);
}

// ////////////
// Iterators //
// ////////////

test "ntz.encoding.unicode.utf8.bytesIterator" {
    var it = try utf8.bytesIterator(all);

    try testing.expectEqualDeep(dollarStr, it.peek());
    try testing.expectEqualDeep(dollarStr, it.next());
    try testing.expectEqualDeep(centStr, it.peek());
    try testing.expectEqualDeep(euroStr, it.peekN(2));
    try testing.expectEqualDeep(bagStr, it.peekN(3));
    it.skip();
    try testing.expectEqualDeep(euroStr, it.peek());
    try testing.expectEqualDeep(bagStr, it.peekN(2));
    try testing.expectEqualDeep(null, it.peekN(3));
    it.skipN(10);
    try testing.expectEqualDeep(null, it.next());
    try testing.expectEqualDeep(null, it.peek());
    try testing.expectEqualDeep(null, it.peekN(2));
    try testing.expectEqualDeep(null, it.peekN(3));

    it.index = .{ .i = 0, .j = 1 };
    try testing.expectEqualDeep(bagStr, it.peekN(4));
    it.skipN(4);
    try testing.expectEqualDeep(null, it.peek());
    try testing.expectEqualDeep(null, it.next());

    try testing.expectEqualDeep(dollarStr, it.get(.{ .i = 0, .j = 1 }));
    try testing.expectEqualDeep(centStr, it.get(.{ .i = 1, .j = 3 }));
    try testing.expectEqualDeep(euroStr, it.get(.{ .i = 3, .j = 6 }));
    try testing.expectEqualDeep(bagStr, it.get(.{ .i = 6, .j = 10 }));
}

test "ntz.encoding.unicode.utf8.bytesIteratorWithError" {
    var it = try utf8.bytesIteratorWithError(all);

    try testing.expectEqualDeep(dollarStr, try it.peek());
    try testing.expectEqualDeep(dollarStr, try it.next());
    try testing.expectEqualDeep(centStr, try it.peek());
    try testing.expectEqualDeep(euroStr, try it.peekN(2));
    try testing.expectEqualDeep(bagStr, try it.peekN(3));
    try it.skip();
    try testing.expectEqualDeep(euroStr, try it.peek());
    try testing.expectEqualDeep(bagStr, try it.peekN(2));
    try testing.expectEqualDeep(null, try it.peekN(3));
    try it.skipN(10);
    try testing.expectEqualDeep(null, try it.next());
    try testing.expectEqualDeep(null, try it.peek());
    try testing.expectEqualDeep(null, try it.peekN(2));
    try testing.expectEqualDeep(null, try it.peekN(3));

    it.index = .{ .i = 0, .j = 1 };
    try testing.expectEqualDeep(bagStr, try it.peekN(4));
    try it.skipN(4);
    try testing.expectEqualDeep(null, try it.peek());
    try testing.expectEqualDeep(null, try it.next());

    try testing.expectEqualDeep(dollarStr, try it.get(.{ .i = 0, .j = 1 }));
    try testing.expectEqualDeep(centStr, try it.get(.{ .i = 1, .j = 3 }));
    try testing.expectEqualDeep(euroStr, try it.get(.{ .i = 3, .j = 6 }));
    try testing.expectEqualDeep(bagStr, try it.get(.{ .i = 6, .j = 10 }));
}

test "ntz.encoding.unicode.utf8.iterator" {
    var it = try utf8.iterator(all);

    try testing.expectEqualDeep(dollarCp, it.peek());
    try testing.expectEqualDeep(dollarCp, it.next());
    try testing.expectEqualDeep(centCp, it.peek());
    try testing.expectEqualDeep(euroCp, it.peekN(2));
    try testing.expectEqualDeep(bagCp, it.peekN(3));
    it.skip();
    try testing.expectEqualDeep(euroCp, it.peek());
    try testing.expectEqualDeep(bagCp, it.peekN(2));
    try testing.expectEqualDeep(null, it.peekN(3));
    it.skipN(10);
    try testing.expectEqualDeep(null, it.next());
    try testing.expectEqualDeep(null, it.peek());
    try testing.expectEqualDeep(null, it.peekN(2));
    try testing.expectEqualDeep(null, it.peekN(3));

    it.index = .{ .i = 0, .j = 1 };
    try testing.expectEqualDeep(bagCp, it.peekN(4));
    it.skipN(4);
    try testing.expectEqualDeep(null, it.peek());
    try testing.expectEqualDeep(null, it.next());

    try testing.expectEqualDeep(dollarCp, it.get(.{ .i = 0, .j = 1 }));
    try testing.expectEqualDeep(centCp, it.get(.{ .i = 1, .j = 3 }));
    try testing.expectEqualDeep(euroCp, it.get(.{ .i = 3, .j = 6 }));
    try testing.expectEqualDeep(bagCp, it.get(.{ .i = 6, .j = 10 }));
}

test "ntz.encoding.unicode.utf8.iteratorWithError" {
    var it = try utf8.iteratorWithError(all);

    try testing.expectEqualDeep(dollarCp, try it.peek());
    try testing.expectEqualDeep(dollarCp, try it.next());
    try testing.expectEqualDeep(centCp, try it.peek());
    try testing.expectEqualDeep(euroCp, try it.peekN(2));
    try testing.expectEqualDeep(bagCp, try it.peekN(3));
    try it.skip();
    try testing.expectEqualDeep(euroCp, try it.peek());
    try testing.expectEqualDeep(bagCp, try it.peekN(2));
    try testing.expectEqualDeep(null, try it.peekN(3));
    try it.skipN(10);
    try testing.expectEqualDeep(null, try it.next());
    try testing.expectEqualDeep(null, try it.peek());
    try testing.expectEqualDeep(null, try it.peekN(2));
    try testing.expectEqualDeep(null, try it.peekN(3));

    it.index = .{ .i = 0, .j = 1 };
    try testing.expectEqualDeep(bagCp, try it.peekN(4));
    try it.skipN(4);
    try testing.expectEqualDeep(null, try it.peek());
    try testing.expectEqualDeep(null, try it.next());

    try testing.expectEqualDeep(dollarCp, try it.get(.{ .i = 0, .j = 1 }));
    try testing.expectEqualDeep(centCp, try it.get(.{ .i = 1, .j = 3 }));
    try testing.expectEqualDeep(euroCp, try it.get(.{ .i = 3, .j = 6 }));
    try testing.expectEqualDeep(bagCp, try it.get(.{ .i = 6, .j = 10 }));
}
