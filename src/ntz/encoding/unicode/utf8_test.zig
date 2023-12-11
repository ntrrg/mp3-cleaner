// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const encoding = ntz.encoding;
const unicode = encoding.unicode;
const io = ntz.io;
const testing = ntz.testing;

const utf8 = unicode.utf8;

test "ntz.encoding.unicode.utf8" {
    testing.refAllDecls(utf8);
}

// /////////
// decode //
// /////////

test "ntz.encoding.unicode.utf8.decode: one byte" {
    const in = "$";
    const want = try unicode.Codepoint.init('$');

    var buf = std.io.fixedBufferStream(in);
    //var cr = io.countingReader(buf.reader());

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decode(&got, buf.reader());

    try testing.expectEql(got, want);
    try testing.expectEql(n, 1);
    //try testing.expectEql(cr.read_count, 1);
    //try testing.expectEql(cr.byte_count, n);
}

test "ntz.encoding.unicode.utf8.decode: two bytes" {
    const in = "¢";
    const want = try unicode.Codepoint.init('¢');

    var buf = std.io.fixedBufferStream(in);
    //var cr = io.countingReader(buf.reader());

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decode(&got, buf.reader());

    try testing.expectEql(got, want);
    try testing.expectEql(n, 2);
    //try testing.expectEql(cr.read_count, 1);
    //try testing.expectEql(cr.byte_count, n);
}

test "ntz.encoding.unicode.utf8.decode: three bytes" {
    const in = "€";
    const want = try unicode.Codepoint.init('€');

    var buf = std.io.fixedBufferStream(in);
    //var cr = io.countingReader(buf.reader());

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decode(&got, buf.reader());

    try testing.expectEql(got, want);
    try testing.expectEql(n, 3);
    //try testing.expectEql(cr.read_count, 1);
    //try testing.expectEql(cr.byte_count, n);
}

test "ntz.encoding.unicode.utf8.decode: four bytes" {
    const in = "💰";
    const want = try unicode.Codepoint.init('💰');

    var buf = std.io.fixedBufferStream(in);
    //var cr = io.countingReader(buf.reader());

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decode(&got, buf.reader());

    try testing.expectEql(got, want);
    try testing.expectEql(n, 4);
    //try testing.expectEql(cr.read_count, 1);
    //try testing.expectEql(cr.byte_count, n);
}

// ////////////
// decodeBuf //
// ////////////

test "ntz.encoding.unicode.utf8.decodeBuf: one byte" {
    const in = "$";
    const want = try unicode.Codepoint.init('$');

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decodeBuf(&got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 1);
}

test "ntz.encoding.unicode.utf8.decodeBuf: two bytes" {
    const in = "¢";
    const want = try unicode.Codepoint.init('¢');

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decodeBuf(&got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 2);
}

test "ntz.encoding.unicode.utf8.decodeBuf: three bytes" {
    const in = "€";
    const want = try unicode.Codepoint.init('€');

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decodeBuf(&got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 3);
}

test "ntz.encoding.unicode.utf8.decodeBuf: four bytes" {
    const in = "💰";
    const want = try unicode.Codepoint.init('💰');

    var got = unicode.Codepoint{ .val = 0 };
    const n = try utf8.decodeBuf(&got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 4);
}

// /////////
// encode //
// /////////

test "ntz.encoding.unicode.utf8.encode: one byte" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    var cw = io.countingWriter(buf.writer());

    const in = try unicode.Codepoint.init('$');
    const want = "$";

    const n = try utf8.encode(&cw, in);

    try testing.expectEqlStrs(buf.items, want);
    try testing.expectEql(n, 1);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, n);
}

test "ntz.encoding.unicode.utf8.encode: two bytes" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    var cw = io.countingWriter(buf.writer());

    const in = try unicode.Codepoint.init('¢');
    const want = "¢";

    const n = try utf8.encode(&cw, in);

    try testing.expectEqlStrs(buf.items, want);
    try testing.expectEql(n, 2);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, n);
}

test "ntz.encoding.unicode.utf8.encode: three bytes" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    var cw = io.countingWriter(buf.writer());

    const in = try unicode.Codepoint.init('€');
    const want = "€";

    const n = try utf8.encode(&cw, in);

    try testing.expectEqlStrs(buf.items, want);
    try testing.expectEql(n, 3);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, n);
}

test "ntz.encoding.unicode.utf8.encode: four bytes" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    var cw = io.countingWriter(buf.writer());

    const in = try unicode.Codepoint.init('💰');
    const want = "💰";

    const n = try utf8.encode(&cw, in);

    try testing.expectEqlStrs(buf.items, want);
    try testing.expectEql(n, 4);
    try testing.expectEql(cw.write_count, 1);
    try testing.expectEql(cw.byte_count, n);
}

// ////////////
// encodeBuf //
// ////////////

test "ntz.encoding.unicode.utf8.encodeBuf: one byte" {
    const in = try unicode.Codepoint.init('$');
    const want = "$";

    var got: [1]u8 = undefined;
    const n = try utf8.encodeBuf(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 1);
}

test "ntz.encoding.unicode.utf8.encodeBuf: two bytes" {
    const in = try unicode.Codepoint.init('¢');
    const want = "¢";

    var got: [2]u8 = undefined;
    const n = try utf8.encodeBuf(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 2);
}

test "ntz.encoding.unicode.utf8.encodeBuf: three bytes" {
    const in = try unicode.Codepoint.init('€');
    const want = "€";

    var got: [3]u8 = undefined;
    const n = try utf8.encodeBuf(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 3);
}

test "ntz.encoding.unicode.utf8.encodeBuf: four bytes" {
    const in = try unicode.Codepoint.init('💰');
    const want = "💰";

    var got: [4]u8 = undefined;
    const n = try utf8.encodeBuf(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 4);
}

test "ntz.encoding.unicode.utf8.encodeBuf: small buffer" {
    const in = try unicode.Codepoint.init('$');
    var got: [0]u8 = undefined;
    try testing.expectErr(utf8.encodeBuf(&got, in), encoding.Error.OutputTooSmall);
}

// //////////////
// lenFromByte //
// //////////////

test "ntz.encoding.unicode.utf8.lenFromByte" {
    // One byte.

    try testing.expectEql(try utf8.lenFromByte(0), 1);
    try testing.expectEql(try utf8.lenFromByte('$'), 1);
    try testing.expectEql(try utf8.lenFromByte(0b0111_1111), 1);

    // Two bytes.

    try testing.expectEql(try utf8.lenFromByte(0b110_00010), 2);
    try testing.expectEql(try utf8.lenFromByte("¢"[0]), 2);
    try testing.expectEql(try utf8.lenFromByte(0b110_10111), 2);

    // Three bytes.

    try testing.expectEql(try utf8.lenFromByte(0b1110_0000), 3);
    try testing.expectEql(try utf8.lenFromByte("€"[0]), 3);
    try testing.expectEql(try utf8.lenFromByte(0b1110_1111), 3);

    // Four bytes.

    try testing.expectEql(try utf8.lenFromByte(0b11110_000), 4);
    try testing.expectEql(try utf8.lenFromByte("💰"[0]),  4);
    try testing.expectEql(try utf8.lenFromByte(0b11110_111), 4);

    // Invalid first byte.

    try testing.expectErr(utf8.lenFromByte(0b111110_11), utf8.Error.InvalidFirstByte);
    try testing.expectErr(utf8.lenFromByte(0b1111110_1), utf8.Error.InvalidFirstByte);
    try testing.expectErr(utf8.lenFromByte(0b1111_1110), utf8.Error.InvalidFirstByte);
    try testing.expectErr(utf8.lenFromByte(0b1111_1111), utf8.Error.InvalidFirstByte);
}

// ///////////////
// lenFromBytes //
// ///////////////

test "ntz.encoding.unicode.utf8.lenFromBytes" {
    try testing.expectEql(try utf8.lenFromBytes(""), 0);
    try testing.expectEql(try utf8.lenFromBytes("$"), 1);
    try testing.expectEql(try utf8.lenFromBytes("¢"), 2);
    try testing.expectEql(try utf8.lenFromBytes("€"), 3);
    try testing.expectEql(try utf8.lenFromBytes("💰"), 4);

    try testing.expectEql(try utf8.lenFromBytes("$¢€💰"), 1);
    try testing.expectEql(try utf8.lenFromBytes("¢€💰$"), 2);
    try testing.expectEql(try utf8.lenFromBytes("€💰$¢"), 3);
    try testing.expectEql(try utf8.lenFromBytes("💰$¢€"), 4);

    try testing.expectErr(utf8.lenFromBytes("\xF0"), encoding.Error.IncompleteInput);
}

// ///////////////////
// lenFromCodepoint //
// ///////////////////

test "ntz.encoding.unicode.utf8.lenFromCodepoint" {
    // One byte.

    var in = try unicode.Codepoint.init(0);
    try testing.expectEql(utf8.lenFromCodepoint(in), 1);

    in = try unicode.Codepoint.init('$');
    try testing.expectEql(utf8.lenFromCodepoint(in), 1);

    in = try unicode.Codepoint.init(0b0111_1111);
    try testing.expectEql(utf8.lenFromCodepoint(in), 1);

    // Two bytes.

    in = try unicode.Codepoint.init(0b1000_0000);
    try testing.expectEql(utf8.lenFromCodepoint(in), 2);

    in = try unicode.Codepoint.init('¢');
    try testing.expectEql(utf8.lenFromCodepoint(in), 2);

    in = try unicode.Codepoint.init(0b0111_1111_1111);
    try testing.expectEql(utf8.lenFromCodepoint(in), 2);

    // Three bytes.

    in = try unicode.Codepoint.init(0b1000_0000_0000);
    try testing.expectEql(utf8.lenFromCodepoint(in), 3);

    in = try unicode.Codepoint.init('€');
    try testing.expectEql(utf8.lenFromCodepoint(in), 3);

    in = try unicode.Codepoint.init(0b1111_1111_1111_1111);
    try testing.expectEql(utf8.lenFromCodepoint(in), 3);

    // Four bytes.

    in = try unicode.Codepoint.init(0b0001_0000_0000_0000_0000);
    try testing.expectEql(utf8.lenFromCodepoint(in), 4);

    in = try unicode.Codepoint.init('💰');
    try testing.expectEql(utf8.lenFromCodepoint(in), 4);

    in = try unicode.Codepoint.init(0b0001_1111_1111_1111_1111_1111);
    try testing.expectEql(utf8.lenFromCodepoint(in), 4);
}
