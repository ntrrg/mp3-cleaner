// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const test_options = @import("test_options");

const ntz = @import("ntz");
const encoding = ntz.encoding;
const unicode = encoding.unicode;
const io = ntz.io;
const testing = ntz.testing;

const utf8 = unicode.utf8;

// Codepoints:
// - $ \x24 \u{0024}
// - ¢ \xC2\xA2 \u{00A2}
// - € \xE2\x82\xAC \u{20AC}
// - 💰 \xF0\x9F\x92\xB0 \u{1F4B0}

test "ntz.encoding.unicode.utf8" {
    testing.refAllDecls(utf8);
}

test "ntz.encoding.unicode.utf8: all codepoints" {
    if (!test_options.run_slow) return testing.skip();

    for (0..0x10FFFF) |i| {
        if (unicode.isSurrogateCharacter(i)) continue;

        var buf: [4]u8 = undefined;

        const want = try unicode.Codepoint.init(@intCast(i));
        const n = try utf8.encode(buf[0..], want);

        var got = unicode.Codepoint{ .value = 0 };
        _ = try utf8.decode(null, &got, buf[0..n]);

        try testing.expectEql(got, want);
    }
}

// ///////////
// Iterator //
// ///////////

test "ntz.encoding.unicode.utf8.Iterator.count" {
    try testing.expectEql(try utf8.count(""), 0);
    try testing.expectEql(try utf8.count("$"), 1);
    try testing.expectEql(try utf8.count("¢"), 1);
    try testing.expectEql(try utf8.count("€"), 1);
    try testing.expectEql(try utf8.count("💰"), 1);
    try testing.expectEql(try utf8.count("$¢€\u{1F4B0}"), 4);

    try testing.expectEql(try utf8.count("hello, world $!"), 15);
    try testing.expectEql(try utf8.count("hello, world ¢!"), 15);
    try testing.expectEql(try utf8.count("hello, world €!"), 15);
    try testing.expectEql(try utf8.count("hello, world \u{1F4B0}!"), 15);

    try testing.expectErr(
        utf8.count("\xFF"),
        utf8.CountError.InvalidFirstByte,
    );

    try testing.expectErr(
        utf8.count("\xF0"),
        utf8.CountError.IncompleteInput,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.get" {
    var it = utf8.Iterator.init("$¢€💰");

    try testing.expectEql(try it.get(3), try unicode.Codepoint.init('💰'));
    try testing.expectEql(try it.get(2), try unicode.Codepoint.init('€'));
    try testing.expectEql(try it.get(1), try unicode.Codepoint.init('¢'));
    try testing.expectEql(try it.get(0), try unicode.Codepoint.init('$'));

    try testing.expectEql(
        try utf8.get("$\xFF", 0),
        try unicode.Codepoint.init('$'),
    );

    try testing.expectErr(
        utf8.get("$\xFF", 1),
        utf8.Iterator.GetError.InvalidFirstByte,
    );

    try testing.expectEql(
        try utf8.get("$\xF0", 0),
        try unicode.Codepoint.init('$'),
    );

    try testing.expectErr(
        utf8.get("$\xF0", 1),
        utf8.Iterator.GetError.IncompleteInput,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.getBytes" {
    var it = utf8.Iterator.init("$¢€💰");

    try testing.expectEqlStrs(try it.getBytes(3), "💰");
    try testing.expectEqlStrs(try it.getBytes(2), "€");
    try testing.expectEqlStrs(try it.getBytes(1), "¢");
    try testing.expectEqlStrs(try it.getBytes(0), "$");
    try testing.expectEqlStrs(try it.nextBytes(), "$");

    try testing.expectEqlStrs(try utf8.getBytes("$\xFF", 0), "$");

    try testing.expectErr(
        utf8.getBytes("$\xFF", 1),
        utf8.Iterator.GetBytesError.InvalidFirstByte,
    );

    try testing.expectEqlStrs(try utf8.getBytes("$\xF0", 0), "$");

    try testing.expectErr(
        utf8.getBytes("$\xF0", 1),
        utf8.Iterator.GetBytesError.IncompleteInput,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.index" {
    var it = utf8.Iterator.init("$¢€💰");

    try testing.expectEql(try it.index(0), .{ .i = 0, .j = 1 });
    try testing.expectEql(try it.index(1), .{ .i = 1, .j = 3 });
    try testing.expectEql(try it.index(2), .{ .i = 3, .j = 6 });
    try testing.expectEql(try it.index(3), .{ .i = 6, .j = 10 });

    try testing.expectEql(try utf8.index("$\xFF", 0), .{ .i = 0, .j = 1 });

    try testing.expectErr(
        utf8.index("$\xFF", 1),
        utf8.Iterator.IndexError.InvalidFirstByte,
    );

    try testing.expectEql(try utf8.index("$\xF0", 0), .{ .i = 0, .j = 1 });

    try testing.expectErr(
        utf8.index("$\xF0", 1),
        utf8.Iterator.IndexError.IncompleteInput,
    );

    try testing.expectErr(
        utf8.index("", 0),
        utf8.Iterator.IndexError.OutOfRange,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.next" {
    var it = utf8.Iterator.init("$¢€💰");

    try testing.expectEql(try it.next(), try unicode.Codepoint.init('$'));
    try testing.expectEql(try it.next(), try unicode.Codepoint.init('¢'));
    try testing.expectEql(try it.next(), try unicode.Codepoint.init('€'));
    try testing.expectEql(try it.next(), try unicode.Codepoint.init('💰'));

    try testing.expectErr(
        it.next(),
        utf8.Iterator.NextError.EndOfIteration,
    );

    try testing.expectErr(
        @constCast(&utf8.Iterator.init("\xFF")).next(),
        utf8.Iterator.NextBytesError.InvalidFirstByte,
    );

    try testing.expectErr(
        @constCast(&utf8.Iterator.init("\xF0")).next(),
        utf8.Iterator.NextBytesError.IncompleteInput,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.nextByte" {
    var it = utf8.Iterator.init("$¢€💰");

    try testing.expectEql(try it.nextByte(), '$');

    try testing.expectEqlStrs(&.{
        try it.nextByte(),
        try it.nextByte(),
    }, "¢");

    try testing.expectEqlStrs(&.{
        try it.nextByte(),
        try it.nextByte(),
        try it.nextByte(),
    }, "€");

    try testing.expectEqlStrs(&.{
        try it.nextByte(),
        try it.nextByte(),
        try it.nextByte(),
        try it.nextByte(),
    }, "💰");

    try testing.expectErr(
        it.nextByte(),
        utf8.Iterator.NextBytesError.EndOfIteration,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.nextBytes" {
    var it = utf8.Iterator.init("$¢€💰");

    try testing.expectEqlStrs(try it.nextBytes(), "$");
    try testing.expectEqlStrs(try it.nextBytes(), "¢");
    try testing.expectEqlStrs(try it.nextBytes(), "€");
    try testing.expectEqlStrs(try it.nextBytes(), "💰");

    try testing.expectErr(
        it.nextBytes(),
        utf8.Iterator.NextBytesError.EndOfIteration,
    );

    try testing.expectErr(
        @constCast(&utf8.Iterator.init("\xFF")).nextBytes(),
        utf8.Iterator.NextBytesError.InvalidFirstByte,
    );

    try testing.expectErr(
        @constCast(&utf8.Iterator.init("\xF0")).nextBytes(),
        utf8.Iterator.NextBytesError.IncompleteInput,
    );
}

test "ntz.encoding.unicode.utf8.Iterator.skip" {
    var it = utf8.Iterator.init("$¢€💰");

    try it.skip();
    try testing.expectEqlStrs(try it.nextBytes(), "¢");
    try it.skip();
    try testing.expectEqlStrs(try it.nextBytes(), "💰");

    try testing.expectErr(
        it.skip(),
        utf8.Iterator.SkipError.EndOfIteration,
    );

    try testing.expectErr(
        @constCast(&utf8.Iterator.init("\xFF")).skip(),
        utf8.Iterator.SkipError.InvalidFirstByte,
    );

    try testing.expectErr(
        @constCast(&utf8.Iterator.init("\xF0")).skip(),
        utf8.Iterator.SkipError.IncompleteInput,
    );
}

// /////////
// decode //
// /////////

test "ntz.encoding.unicode.utf8.decode: one byte" {
    const in = "$";
    const want = try unicode.Codepoint.init('$');

    var got = unicode.Codepoint{ .value = 0 };
    const n = try utf8.decode(null, &got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 1);
}

test "ntz.encoding.unicode.utf8.decode: two bytes" {
    const in = "¢";
    const want = try unicode.Codepoint.init('¢');

    var got = unicode.Codepoint{ .value = 0 };
    const n = try utf8.decode(null, &got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 2);
}

test "ntz.encoding.unicode.utf8.decode: three bytes" {
    const in = "€";
    const want = try unicode.Codepoint.init('€');

    var got = unicode.Codepoint{ .value = 0 };
    const n = try utf8.decode(null, &got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 3);
}

test "ntz.encoding.unicode.utf8.decode: four bytes" {
    const in = "💰";
    const want = try unicode.Codepoint.init('💰');

    var got = unicode.Codepoint{ .value = 0 };
    const n = try utf8.decode(null, &got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 4);
}

test "ntz.encoding.unicode.utf8.decode: empty" {
    const in = "";
    const want = try unicode.Codepoint.init(0);

    var got = unicode.Codepoint{ .value = 0 };
    const n = try utf8.decode(null, &got, in);

    try testing.expectEql(got, want);
    try testing.expectEql(n, 0);
}

test "ntz.encoding.unicode.utf8.decode: incomplete" {
    const in = "\xF0";
    const want = try unicode.Codepoint.init(0);

    var got = unicode.Codepoint{ .value = 0 };

    try testing.expectErr(
        utf8.decode(null, &got, in),
        utf8.DecodeError.IncompleteInput,
    );

    try testing.expectEql(got, want);
}

test "ntz.encoding.unicode.utf8.decode: invalid first byte" {
    const in = "\xFF";
    const want = try unicode.Codepoint.init(0);

    var got = unicode.Codepoint{ .value = 0 };

    try testing.expectErr(
        utf8.decode(null, &got, in),
        utf8.DecodeError.InvalidFirstByte,
    );

    try testing.expectEql(got, want);
}

test "ntz.encoding.unicode.utf8.decode: invalid intermediate byte" {
    const in = "\xF0\x0F\x0F\x0F";
    const want = try unicode.Codepoint.init(0);

    var got = unicode.Codepoint{ .value = 0 };

    var diag = utf8.DecodeDiagnostic{};

    try testing.expectErr(
        utf8.decode(&diag, &got, in),
        utf8.DecodeError.InvalidIntermediateByte,
    );

    try testing.expectEql(got, want);
    try testing.expectEql(diag.index, 1);
}

// ////////////
// decodeLen //
// ////////////

test "ntz.encoding.unicode.utf8.decodeLen" {
    try testing.expectEql(try utf8.decodeLen(""), 0);
    try testing.expectEql(try utf8.decodeLen("$"), 1);
    try testing.expectEql(try utf8.decodeLen("¢"), 2);
    try testing.expectEql(try utf8.decodeLen("€"), 3);
    try testing.expectEql(try utf8.decodeLen("\u{1F4B0}"), 4);

    try testing.expectEql(try utf8.decodeLen("$¢€\u{1F4B0}"), 1);
    try testing.expectEql(try utf8.decodeLen("¢€\u{1F4B0}$"), 2);
    try testing.expectEql(try utf8.decodeLen("€\u{1F4B0}$¢"), 3);
    try testing.expectEql(try utf8.decodeLen("\u{1F4B0}$¢€"), 4);

    try testing.expectErr(
        utf8.decodeLen("\xFF"),
        utf8.DecodeLenError.InvalidFirstByte,
    );

    try testing.expectErr(
        utf8.decodeLen("\xF0"),
        utf8.DecodeLenError.IncompleteInput,
    );
}

// //////////////
// decodeLenFB //
// //////////////

test "ntz.encoding.unicode.utf8.decodeLenFB" {
    try testing.expectEql(try utf8.decodeLenFB(0), 1);
    try testing.expectEql(try utf8.decodeLenFB(0x24), 1);
    try testing.expectEql(try utf8.decodeLenFB(0b0111_1111), 1);

    try testing.expectEql(try utf8.decodeLenFB(0b110_00000), 2);
    try testing.expectEql(try utf8.decodeLenFB(0xC2), 2);
    try testing.expectEql(try utf8.decodeLenFB(0b110_11111), 2);

    try testing.expectEql(try utf8.decodeLenFB(0b1110_0000), 3);
    try testing.expectEql(try utf8.decodeLenFB(0xE2), 3);
    try testing.expectEql(try utf8.decodeLenFB(0b1110_1111), 3);

    try testing.expectEql(try utf8.decodeLenFB(0b11110_000), 4);
    try testing.expectEql(try utf8.decodeLenFB(0xF0), 4);
    try testing.expectEql(try utf8.decodeLenFB(0b11110_111), 4);

    try testing.expectErr(
        utf8.decodeLenFB(0b111110_11),
        utf8.DecodeLenFBError.InvalidFirstByte,
    );

    try testing.expectErr(
        utf8.decodeLenFB(0b1111110_1),
        utf8.DecodeLenFBError.InvalidFirstByte,
    );

    try testing.expectErr(
        utf8.decodeLenFB(0b1111_1110),
        utf8.DecodeLenFBError.InvalidFirstByte,
    );

    try testing.expectErr(
        utf8.decodeLenFB(0b1111_1111),
        utf8.DecodeLenFBError.InvalidFirstByte,
    );
}

// ///////////////
// decodeReader //
// ///////////////

//test "ntz.encoding.unicode.utf8.decodeReader: one byte" {
//    const in = "$";
//    const want = try unicode.Codepoint.init('$');
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//    const n = try utf8.decodeReader(&got, buf.reader());
//
//    try testing.expectEql(got, want);
//    try testing.expectEql(n, 1);
//}
//
//test "ntz.encoding.unicode.utf8.decodeReader: two bytes" {
//    const in = "¢";
//    const want = try unicode.Codepoint.init('¢');
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//    const n = try utf8.decodeReader(&got, buf.reader());
//
//    try testing.expectEql(got, want);
//    try testing.expectEql(n, 2);
//}
//
//test "ntz.encoding.unicode.utf8.decodeReader: three bytes" {
//    const in = "€";
//    const want = try unicode.Codepoint.init('€');
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//    const n = try utf8.decodeReader(&got, buf.reader());
//
//    try testing.expectEql(got, want);
//    try testing.expectEql(n, 3);
//}
//
//test "ntz.encoding.unicode.utf8.decodeReader: four bytes" {
//    const in = "💰";
//    const want = try unicode.Codepoint.init('💰');
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//    const n = try utf8.decodeReader(&got, buf.reader());
//
//    try testing.expectEql(got, want);
//    try testing.expectEql(n, 4);
//}
//
//test "ntz.encoding.unicode.utf8.decodeReader: empty" {
//    const in = "";
//    const want = try unicode.Codepoint.init(0);
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//    const n = try utf8.decodeReader(&got, buf.reader());
//
//    try testing.expectEql(got, want);
//    try testing.expectEql(n, 0);
//}
//
//test "ntz.encoding.unicode.utf8.decodeReader: invalid first byte" {
//    const in = "\xFF";
//    const want = try unicode.Codepoint.init(0);
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//
//    try testing.expectErr(
//        utf8.decodeReader(&got, buf.reader()),
//        utf8.Error.InvalidFirstByte,
//    );
//
//    try testing.expectEql(got, want);
//}
//
//test "ntz.encoding.unicode.utf8.decodeReader: incomplete" {
//    const in = "\xF0";
//    const want = try unicode.Codepoint.init(0);
//
//    var buf = std.io.fixedBufferStream(in);
//    var got = unicode.Codepoint{ .value = 0 };
//
//    try testing.expectErr(
//        utf8.decodeReader(&got, buf.reader()),
//        encoding.Error.IncompleteInput,
//    );
//
//    try testing.expectEql(got, want);
//}

// /////////
// encode //
// /////////

test "ntz.encoding.unicode.utf8.encode: one byte" {
    const in = try unicode.Codepoint.init('$');
    const want = "$";

    var got: [1]u8 = undefined;
    const n = try utf8.encode(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 1);
}

test "ntz.encoding.unicode.utf8.encode: two bytes" {
    const in = try unicode.Codepoint.init('¢');
    const want = "¢";

    var got: [2]u8 = undefined;
    const n = try utf8.encode(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 2);
}

test "ntz.encoding.unicode.utf8.encode: three bytes" {
    const in = try unicode.Codepoint.init('€');
    const want = "€";

    var got: [3]u8 = undefined;
    const n = try utf8.encode(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 3);
}

test "ntz.encoding.unicode.utf8.encode: four bytes" {
    const in = try unicode.Codepoint.init('💰');
    const want = "💰";

    var got: [4]u8 = undefined;
    const n = try utf8.encode(&got, in);

    try testing.expectEqlStrs(&got, want);
    try testing.expectEql(n, 4);
}

test "ntz.encoding.unicode.utf8.encode: small buffer" {
    const in = try unicode.Codepoint.init('$');
    var got: [0]u8 = undefined;

    try testing.expectErr(
        utf8.encode(&got, in),
        utf8.EncodeError.OutputTooSmall,
    );
}

// ////////////
// encodeLen //
// ////////////

test "ntz.encoding.unicode.utf8.encodeLen" {
    // One byte.

    var in = try unicode.Codepoint.init(0);
    try testing.expectEql(utf8.encodeLen(in), 1);

    in = try unicode.Codepoint.init('$');
    try testing.expectEql(utf8.encodeLen(in), 1);

    in = try unicode.Codepoint.init(0b0111_1111);
    try testing.expectEql(utf8.encodeLen(in), 1);

    // Two bytes.

    in = try unicode.Codepoint.init(0b1000_0000);
    try testing.expectEql(utf8.encodeLen(in), 2);

    in = try unicode.Codepoint.init('¢');
    try testing.expectEql(utf8.encodeLen(in), 2);

    in = try unicode.Codepoint.init(0b0111_1111_1111);
    try testing.expectEql(utf8.encodeLen(in), 2);

    // Three bytes.

    in = try unicode.Codepoint.init(0b1000_0000_0000);
    try testing.expectEql(utf8.encodeLen(in), 3);

    in = try unicode.Codepoint.init('€');
    try testing.expectEql(utf8.encodeLen(in), 3);

    in = try unicode.Codepoint.init(0b1111_1111_1111_1111);
    try testing.expectEql(utf8.encodeLen(in), 3);

    // Four bytes.

    in = try unicode.Codepoint.init(0b0001_0000_0000_0000_0000);
    try testing.expectEql(utf8.encodeLen(in), 4);

    in = try unicode.Codepoint.init('💰');
    try testing.expectEql(utf8.encodeLen(in), 4);

    in = try unicode.Codepoint.init(0x10FFFF);
    try testing.expectEql(utf8.encodeLen(in), 4);
}

// ///////////////
// encodeWriter //
// ///////////////

//test "ntz.encoding.unicode.utf8.encodeWriter: one byte" {
//    const ally = testing.allocator;
//
//    var buf = std.ArrayList(u8).init(ally);
//    defer buf.deinit();
//    var cw = io.countingWriter(buf.writer());
//
//    const in = try unicode.Codepoint.init('$');
//    const want = "$";
//
//    const n = try utf8.encodeWriter(&cw, in);
//
//    try testing.expectEqlStrs(buf.items, want);
//    try testing.expectEql(n, 1);
//    try testing.expectEql(cw.write_count, 1);
//    try testing.expectEql(cw.byte_count, n);
//}
//
//test "ntz.encoding.unicode.utf8.encodeWriter: two bytes" {
//    const ally = testing.allocator;
//
//    var buf = std.ArrayList(u8).init(ally);
//    defer buf.deinit();
//    var cw = io.countingWriter(buf.writer());
//
//    const in = try unicode.Codepoint.init('¢');
//    const want = "¢";
//
//    const n = try utf8.encodeWriter(&cw, in);
//
//    try testing.expectEqlStrs(buf.items, want);
//    try testing.expectEql(n, 2);
//    try testing.expectEql(cw.write_count, 1);
//    try testing.expectEql(cw.byte_count, n);
//}
//
//test "ntz.encoding.unicode.utf8.encodeWriter: three bytes" {
//    const ally = testing.allocator;
//
//    var buf = std.ArrayList(u8).init(ally);
//    defer buf.deinit();
//    var cw = io.countingWriter(buf.writer());
//
//    const in = try unicode.Codepoint.init('€');
//    const want = "€";
//
//    const n = try utf8.encodeWriter(&cw, in);
//
//    try testing.expectEqlStrs(buf.items, want);
//    try testing.expectEql(n, 3);
//    try testing.expectEql(cw.write_count, 1);
//    try testing.expectEql(cw.byte_count, n);
//}
//
//test "ntz.encoding.unicode.utf8.encodeWriter: four bytes" {
//    const ally = testing.allocator;
//
//    var buf = std.ArrayList(u8).init(ally);
//    defer buf.deinit();
//    var cw = io.countingWriter(buf.writer());
//
//    const in = try unicode.Codepoint.init('💰');
//    const want = "💰";
//
//    const n = try utf8.encodeWriter(&cw, in);
//
//    try testing.expectEqlStrs(buf.items, want);
//    try testing.expectEql(n, 4);
//    try testing.expectEql(cw.write_count, 1);
//    try testing.expectEql(cw.byte_count, n);
//}

// //////////////
// isFirstByte //
// //////////////

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
// /////////////////////
// isIntermediateByte //
// /////////////////////

test "ntz.encoding.unicode.utf8.isIntermediateByte" {
    try testing.expect(!utf8.isIntermediateByte(0b0111_1111));
    try testing.expect(utf8.isIntermediateByte(0b10_000000));
    try testing.expect(utf8.isIntermediateByte(0b10_111111));
    try testing.expect(!utf8.isIntermediateByte(0b11_000000));
}

//////////////
// validate //
//////////////

test "ntz.encoding.unicode.utf8.validate" {
    try utf8.validate(null, "\x24");
    try utf8.validate(null, "\xC2\xA2");
    try utf8.validate(null, "\xE2\x82\xAC");
    try utf8.validate(null, "\xF0\x9F\x92\xB0");
    //try utf8.validate(null, "\x24 \xC2\xA2 \xE2\x82\xAC \xF0\x9F\x92\xB0");
}

test "ntz.encoding.unicode.utf8.validate: incomplete" {
    var diag = utf8.DecodeDiagnostic{};

    try testing.expectErr(
        utf8.validate(&diag, ""),
        utf8.ValidateError.IncompleteInput,
    );

    try testing.expectEql(diag.index, 0);
    try testing.expectEql(diag.len_expected, 0);

    try testing.expectErr(
        utf8.validate(&diag, "\xC2"),
        utf8.ValidateError.IncompleteInput,
    );

    try testing.expectEql(diag.index, 0);
    try testing.expectEql(diag.len_expected, 2);

    try testing.expectErr(
        utf8.validate(&diag, "\xE2\x82"),
        utf8.ValidateError.IncompleteInput,
    );

    try testing.expectEql(diag.index, 0);
    try testing.expectEql(diag.len_expected, 3);

    try testing.expectErr(
        utf8.validate(&diag, "\xF0\x9F\x92"),
        utf8.ValidateError.IncompleteInput,
    );

    try testing.expectEql(diag.index, 0);
    try testing.expectEql(diag.len_expected, 4);
}

test "ntz.encoding.unicode.utf8.validate: invalid bytes" {
    var diag = utf8.DecodeDiagnostic{};

    try testing.expectErr(
        utf8.validate(&diag, "\xFF\x0F\x0F\x0F"),
        utf8.ValidateError.InvalidFirstByte,
    );

    try testing.expectEql(diag.index, 0);
    try testing.expectEql(diag.len_expected, 0);

    try testing.expectErr(
        utf8.validate(&diag, "\xF0\x0F\x0F\x0F"),
        utf8.ValidateError.InvalidIntermediateByte,
    );

    try testing.expectEql(diag.index, 1);
    try testing.expectEql(diag.len_expected, 4);

    try testing.expectErr(
        utf8.validate(&diag, "\xF0\x9F\x0F\x0F"),
        utf8.ValidateError.InvalidIntermediateByte,
    );

    try testing.expectEql(diag.index, 2);
    try testing.expectEql(diag.len_expected, 4);

    try testing.expectErr(
        utf8.validate(&diag, "\xF0\x9F\x92\x0F"),
        utf8.ValidateError.InvalidIntermediateByte,
    );

    try testing.expectEql(diag.index, 3);
    try testing.expectEql(diag.len_expected, 4);
}

test "ntz.encoding.unicode.utf8.validate: too many bytes" {
    var diag = utf8.DecodeDiagnostic{};

    try testing.expectErr(
        utf8.validate(&diag, "12"),
        utf8.ValidateError.TooManyBytes,
    );

    try testing.expectEql(diag.index, 0);
    try testing.expectEql(diag.len_expected, 1);
}
