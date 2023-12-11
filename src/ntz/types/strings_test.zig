// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const strings = ntz.types.strings;

test "ntz.types.strings" {
    testing.refAllDecls(strings);
}

// /////////
// concat //
// /////////

test "ntz.types.strings.concat" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "hello, ", "world!");
    defer ally.free(got);
    try testing.expectEqlStrs(got, "hello, world!");
}

test "ntz.types.strings.concat: null items" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "hello, \x00", "\x00world!");
    defer ally.free(got);
    try testing.expectEqlStrs(got, "hello, \x00\x00world!");
}

test "ntz.types.strings.concat: empty" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "", "");
    defer ally.free(got);
    try testing.expectEqlStrs(got, "");
}

test "ntz.types.strings.concat: empty slice" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "", "world");
    defer ally.free(got);
    try testing.expectEqlStrs(got, "world");
}

test "ntz.types.strings.concat: empty items" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "hello", "");
    defer ally.free(got);
    try testing.expectEqlStrs(got, "hello");
}

// /////////////
// concatMany //
// /////////////

test "ntz.types.strings.concatMany" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &.{ "hello", ", ", "world", "!" });
    defer ally.free(got);
    try testing.expectEqlStrs(got, "hello, world!");
}

test "ntz.types.strings.concatMany: null items" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &.{ "hello, ", "\x00", "world!" });
    defer ally.free(got);
    try testing.expectEqlStrs(got, "hello, \x00world!");
}

test "ntz.types.strings.concatMany: empty" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &.{});
    defer ally.free(got);
    try testing.expectEqlStrs(got, "");
}

test "ntz.types.strings.concatMany: empty strings" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &.{ "", "" });
    defer ally.free(got);
    try testing.expectEqlStrs(got, "");
}

test "ntz.types.strings.concatMany: some empty strings" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &.{ "", "world" });
    defer ally.free(got);
    try testing.expectEqlStrs(got, "world");
}

test "ntz.types.strings.concatMany: empty edges" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &.{ "", "hello", "" });
    defer ally.free(got);
    try testing.expectEqlStrs(got, "hello");
}

// ///////////
// endsWith //
// ///////////

test "ntz.types.strings.endsWith" {
    try testing.expect(strings.endsWith("asd", "d"));
    try testing.expect(strings.endsWith("asd", "sd"));
    try testing.expect(strings.endsWith("asd", "asd"));
    try testing.expect(!strings.endsWith("asd", ""));
    try testing.expect(!strings.endsWith("asd", "q"));
    try testing.expect(!strings.endsWith("asd", "qwer"));
}

// //////
// eql //
// //////

test "ntz.types.strings.eql" {
    try testing.expect(strings.eql("asd", "asd"));
    try testing.expect(!strings.eql("qwe", "asd"));
    try testing.expect(!strings.eql("qwe", "asdf"));
}

test "ntz.types.strings.eql: same pointer" {
    const data: []const u8 = "hello, world!";
    try testing.expect(strings.eql(data, data[0..]));
}

test "ntz.types.strings.eql: different pointer" {
    var a: [4]u8 = undefined;
    var b: [4]u8 = undefined;

    @memcpy(&a, "abcd");
    @memcpy(&b, "abcd");

    try testing.expect(strings.eql(&a, &b));
}

// /////////
// eqlAll //
// /////////

test "ntz.types.strings.eqlAll" {
    try testing.expect(strings.eqlAll("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!strings.eqlAll("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!strings.eqlAll("asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!strings.eqlAll("asd", &.{ "asd", "asd", "qwe" }));
}

test "ntz.types.strings.eqlAll: empty strings" {
    try testing.expect(!strings.eqlAll("asd", &.{ "", "", "" }));
}

test "ntz.types.strings.eqlAll: no strings" {
    try testing.expect(!strings.eqlAll("asd", &.{}));
}

// /////////
// eqlAny //
// /////////

test "ntz.types.strings.eqlAny" {
    try testing.expect(strings.eqlAny("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(strings.eqlAny("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(strings.eqlAny("asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!strings.eqlAny("asd", &.{ "qwe", "qwe", "qwe" }));
}

test "ntz.types.strings.eqlAny: empty strings" {
    try testing.expect(!strings.eqlAny("asd", &.{ "", "", "" }));
}

test "ntz.types.strings.eqlAny: no strings" {
    try testing.expect(!strings.eqlAny("asd", &.{}));
}

// ///////////
// findByte //
// ///////////

test "ntz.types.strings.findByte" {
    try testing.expectEql(strings.findByte("asd", 'a'), 0);
    try testing.expectEql(strings.findByte("asd", 's'), 1);
    try testing.expectEql(strings.findByte("asd", 'd'), 2);
    try testing.expectEql(strings.findByte("asd", 'f'), null);
}

// /////////////
// findByteAt //
// /////////////

test "ntz.types.strings.findByteAt" {
    try testing.expectEql(strings.findByteAt(0, "asd", 'a'), 0);
    try testing.expectEql(strings.findByteAt(1, "asd", 'a'), null);
    try testing.expectEql(strings.findByteAt(1, "asd", 's'), 1);
    try testing.expectEql(strings.findByteAt(2, "asd", 's'), null);
    try testing.expectEql(strings.findByteAt(2, "asd", 'd'), 2);
    try testing.expectEql(strings.findByteAt(3, "asd", 'd'), null);
    try testing.expectEql(strings.findByteAt(0, "asd", 'f'), null);
    try testing.expectEql(strings.findByteAt(3, "asd", 'f'), null);
}

// /////////////
// startsWith //
// /////////////

test "ntz.types.strings.startsWith" {
    try testing.expect(strings.startsWith("asd", "a"));
    try testing.expect(strings.startsWith("asd", "as"));
    try testing.expect(strings.startsWith("asd", "asd"));
    try testing.expect(!strings.startsWith("asd", ""));
    try testing.expect(!strings.startsWith("asd", "q"));
    try testing.expect(!strings.startsWith("asd", "qwer"));
}
