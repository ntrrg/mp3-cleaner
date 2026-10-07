// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const strings = ntz.types.strings;

test "ntz.types.strings" {}

// concat //

test "ntz.types.strings.concat" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "hello, ", "world!");
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "hello, world!");
}

test "ntz.types.strings.concat: null items" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "hello, \x00", "\x00world!");
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "hello, \x00\x00world!");
}

test "ntz.types.strings.concat: empty" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "", "");
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "");
}

test "ntz.types.strings.concat: empty these" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "", "world");
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "world");
}

test "ntz.types.strings.concat: empty those" {
    const ally = testing.allocator;

    const got = try strings.concat(ally, "hello", "");
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "hello");
}

// concatMany //

test "ntz.types.strings.concatMany" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &[_][]const u8{ "hello", ", ", "world", "!" });
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "hello, world!");
}

test "ntz.types.strings.concatMany: null items" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &[_][]const u8{ "hello, ", "\x00", "world!" });
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "hello, \x00world!");
}

test "ntz.types.strings.concatMany: empty" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &[_]strings.String{});
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "");
}

test "ntz.types.strings.concatMany: empty strings" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &[_][]const u8{ "", "" });
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "");
}

test "ntz.types.strings.concatMany: some empty strings" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &[_][]const u8{ "", "world" });
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "world");
}

test "ntz.types.strings.concatMany: empty edges" {
    const ally = testing.allocator;

    const got = try strings.concatMany(ally, &[_][]const u8{ "", "hello", "" });
    defer ally.free(got.data);
    try testing.expectEqlStrs(got, "hello");
}

// endsWith //

test "ntz.types.strings.endsWith" {
    try testing.expect(strings.endsWith("asd", "d"));
    try testing.expect(strings.endsWith("asd", "sd"));
    try testing.expect(strings.endsWith("asd", "asd"));
    try testing.expect(!strings.endsWith("asd", ""));
    try testing.expect(!strings.endsWith("asd", "q"));
    try testing.expect(!strings.endsWith("asd", "qwer"));
}

// equal //

test "ntz.types.strings.equal" {
    try testing.expect(strings.equal("asd", "asd"));
    try testing.expect(!strings.equal("qwe", "asd"));
    try testing.expect(!strings.equal("qwe", "asdf"));
}

test "ntz.types.strings.equal: same pointer" {
    const data: []const u8 = "hello, world!";
    try testing.expect(strings.equal(data, data[0..]));
}

test "ntz.types.strings.equal: different pointer" {
    var a: [4]u8 = undefined;
    var b: [4]u8 = undefined;

    @memcpy(&a, "abcd");
    @memcpy(&b, "abcd");

    try testing.expect(strings.equal(&a, &b));
}

// equalAll //

test "ntz.types.strings.equalAll" {
    try testing.expect(strings.equalAll("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!strings.equalAll("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!strings.equalAll("asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!strings.equalAll("asd", &.{ "asd", "asd", "qwe" }));
}

test "ntz.types.strings.equalAll: empty strings" {
    try testing.expect(!strings.equalAll("asd", &.{ "", "", "" }));
}

test "ntz.types.strings.equalAll: no strings" {
    try testing.expect(!strings.equalAll("asd", &.{}));
}

// equalAny //

test "ntz.types.strings.equalAny" {
    try testing.expect(strings.equalAny("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(strings.equalAny("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(strings.equalAny("asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!strings.equalAny("asd", &.{ "qwe", "qwe", "qwe" }));
}

test "ntz.types.strings.equalAny: empty strings" {
    try testing.expect(!strings.equalAny("asd", &.{ "", "", "" }));
}

test "ntz.types.strings.equalAny: no strings" {
    try testing.expect(!strings.equalAny("asd", &.{}));
}

// find //

test "ntz.types.bytes.find" {
    try testing.expectEql(strings.find("asd", "a"), 0);
    try testing.expectEql(strings.find("asd", "as"), 0);
    try testing.expectEql(strings.find("asd", "asd"), 0);
    try testing.expectEql(strings.find("asd", "s"), 1);
    try testing.expectEql(strings.find("asd", "sd"), 1);
    try testing.expectEql(strings.find("asd", "d"), 2);
    try testing.expectEql(strings.find("asd", "f"), null);
}

// findAt //

test "ntz.types.strings.findAt" {
    try testing.expectEql(strings.findAt(0, "asd", "a"), 0);
    try testing.expectEql(strings.findAt(1, "asd", "a"), null);
    try testing.expectEql(strings.findAt(0, "asd", "as"), 0);
    try testing.expectEql(strings.findAt(1, "asd", "as"), null);
    try testing.expectEql(strings.findAt(0, "asd", "asd"), 0);
    try testing.expectEql(strings.findAt(1, "asd", "asd"), null);
    try testing.expectEql(strings.findAt(0, "asd", "s"), 1);
    try testing.expectEql(strings.findAt(1, "asd", "s"), 1);
    try testing.expectEql(strings.findAt(2, "asd", "s"), null);
    try testing.expectEql(strings.findAt(0, "asd", "sd"), 1);
    try testing.expectEql(strings.findAt(1, "asd", "sd"), 1);
    try testing.expectEql(strings.findAt(2, "asd", "sd"), null);
    try testing.expectEql(strings.findAt(0, "asd", "d"), 2);
    try testing.expectEql(strings.findAt(1, "asd", "d"), 2);
    try testing.expectEql(strings.findAt(2, "asd", "d"), 2);
    try testing.expectEql(strings.findAt(3, "asd", "d"), null);
    try testing.expectEql(strings.findAt(0, "asd", "f"), null);
    try testing.expectEql(strings.findAt(3, "asd", "f"), null);
}

// findByte //

test "ntz.types.strings.findByte" {
    try testing.expectEql(strings.findByte("asd", 'a'), 0);
    try testing.expectEql(strings.findByte("asd", 's'), 1);
    try testing.expectEql(strings.findByte("asd", 'd'), 2);
    try testing.expectEql(strings.findByte("asd", 'f'), null);
}

// findByteAt //

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

// is //

test "ntz.types.strings.is" {
    const want = "hello, world!";
    var s = strings.init(want);
    const cs = s;

    try testing.expect(strings.is(s));
    try testing.expect(strings.is(&s));
    try testing.expect(strings.is(cs));
    try testing.expect(strings.is(&cs));
    try testing.expect(!strings.is(""));
    try testing.expect(!strings.is("hello"));
    try testing.expect(!strings.is(want));
    try testing.expectEqlStrs(strings.init(""), strings.init(""));
}

// isStrings //

test "ntz.types.strings.isStrings" {
    const group = [_]strings.String{
        strings.init("hello"),
        strings.init("world"),
    };

    try testing.expect(strings.isStrings([0]strings.String{}));
    try testing.expect(strings.isStrings(group[0..0]));
    try testing.expect(strings.isStrings(group));
    try testing.expect(strings.isStrings(&group));
    try testing.expect(strings.isStrings(group[0..]));
    try testing.expect(strings.isStrings(.{ group[0], group[1] }));
}

// startsWith //

test "ntz.types.strings.startsWith" {
    try testing.expect(strings.startsWith("asd", "a"));
    try testing.expect(strings.startsWith("asd", "as"));
    try testing.expect(strings.startsWith("asd", "asd"));
    try testing.expect(!strings.startsWith("asd", ""));
    try testing.expect(!strings.startsWith("asd", "q"));
    try testing.expect(!strings.startsWith("asd", "qwer"));
}
