// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const bytes = ntz.types.bytes;

test "ntz.types.bytes" {
    testing.refAllDecls(bytes);
}

// /////////
// append //
// /////////

test "ntz.types.bytes.append" {
    const ally = testing.allocator;

    const got = try bytes.append(ally, "hello, world", '!');
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello, world!");
}

test "ntz.types.bytes.append: null item" {
    const ally = testing.allocator;

    const got = try bytes.append(ally, "hello, world", 0);
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello, world\x00");
}

test "ntz.types.bytes.append: empty slice" {
    const ally = testing.allocator;

    const got = try bytes.append(ally, "", 'M');
    defer ally.free(got);
    try testing.expectEqlBytes(got, "M");
}

// /////////
// concat //
// /////////

test "ntz.types.bytes.concat" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "hello, ", "world!");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello, world!");
}

test "ntz.types.bytes.concat: null items" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "hello, \x00", "\x00world!");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello, \x00\x00world!");
}

test "ntz.types.bytes.concat: empty" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "", "");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "");
}

test "ntz.types.bytes.concat: empty slice" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "", "world");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "world");
}

test "ntz.types.bytes.concat: empty items" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "hello", "");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello");
}

// /////////////
// concatMany //
// /////////////

test "ntz.types.bytes.concatMany" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{ "hello", ", ", "world", "!" });
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello, world!");
}

test "ntz.types.bytes.concatMany: null items" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{ "hello, ", "\x00", "world!" });
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello, \x00world!");
}

test "ntz.types.bytes.concatMany: empty" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{});
    defer ally.free(got);
    try testing.expectEqlBytes(got, "");
}

test "ntz.types.bytes.concatMany: empty slices" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{ "", "" });
    defer ally.free(got);
    try testing.expectEqlBytes(got, "");
}

test "ntz.types.bytes.concatMany: some empty slices" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{ "", "world" });
    defer ally.free(got);
    try testing.expectEqlBytes(got, "world");
}

test "ntz.types.bytes.concatMany: empty edges" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{ "", "hello", "" });
    defer ally.free(got);
    try testing.expectEqlBytes(got, "hello");
}

// ///////////
// endsWith //
// ///////////

test "ntz.types.bytes.endsWith" {
    try testing.expect(bytes.endsWith("asd", "d"));
    try testing.expect(bytes.endsWith("asd", "sd"));
    try testing.expect(bytes.endsWith("asd", "asd"));
    try testing.expect(!bytes.endsWith("asd", ""));
    try testing.expect(!bytes.endsWith("asd", "q"));
    try testing.expect(!bytes.endsWith("asd", "qwer"));
}

// //////
// eql //
// //////

test "ntz.types.bytes.eql" {
    try testing.expect(bytes.eql("asd", "asd"));
    try testing.expect(!bytes.eql("qwe", "asd"));
    try testing.expect(!bytes.eql("qwe", "asdf"));
}

test "ntz.types.bytes.eql: same pointer" {
    const data: []const u8 = "hello, world!";
    try testing.expect(bytes.eql(data, data[0..]));
}

test "ntz.types.bytes.eql: different pointer" {
    var a: [4]u8 = undefined;
    var b: [4]u8 = undefined;

    @memcpy(&a, "abcd");
    @memcpy(&b, "abcd");

    try testing.expect(bytes.eql(&a, &b));
}

// /////////
// eqlAll //
// /////////

test "ntz.types.bytes.eqlAll" {
    try testing.expect(bytes.eqlAll("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!bytes.eqlAll("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!bytes.eqlAll("asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!bytes.eqlAll("asd", &.{ "asd", "asd", "qwe" }));
}

test "ntz.types.bytes.eqlAll: empty slices" {
    try testing.expect(!bytes.eqlAll("asd", &.{ "", "", "" }));
}

test "ntz.types.bytes.eqlAll: no slices" {
    try testing.expect(!bytes.eqlAll("asd", &.{}));
}

// /////////
// eqlAny //
// /////////

test "ntz.types.bytes.eqlAny" {
    try testing.expect(bytes.eqlAny("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(bytes.eqlAny("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(bytes.eqlAny("asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!bytes.eqlAny("asd", &.{ "qwe", "qwe", "qwe" }));
}

test "ntz.types.bytes.eqlAny: empty slices" {
    try testing.expect(!bytes.eqlAny("asd", &.{ "", "", "" }));
}

test "ntz.types.bytes.eqlAny: no slices" {
    try testing.expect(!bytes.eqlAny("asd", &.{}));
}

// ///////
// find //
// ///////

test "ntz.types.bytes.find" {
    try testing.expectEql(bytes.find("asd", 'a'), 0);
    try testing.expectEql(bytes.find("asd", 's'), 1);
    try testing.expectEql(bytes.find("asd", 'd'), 2);
    try testing.expectEql(bytes.find("asd", 'f'), null);
}

// /////////
// findAt //
// /////////

test "ntz.types.bytes.findAt" {
    try testing.expectEql(bytes.findAt(0, "asd", 'a'), 0);
    try testing.expectEql(bytes.findAt(1, "asd", 'a'), null);
    try testing.expectEql(bytes.findAt(1, "asd", 's'), 1);
    try testing.expectEql(bytes.findAt(2, "asd", 's'), null);
    try testing.expectEql(bytes.findAt(2, "asd", 'd'), 2);
    try testing.expectEql(bytes.findAt(3, "asd", 'd'), null);
    try testing.expectEql(bytes.findAt(0, "asd", 'f'), null);
    try testing.expectEql(bytes.findAt(3, "asd", 'f'), null);
}

// /////////////
// startsWith //
// /////////////

test "ntz.types.bytes.startsWith" {
    try testing.expect(bytes.startsWith("asd", "a"));
    try testing.expect(bytes.startsWith("asd", "as"));
    try testing.expect(bytes.startsWith("asd", "asd"));
    try testing.expect(!bytes.startsWith("asd", ""));
    try testing.expect(!bytes.startsWith("asd", "q"));
    try testing.expect(!bytes.startsWith("asd", "qwer"));
}
