// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const slices = ntz.types.slices;

test "ntz.types.slices" {
    testing.refAllDecls(slices);
}

// /////////
// append //
// /////////

test "ntz.types.slices.append" {
    const ally = testing.allocator;

    const got = try slices.append(u8, "hello, world", '!', ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world!");
}

test "ntz.types.slices.append: null item" {
    const ally = testing.allocator;

    const got = try slices.append(u8, "hello, world", 0, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world\x00");
}

test "ntz.types.slices.append: empty slice" {
    const ally = testing.allocator;

    const got = try slices.append(u8, "", 'M', ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "M");
}

// /////////
// concat //
// /////////

test "ntz.types.slices.concat" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, "hello, ", "world!", ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world!");
}

test "ntz.types.slices.concat: null items" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, "hello, \x00", "\x00world!", ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, \x00\x00world!");
}

test "ntz.types.slices.concat: empty" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, "", "", ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "");
}

test "ntz.types.slices.concat: empty slice" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, "", "world", ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "world");
}

test "ntz.types.slices.concat: empty items" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, "hello", "", ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello");
}

// /////////////
// concatMany //
// /////////////

test "ntz.types.slices.concatMany" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, &.{ "hello", ", ", "world", "!" }, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world!");
}

test "ntz.types.slices.concatMany: null items" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, &.{ "hello, ", "\x00", "world!" }, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, \x00world!");
}

test "ntz.types.slices.concatMany: empty" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, &.{}, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "");
}

test "ntz.types.slices.concatMany: empty slices" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, &.{ "", "" }, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "");
}

test "ntz.types.slices.concatMany: some empty slices" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, &.{ "", "world" }, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "world");
}

test "ntz.types.slices.concatMany: empty edges" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, &.{ "", "hello", "" }, ally);
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello");
}

// ///////////
// endsWith //
// ///////////

test "ntz.types.slices.endsWith" {
    try testing.expect(slices.endsWith(u8, "asd", "d"));
    try testing.expect(slices.endsWith(u8, "asd", "sd"));
    try testing.expect(slices.endsWith(u8, "asd", "asd"));
    try testing.expect(!slices.endsWith(u8, "asd", ""));
    try testing.expect(!slices.endsWith(u8, "asd", "q"));
    try testing.expect(!slices.endsWith(u8, "asd", "qwer"));
}

// //////
// eql //
// //////

test "ntz.types.slices.eql" {
    try testing.expect(slices.eql(u8, "asd", "asd"));
    try testing.expect(!slices.eql(u8, "qwe", "asd"));
    try testing.expect(!slices.eql(u8, "qwe", "asdf"));
}

test "ntz.types.slices.eql: same pointer" {
    const data: []const u8 = "hello, world!";
    try testing.expect(slices.eql(u8, data, data[0..]));
}

test "ntz.types.slices.eql: different pointer" {
    var a: [4]u8 = undefined;
    var b: [4]u8 = undefined;

    @memcpy(&a, "abcd");
    @memcpy(&b, "abcd");

    try testing.expect(slices.eql(u8, &a, &b));
}

// /////////
// eqlAll //
// /////////

test "ntz.types.slices.eqlAll" {
    try testing.expect(slices.eqlAll(u8, "asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!slices.eqlAll(u8, "asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!slices.eqlAll(u8, "asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!slices.eqlAll(u8, "asd", &.{ "asd", "asd", "qwe" }));
}

test "ntz.types.slices.eqlAll: empty slices" {
    try testing.expect(!slices.eqlAll(u8, "asd", &.{ "", "", "" }));
}

test "ntz.types.slices.eqlAll: no slices" {
    try testing.expect(!slices.eqlAll(u8, "asd", &.{}));
}

// /////////
// eqlAny //
// /////////

test "ntz.types.slices.eqlAny" {
    try testing.expect(slices.eqlAny(u8, "asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(slices.eqlAny(u8, "asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(slices.eqlAny(u8, "asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!slices.eqlAny(u8, "asd", &.{ "qwe", "qwe", "qwe" }));
}

test "ntz.types.slices.eqlAny: empty slices" {
    try testing.expect(!slices.eqlAny(u8, "asd", &.{ "", "", "" }));
}

test "ntz.types.slices.eqlAny: no slices" {
    try testing.expect(!slices.eqlAny(u8, "asd", &.{}));
}

// ///////
// find //
// ///////

test "ntz.types.slices.find" {
    try testing.expectEql(slices.find(u8, "asd", 'a'), 0);
    try testing.expectEql(slices.find(u8, "asd", 's'), 1);
    try testing.expectEql(slices.find(u8, "asd", 'd'), 2);
    try testing.expectEql(slices.find(u8, "asd", 'f'), null);
}

// /////////
// findAt //
// /////////

test "ntz.types.slices.findAt" {
    try testing.expectEql(slices.findAt(u8, 0, "asd", 'a'), 0);
    try testing.expectEql(slices.findAt(u8, 1, "asd", 'a'), null);
    try testing.expectEql(slices.findAt(u8, 1, "asd", 's'), 1);
    try testing.expectEql(slices.findAt(u8, 2, "asd", 's'), null);
    try testing.expectEql(slices.findAt(u8, 2, "asd", 'd'), 2);
    try testing.expectEql(slices.findAt(u8, 3, "asd", 'd'), null);
    try testing.expectEql(slices.findAt(u8, 0, "asd", 'f'), null);
    try testing.expectEql(slices.findAt(u8, 3, "asd", 'f'), null);
}

// /////////////
// startsWith //
// /////////////

test "ntz.types.slices.startsWith" {
    try testing.expect(slices.startsWith(u8, "asd", "a"));
    try testing.expect(slices.startsWith(u8, "asd", "as"));
    try testing.expect(slices.startsWith(u8, "asd", "asd"));
    try testing.expect(!slices.startsWith(u8, "asd", ""));
    try testing.expect(!slices.startsWith(u8, "asd", "q"));
    try testing.expect(!slices.startsWith(u8, "asd", "qwer"));
}
