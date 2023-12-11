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

test "ntz.types.bytes.concat: empty" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "", "");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "");
}

test "ntz.types.bytes.concat: empty these" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "", "world");
    defer ally.free(got);
    try testing.expectEqlBytes(got, "world");
}

test "ntz.types.bytes.concat: empty those" {
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

// ////////
// equal //
// ////////

test "ntz.types.bytes.equal" {
    try testing.expect(bytes.equal("asd", "asd"));
    try testing.expect(!bytes.equal("qwe", "asd"));
    try testing.expect(!bytes.equal("qwe", "asdf"));
}

test "ntz.types.bytes.equal: same pointer" {
    const data: []const u8 = "hello, world!";
    try testing.expect(bytes.equal(data, data[0..]));
}

test "ntz.types.bytes.equal: different pointer" {
    var a: [4]u8 = undefined;
    var b: [4]u8 = undefined;

    @memcpy(&a, "abcd");
    @memcpy(&b, "abcd");

    try testing.expect(bytes.equal(&a, &b));
}

// ///////////
// equalAll //
// ///////////

test "ntz.types.bytes.equalAll" {
    try testing.expect(bytes.equalAll("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!bytes.equalAll("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!bytes.equalAll("asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!bytes.equalAll("asd", &.{ "asd", "asd", "qwe" }));
}

test "ntz.types.bytes.equalAll: empty slices" {
    try testing.expect(!bytes.equalAll("asd", &.{ "", "", "" }));
}

test "ntz.types.bytes.equalAll: no slices" {
    try testing.expect(!bytes.equalAll("asd", &.{}));
}

// ///////////
// equalAny //
// ///////////

test "ntz.types.bytes.equalAny" {
    try testing.expect(bytes.equalAny("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(bytes.equalAny("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(bytes.equalAny("asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!bytes.equalAny("asd", &.{ "qwe", "qwe", "qwe" }));
}

test "ntz.types.bytes.equalAny: empty slices" {
    try testing.expect(!bytes.equalAny("asd", &.{ "", "", "" }));
}

test "ntz.types.bytes.equalAny: no slices" {
    try testing.expect(!bytes.equalAny("asd", &.{}));
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

// //////////
// findSeq //
// //////////

test "ntz.types.bytes.findSeq" {
    try testing.expectEql(bytes.findSeq("asd", "a"), 0);
    try testing.expectEql(bytes.findSeq("asd", "as"), 0);
    try testing.expectEql(bytes.findSeq("asd", "asd"), 0);
    try testing.expectEql(bytes.findSeq("asd", "s"), 1);
    try testing.expectEql(bytes.findSeq("asd", "sd"), 1);
    try testing.expectEql(bytes.findSeq("asd", "d"), 2);
    try testing.expectEql(bytes.findSeq("asd", "f"), null);
}

// ////////////
// findSeqAt //
// ////////////

test "ntz.types.bytes.findSeqAt" {
    try testing.expectEql(bytes.findSeqAt(0, "asd", "a"), 0);
    try testing.expectEql(bytes.findSeqAt(1, "asd", "a"), null);
    try testing.expectEql(bytes.findSeqAt(0, "asd", "as"), 0);
    try testing.expectEql(bytes.findSeqAt(1, "asd", "as"), null);
    try testing.expectEql(bytes.findSeqAt(0, "asd", "asd"), 0);
    try testing.expectEql(bytes.findSeqAt(1, "asd", "asd"), null);
    try testing.expectEql(bytes.findSeqAt(0, "asd", "s"), 1);
    try testing.expectEql(bytes.findSeqAt(1, "asd", "s"), 1);
    try testing.expectEql(bytes.findSeqAt(2, "asd", "s"), null);
    try testing.expectEql(bytes.findSeqAt(0, "asd", "sd"), 1);
    try testing.expectEql(bytes.findSeqAt(1, "asd", "sd"), 1);
    try testing.expectEql(bytes.findSeqAt(2, "asd", "sd"), null);
    try testing.expectEql(bytes.findSeqAt(0, "asd", "d"), 2);
    try testing.expectEql(bytes.findSeqAt(1, "asd", "d"), 2);
    try testing.expectEql(bytes.findSeqAt(2, "asd", "d"), 2);
    try testing.expectEql(bytes.findSeqAt(3, "asd", "d"), null);
    try testing.expectEql(bytes.findSeqAt(0, "asd", "f"), null);
    try testing.expectEql(bytes.findSeqAt(3, "asd", "f"), null);
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
