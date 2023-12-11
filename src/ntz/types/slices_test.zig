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

    const got = try slices.append(u8, ally, "hello, world", '!');
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world!");
}

test "ntz.types.slices.append: empty slice" {
    const ally = testing.allocator;

    const got = try slices.append(u8, ally, "", 'M');
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "M");
}

// /////////
// concat //
// /////////

test "ntz.types.slices.concat" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "hello, ", "world!");
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world!");
}

test "ntz.types.slices.concat: empty" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "", "");
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "");
}

test "ntz.types.slices.concat: empty these" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "", "world");
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "world");
}

test "ntz.types.slices.concat: empty those" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "hello", "");
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello");
}

// /////////////
// concatMany //
// /////////////

test "ntz.types.slices.concatMany" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "hello", ", ", "world", "!" });
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "hello, world!");
}

test "ntz.types.slices.concatMany: empty" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{});
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "");
}

test "ntz.types.slices.concatMany: empty slices" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "", "" });
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "");
}

test "ntz.types.slices.concatMany: some empty slices" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "", "world" });
    defer ally.free(got);
    try testing.expectEqlSlcs(u8, got, "world");
}

test "ntz.types.slices.concatMany: empty edges" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "", "hello", "" });
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

// ////////
// equal //
// ////////

test "ntz.types.slices.equal" {
    try testing.expect(slices.equal(u8, "asd", "asd"));
    try testing.expect(!slices.equal(u8, "qwe", "asd"));
    try testing.expect(!slices.equal(u8, "qwe", "asdf"));
}

test "ntz.types.slices.equal: same pointer" {
    const data: []const u8 = "hello, world!";
    try testing.expect(slices.equal(u8, data, data[0..]));
}

test "ntz.types.slices.equal: different pointer" {
    var a: [4]u8 = undefined;
    var b: [4]u8 = undefined;

    @memcpy(&a, "abcd");
    @memcpy(&b, "abcd");

    try testing.expect(slices.equal(u8, &a, &b));
}

// ///////////
// equalAll //
// ///////////

test "ntz.types.slices.equalAll" {
    try testing.expect(slices.equalAll(u8, "asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!slices.equalAll(u8, "asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!slices.equalAll(u8, "asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!slices.equalAll(u8, "asd", &.{ "asd", "asd", "qwe" }));
}

test "ntz.types.slices.equalAll: empty slices" {
    try testing.expect(!slices.equalAll(u8, "asd", &.{ "", "", "" }));
}

test "ntz.types.slices.equalAll: no slices" {
    try testing.expect(!slices.equalAll(u8, "asd", &.{}));
}

// ///////////
// equalAny //
// ///////////

test "ntz.types.slices.equalAny" {
    try testing.expect(slices.equalAny(u8, "asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(slices.equalAny(u8, "asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(slices.equalAny(u8, "asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!slices.equalAny(u8, "asd", &.{ "qwe", "qwe", "qwe" }));
}

test "ntz.types.slices.equalAny: empty slices" {
    try testing.expect(!slices.equalAny(u8, "asd", &.{ "", "", "" }));
}

test "ntz.types.slices.equalAny: no slices" {
    try testing.expect(!slices.equalAny(u8, "asd", &.{}));
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
    try testing.expectEql(slices.findAt(u8, 0, "asd", 's'), 1);
    try testing.expectEql(slices.findAt(u8, 1, "asd", 's'), 1);
    try testing.expectEql(slices.findAt(u8, 2, "asd", 's'), null);
    try testing.expectEql(slices.findAt(u8, 0, "asd", 'd'), 2);
    try testing.expectEql(slices.findAt(u8, 1, "asd", 'd'), 2);
    try testing.expectEql(slices.findAt(u8, 2, "asd", 'd'), 2);
    try testing.expectEql(slices.findAt(u8, 3, "asd", 'd'), null);
    try testing.expectEql(slices.findAt(u8, 0, "asd", 'f'), null);
    try testing.expectEql(slices.findAt(u8, 3, "asd", 'f'), null);
}

// //////////
// findSeq //
// //////////

test "ntz.types.slices.findSeq" {
    try testing.expectEql(slices.findSeq(u8, "asd", "a"), 0);
    try testing.expectEql(slices.findSeq(u8, "asd", "as"), 0);
    try testing.expectEql(slices.findSeq(u8, "asd", "asd"), 0);
    try testing.expectEql(slices.findSeq(u8, "asd", "s"), 1);
    try testing.expectEql(slices.findSeq(u8, "asd", "sd"), 1);
    try testing.expectEql(slices.findSeq(u8, "asd", "d"), 2);
    try testing.expectEql(slices.findSeq(u8, "asd", "f"), null);
}

// ////////////
// findSeqAt //
// ////////////

test "ntz.types.slices.findSeqAt" {
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "a"), 0);
    try testing.expectEql(slices.findSeqAt(u8, 1, "asd", "a"), null);
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "as"), 0);
    try testing.expectEql(slices.findSeqAt(u8, 1, "asd", "as"), null);
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "asd"), 0);
    try testing.expectEql(slices.findSeqAt(u8, 1, "asd", "asd"), null);
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "s"), 1);
    try testing.expectEql(slices.findSeqAt(u8, 1, "asd", "s"), 1);
    try testing.expectEql(slices.findSeqAt(u8, 2, "asd", "s"), null);
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "sd"), 1);
    try testing.expectEql(slices.findSeqAt(u8, 1, "asd", "sd"), 1);
    try testing.expectEql(slices.findSeqAt(u8, 2, "asd", "sd"), null);
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "d"), 2);
    try testing.expectEql(slices.findSeqAt(u8, 1, "asd", "d"), 2);
    try testing.expectEql(slices.findSeqAt(u8, 2, "asd", "d"), 2);
    try testing.expectEql(slices.findSeqAt(u8, 3, "asd", "d"), null);
    try testing.expectEql(slices.findSeqAt(u8, 0, "asd", "f"), null);
    try testing.expectEql(slices.findSeqAt(u8, 3, "asd", "f"), null);
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
