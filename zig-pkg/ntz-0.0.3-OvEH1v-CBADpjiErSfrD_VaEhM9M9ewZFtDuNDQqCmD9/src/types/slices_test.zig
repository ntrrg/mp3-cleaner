// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const slices = ntz.types.slices;

test "ntz.types.slices" {}

// Child //

test "ntz.types.slices.Child" {
    try testing.expectEqual(u8, slices.Child([]u8));
    try testing.expectEqual(u8, slices.Child([0]u8));
    try testing.expectEqual(u8, slices.Child(*[0]u8));
    try testing.expectEqual(u8, slices.Child([*:0]u8));
}

// append //

test "ntz.types.slices.append" {
    const ally = testing.allocator;

    const got = try slices.append(u8, ally, "hello, world", '!');
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "hello, world!", got);
}

test "ntz.types.slices.append: empty slice" {
    const ally = testing.allocator;

    const got = try slices.append(u8, ally, "", 'M');
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "M", got);
}

// as //

test "ntz.types.slices.as" {
    const array = [_]u8{ 'a', 'b', 0 };
    try testing.expectEqual([]const u8, @TypeOf(slices.as(array).?));
    try testing.expectEqual([]const u8, @TypeOf(slices.as(&array).?));
    try testing.expectEqual([]const u8, @TypeOf(slices.as("hello, world!").?));

    const mpz: [*:0]const u8 = array[0..2 :0];
    const slc = slices.as(mpz).?;
    try testing.expectEqual([]const u8, @TypeOf(slc));
    try testing.expectEqual(2, slc.len);

    const mp: [*]const u8 = &array;
    try testing.expectEqual(null, slices.as(mp));
}

// concat //

test "ntz.types.slices.concat" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "hello, ", "world!");
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "hello, world!", got);
}

test "ntz.types.slices.concat: empty" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "", "");
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "", got);
}

test "ntz.types.slices.concat: empty these" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "", "world");
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "world", got);
}

test "ntz.types.slices.concat: empty those" {
    const ally = testing.allocator;

    const got = try slices.concat(u8, ally, "hello", "");
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "hello", got);
}

// concatMany //

test "ntz.types.slices.concatMany" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "hello", ", ", "world", "!" });
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "hello, world!", got);
}

test "ntz.types.slices.concatMany: empty" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{});
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "", got);
}

test "ntz.types.slices.concatMany: empty slices" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "", "" });
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "", got);
}

test "ntz.types.slices.concatMany: some empty slices" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "", "world" });
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "world", got);
}

test "ntz.types.slices.concatMany: empty edges" {
    const ally = testing.allocator;

    const got = try slices.concatMany(u8, ally, &.{ "", "hello", "" });
    defer ally.free(got);
    try testing.expectEqualSlices(u8, "hello", got);
}

// copy //

test "ntz.types.slices.copy" {
    const src = "abcde";
    var dst: [src.len]u8 = undefined;
    var n = slices.copy(u8, &dst, src);
    try testing.expectEqualSlices(u8, src, &dst);
    try testing.expectEqual(src.len, n);

    n = slices.copyAt(u8, 3, &dst, "ab");
    try testing.expectEqualSlices(u8, "abcab", &dst);
    try testing.expectEqual(2, n);
}

// copyLtr //

test "ntz.types.slices.copyLtr" {
    const src = "abcde";
    var dst: [src.len]u8 = undefined;
    var n = slices.copyLtr(u8, &dst, src);

    try testing.expectEqualSlices(u8, src, &dst);
    try testing.expectEqual(src.len, n);

    n = slices.copyLtr(u8, dst[0..3], dst[2..]);

    try testing.expectEqualSlices(u8, "cdede", &dst);
    try testing.expectEqual(3, n);

    _ = slices.copyLtr(u8, &dst, src);
    n = slices.copyLtr(u8, dst[2..], dst[0..3]);

    try testing.expectEqualSlices(u8, "ababa", &dst);
    try testing.expectEqual(3, n);
}

// copyMany //

test "ntz.types.slices.copyMany" {
    const src1 = "ab";
    const src2 = "c";
    const src3 = "de";
    var dst: [5]u8 = undefined;
    const n = slices.copyMany(u8, &dst, &.{ src1, src2, src3 });

    try testing.expectEqualSlices(u8, "abcde", &dst);
    try testing.expectEqual(5, n);
}

// copyRtl //

test "ntz.types.slices.copyRtl" {
    const src = "abcde";
    var dst: [src.len]u8 = undefined;
    var n = slices.copyRtl(u8, &dst, src);

    try testing.expectEqualSlices(u8, src, &dst);
    try testing.expectEqual(src.len, n);

    n = slices.copyRtl(u8, dst[0..3], dst[2..]);

    try testing.expectEqualSlices(u8, "edede", &dst);
    try testing.expectEqual(3, n);

    _ = slices.copyRtl(u8, &dst, src);
    n = slices.copyRtl(u8, dst[2..], dst[0..3]);

    try testing.expectEqualSlices(u8, "ababc", &dst);
    try testing.expectEqual(3, n);
}

// count //

test "ntz.types.slices.count" {
    try testing.expectEqual(1, slices.count(u8, "asd", 'a'));
    try testing.expectEqual(1, slices.count(u8, "asd", 's'));
    try testing.expectEqual(1, slices.count(u8, "asd", 'd'));
    try testing.expectEqual(0, slices.count(u8, "asd", 'f'));
    try testing.expectEqual(3, slices.count(u8, "www", 'w'));

    try testing.expectEqual(0, slices.countAt(u8, 1, "asd", 'a'));
    try testing.expectEqual(3, slices.countAt(u8, 0, "www", 'w'));
    try testing.expectEqual(2, slices.countAt(u8, 1, "www", 'w'));
    try testing.expectEqual(1, slices.countAt(u8, 2, "www", 'w'));
}

// endsWith //

test "ntz.types.slices.endsWith" {
    try testing.expect(slices.endsWith(u8, "asd", "d"));
    try testing.expect(slices.endsWith(u8, "asd", "sd"));
    try testing.expect(slices.endsWith(u8, "asd", "asd"));
    try testing.expect(!slices.endsWith(u8, "asd", ""));
    try testing.expect(!slices.endsWith(u8, "asd", "q"));
    try testing.expect(!slices.endsWith(u8, "asd", "qwer"));
}

// equal //

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

// equalAll //

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

// equalAny //

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

// find //

test "ntz.types.slices.find" {
    try testing.expectEqual(0, slices.find(u8, "asd", 'a'));
    try testing.expectEqual(1, slices.find(u8, "asd", 's'));
    try testing.expectEqual(2, slices.find(u8, "asd", 'd'));
    try testing.expectEqual(null, slices.find(u8, "asd", 'f'));

    try testing.expectEqual(null, slices.findAt(u8, 1, "asd", 'a'));
    try testing.expectEqual(null, slices.findAt(u8, 3, "asd", 'd'));
    try testing.expectEqual(null, slices.findAt(u8, 0, "asd", 'f'));
    try testing.expectEqual(null, slices.findAt(u8, 3, "asd", 'f'));
}

// findAny //

test "ntz.types.slices.findAny" {
    try testing.expectEqual(
        slices.FindAnyResult(u8){ .index = 0, .value = 'a' },
        slices.findAny(u8, "asd", &.{ 'a', 's', 'd' }),
    );

    try testing.expectEqual(null, slices.findAny(u8, "asd", &.{}));
    try testing.expectEqual(null, slices.findAny(u8, "asd", &.{'f'}));
    try testing.expectEqual(null, slices.findAny(u8, "asd", &.{ 'f', 'g' }));

    try testing.expectEqual(
        slices.FindAnyResult(u8){ .index = 1, .value = 's' },
        slices.findAnyAt(u8, 1, "asd", &.{ 'a', 's' }),
    );

    try testing.expectEqual(null, slices.findAnyAt(u8, 2, "asd", &.{ 'a', 's' }));
}

// findSeq //

test "ntz.types.slices.findSeq" {
    try testing.expectEqual(0, slices.findSeq(u8, "asd", "a"));
    try testing.expectEqual(0, slices.findSeq(u8, "asd", "as"));
    try testing.expectEqual(0, slices.findSeq(u8, "asd", "asd"));
    try testing.expectEqual(1, slices.findSeq(u8, "asd", "s"));
    try testing.expectEqual(1, slices.findSeq(u8, "asd", "sd"));
    try testing.expectEqual(2, slices.findSeq(u8, "asd", "d"));
    try testing.expectEqual(null, slices.findSeq(u8, "asd", "f"));

    try testing.expectEqual(null, slices.findSeqAt(u8, 1, "asd", "a"));
    try testing.expectEqual(null, slices.findSeqAt(u8, 1, "asd", "as"));
    try testing.expectEqual(null, slices.findSeqAt(u8, 3, "asd", "d"));
    try testing.expectEqual(null, slices.findSeqAt(u8, 0, "asd", "f"));
    try testing.expectEqual(null, slices.findSeqAt(u8, 3, "asd", "f"));
}

// is //

test "ntz.types.slices.is" {
    const array = [_]u8{ 'a', 'b', 0 };
    try testing.expect(slices.is(array));
    try testing.expect(slices.is(&array));
    try testing.expect(slices.is("hello, world!"));

    var n: u8 = 42;
    const sp: *u8 = &n;
    try testing.expect(!slices.is(sp));

    const mps: [*:0]const u8 = array[0..2 :0];
    try testing.expect(slices.is(mps));

    const mp: [*]const u8 = &array;
    try testing.expect(!slices.is(mp));

    const cp: [*c]const c_char = &[_]c_char{ 'a', 'b', 0 };
    try testing.expect(!slices.is(cp));

    try testing.expect(!slices.is(true));
    try testing.expect(!slices.is(42));

    var op_val = "hello, world!";
    const op: *anyopaque = @ptrCast(&op_val);
    try testing.expect(!slices.is(op));
}

// split //

test "ntz.types.slices.split" {
    var first, var rest = slices.split(u8, "asd", 'a');
    try testing.expectEqualSlices(u8, "", first);
    try testing.expectEqualSlices(u8, "sd", rest);

    first, rest = slices.split(u8, "asd", 's');
    try testing.expectEqualSlices(u8, "a", first);
    try testing.expectEqualSlices(u8, "d", rest);

    first, rest = slices.split(u8, "asd", 'd');
    try testing.expectEqualSlices(u8, "as", first);
    try testing.expectEqualSlices(u8, "", rest);

    first, rest = slices.split(u8, "asd", 'f');
    try testing.expectEqualSlices(u8, "asd", first);
    try testing.expectEqualSlices(u8, "", rest);

    first, rest = slices.splitAt(u8, 1, "asd", 'a');
    try testing.expectEqualSlices(u8, "sd", first);
    try testing.expectEqualSlices(u8, "", rest);

    first, rest = slices.splitAt(u8, 2, "asd", 'd');
    try testing.expectEqualSlices(u8, "", first);
    try testing.expectEqualSlices(u8, "", rest);

    first, rest = slices.splitAt(u8, 0, "asd", 'f');
    try testing.expectEqualSlices(u8, "asd", first);
    try testing.expectEqualSlices(u8, "", rest);
}

// splitCount //

test "ntz.types.slices.splitCount" {
    try testing.expectEqual(2, slices.splitCount(u8, "asd", 'a'));
    try testing.expectEqual(2, slices.splitCount(u8, "asd", 's'));
    try testing.expectEqual(2, slices.splitCount(u8, "asd", 'd'));
    try testing.expectEqual(1, slices.splitCount(u8, "asd", 'f'));
    try testing.expectEqual(3, slices.splitCount(u8, "awswd", 'w'));
    try testing.expectEqual(4, slices.splitCount(u8, "wawswd", 'w'));
    try testing.expectEqual(4, slices.splitCount(u8, "awswdw", 'w'));
    try testing.expectEqual(4, slices.splitCount(u8, "awswdwf", 'w'));
    try testing.expectEqual(4, slices.splitCount(u8, "www", 'w'));
    try testing.expectEqual(1, slices.splitCount(u8, "", 'a'));
}

// splitIterator //

test "ntz.types.slices.splitIterator" {
    var it = slices.splitIterator(u8, "asd", 'a');
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqualSlices(u8, "sd", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "asd", 's');
    try testing.expectEqualSlices(u8, "a", it.next().?);
    try testing.expectEqualSlices(u8, "d", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "asd", 'd');
    try testing.expectEqualSlices(u8, "as", it.next().?);
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "asd", 'f');
    try testing.expectEqualSlices(u8, "asd", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "awswd", 'w');
    try testing.expectEqualSlices(u8, "a", it.next().?);
    try testing.expectEqualSlices(u8, "s", it.next().?);
    try testing.expectEqualSlices(u8, "d", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "wawswd", 'w');
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqualSlices(u8, "a", it.next().?);
    try testing.expectEqualSlices(u8, "s", it.next().?);
    try testing.expectEqualSlices(u8, "d", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "awswdw", 'w');
    try testing.expectEqualSlices(u8, "a", it.next().?);
    try testing.expectEqualSlices(u8, "s", it.next().?);
    try testing.expectEqualSlices(u8, "d", it.next().?);
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "awswdwf", 'w');
    try testing.expectEqualSlices(u8, "a", it.next().?);
    try testing.expectEqualSlices(u8, "s", it.next().?);
    try testing.expectEqualSlices(u8, "d", it.next().?);
    try testing.expectEqualSlices(u8, "f", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "www", 'w');
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqual(null, it.next());

    it = slices.splitIterator(u8, "", 'a');
    try testing.expectEqualSlices(u8, "", it.next().?);
    try testing.expectEqual(null, it.next());
}

// splitn //

test "ntz.types.slices.splitn" {
    var out: [4][]const u8 = undefined;

    var got = try slices.splitn(u8, 1, &out, "asd", 'a');
    var want: []const []const u8 = &.{ "", "sd" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(2, got.len);

    got = try slices.splitn(u8, 1, &out, "asd", 's');
    want = &.{ "a", "d" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(2, got.len);

    got = try slices.splitn(u8, 1, &out, "asd", 'd');
    want = &.{ "as", "" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(2, got.len);

    got = try slices.splitn(u8, 1, &out, "asd", 'f');
    want = &.{"asd"};
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(1, got.len);

    got = try slices.splitn(u8, 2, &out, "awswd", 'w');
    want = &.{ "a", "s", "d" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(3, got.len);

    got = try slices.splitn(u8, 3, &out, "wawswd", 'w');
    want = &.{ "", "a", "s", "d" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(4, got.len);

    got = try slices.splitn(u8, 3, &out, "awswdw", 'w');
    want = &.{ "a", "s", "d", "" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(4, got.len);

    got = try slices.splitn(u8, 1, &out, "awswd", 'w');
    want = &.{ "a", "swd" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(2, got.len);

    got = try slices.splitn(u8, 2, &out, "awswdwf", 'w');
    want = &.{ "a", "s", "dwf" };
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(3, got.len);

    got = try slices.splitn(u8, 0, &out, "www", 'w');
    want = &.{"www"};
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(1, got.len);

    got = try slices.splitn(u8, 1, &out, "", 'w');
    want = &.{""};
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(1, got.len);

    try testing.expectError(
        slices.SplitError.OutOfMemory,
        slices.splitn(u8, 0, out[0..0], "asd", 's'),
    );

    try testing.expectError(
        slices.SplitError.OutOfMemory,
        slices.splitn(u8, 1, out[0..1], "asd", 's'),
    );

    try testing.expectError(
        slices.SplitError.OutOfMemory,
        slices.splitn(u8, 1, out[0..1], "asdf", 's'),
    );

    got = try slices.splitnAt(u8, 2, 1, &out, "asdf", 's');
    want = &.{"df"};
    for (0..want.len) |i| try testing.expectEqualSlices(u8, want[i], got[i]);
    try testing.expectEqual(1, got.len);
}

// startsWith //

test "ntz.types.slices.startsWith" {
    try testing.expect(slices.startsWith(u8, "asd", "a"));
    try testing.expect(slices.startsWith(u8, "asd", "as"));
    try testing.expect(slices.startsWith(u8, "asd", "asd"));
    try testing.expect(!slices.startsWith(u8, "asd", ""));
    try testing.expect(!slices.startsWith(u8, "asd", "q"));
    try testing.expect(!slices.startsWith(u8, "asd", "qwer"));
}

// ////////
// Slice //
// ////////

test "ntz.types.slices.Slice" {
    const ally = testing.allocator;

    var slc = (slices.Slice(u8){}).managed(ally);
    defer slc.deinit();

    try testing.expectEqual(0, slc.cap());

    try slc.appendMany("hello, world");
    try testing.expectEqualSlices(u8, "hello, world", slc.items());
    try testing.expectEqual(12, slc.len());
    try testing.expectEqual(12, slc.cap());
    try testing.expectEqual(0, slc.available());

    try slc.append('!');
    try testing.expectEqualSlices(u8, "hello, world!", slc.items());
    try testing.expectEqual(13, slc.len());
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(11, slc.available());

    try slc.appendMany(" and bye..");
    try testing.expectEqualSlices(u8, "hello, world! and bye..", slc.items());
    try testing.expectEqual(23, slc.len());
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(1, slc.available());

    slc.clear();
    try testing.expectEqual(0, slc.len());
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(24, slc.available());

    try slc.appendMany("hello, world!");
    try slc.resize(12);
    try testing.expectEqualSlices(u8, "hello, world", slc.items());
    try testing.expectEqual(12, slc.len());
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(12, slc.available());

    try slc.setCapacity(12);
    try testing.expectEqualSlices(u8, "hello, world", slc.items());
    try testing.expectEqual(12, slc.len());
    try testing.expectEqual(12, slc.cap());
    try testing.expectEqual(0, slc.available());

    try slc.setCapacity(0);
    try testing.expectEqual(0, slc.len());
    try testing.expectEqual(0, slc.cap());
    try testing.expectEqual(0, slc.available());

    try slc.setCapacity(1);
    try testing.expectEqual(0, slc.len());
    try testing.expectEqual(1, slc.cap());
    try testing.expectEqual(1, slc.available());

    const elem = try slc.appendAndReturn('M');
    try testing.expectEqual(&slc.slc.ptr[0], elem);
    slc.clear();

    try slc.appendSlices(&.{ "hello", ", ", "world", "!" });
    try testing.expectEqualSlices(u8, "hello, world!", slc.items());
    try testing.expectEqual(13, slc.len());
    try testing.expectEqual(13, slc.cap());
    try testing.expectEqual(0, slc.available());
}

// /////////////
// SliceFixed //
// /////////////

test "ntz.types.slices.SliceFixed" {
    var data: [24]u8 = undefined;
    var slc = slices.SliceFixed(u8){ .data = &data };

    try testing.expectEqual(24, slc.cap());

    try slc.appendMany("hello, world");
    try testing.expectEqualSlices(u8, "hello, world", slc.items());
    try testing.expectEqual(12, slc.len);
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(12, slc.available());

    try slc.append('!');
    try testing.expectEqualSlices(u8, "hello, world!", slc.items());
    try testing.expectEqual(13, slc.len);
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(11, slc.available());

    try slc.appendMany(" and bye..");
    try testing.expectEqualSlices(u8, "hello, world! and bye..", slc.items());
    try testing.expectEqual(23, slc.len);
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(1, slc.available());

    slc.clear();
    try testing.expectEqual(0, slc.len);
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(24, slc.available());

    try slc.appendMany("hello, world!");
    slc.len = 12;
    try testing.expectEqualSlices(u8, "hello, world", slc.items());
    try testing.expectEqual(12, slc.len);
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(12, slc.available());

    slc.clear();
    const elem = try slc.appendAndReturn('M');
    try testing.expectEqual(&slc.data[0], elem);
    slc.clear();

    try slc.appendSlices(&.{ "hello", ", ", "world", "!" });
    try testing.expectEqualSlices(u8, "hello, world!", slc.items());
    try testing.expectEqual(13, slc.len);
    try testing.expectEqual(24, slc.cap());
    try testing.expectEqual(11, slc.available());

    try testing.expectError(
        slices.SliceFixed(u8).Error.OutOfMemory,
        slc.appendMany("not enough memory!!"),
    );
}
