// Copyright 2024 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const bytes = ntz.types.bytes;

test "ntz.types.bytes" {}

// append //

test "ntz.types.bytes.append" {
    const ally = testing.allocator;

    const got = try bytes.append(ally, "hello, world", '!');
    defer ally.free(got);
    try testing.expectEqualStrings("hello, world!", got);
}

// as //

test "ntz.types.bytes.as" {
    const array = [_]u8{ 'a', 'b', 0 };
    try testing.expectEqual([]const u8, @TypeOf(bytes.as(array).?));
    try testing.expectEqual([]const u8, @TypeOf(bytes.as(&array).?));
    try testing.expectEqual([]const u8, @TypeOf(bytes.as("hello, world!").?));

    const mpz: [*:0]const u8 = array[0..2 :0];
    const slc = bytes.as(mpz).?;
    try testing.expectEqual([]const u8, @TypeOf(slc));
    try testing.expectEqual(2, slc.len);

    const mp: [*]const u8 = &array;
    try testing.expectEqual(null, bytes.as(mp));
}

// concat //

test "ntz.types.bytes.concat" {
    const ally = testing.allocator;

    const got = try bytes.concat(ally, "hello, ", "world!");
    defer ally.free(got);
    try testing.expectEqualStrings("hello, world!", got);
}

// concatMany //

test "ntz.types.bytes.concatMany" {
    const ally = testing.allocator;

    const got = try bytes.concatMany(ally, &.{ "hello", ", ", "world", "!" });
    defer ally.free(got);
    try testing.expectEqualStrings("hello, world!", got);
}

// copy //

test "ntz.types.bytes.copy" {
    const src = "abcde";
    var dst: [src.len]u8 = undefined;
    var n = bytes.copy(&dst, src);

    try testing.expectEqualStrings(src, &dst);
    try testing.expectEqual(src.len, n);

    n = bytes.copyAt(3, &dst, "ab");
    try testing.expectEqualStrings("abcab", &dst);
    try testing.expectEqual(2, n);
}

// copyLtr //

test "ntz.types.bytes.copyLtr" {
    const src = "abcde";
    var dst: [src.len]u8 = undefined;
    var n = bytes.copyLtr(&dst, src);

    try testing.expectEqualStrings(src, &dst);
    try testing.expectEqual(src.len, n);

    n = bytes.copyLtr(dst[0..3], dst[2..]);

    try testing.expectEqualStrings("cdede", &dst);
    try testing.expectEqual(3, n);

    _ = bytes.copyLtr(&dst, src);
    n = bytes.copyLtr(dst[2..], dst[0..3]);

    try testing.expectEqualStrings("ababa", &dst);
    try testing.expectEqual(3, n);
}

// copyMany //

test "ntz.types.bytes.copyMany" {
    const src1 = "ab";
    const src2 = "c";
    const src3 = "de";
    var dst: [5]u8 = undefined;
    const n = bytes.copyMany(&dst, &.{ src1, src2, src3 });

    try testing.expectEqualStrings("abcde", &dst);
    try testing.expectEqual(5, n);
}

// copyRtl //

test "ntz.types.bytes.copyRtl" {
    const src = "abcde";
    var dst: [src.len]u8 = undefined;
    var n = bytes.copyRtl(&dst, src);

    try testing.expectEqualStrings(src, &dst);
    try testing.expectEqual(src.len, n);

    n = bytes.copyRtl(dst[0..3], dst[2..]);

    try testing.expectEqualStrings("edede", &dst);
    try testing.expectEqual(3, n);

    _ = bytes.copyRtl(&dst, src);
    n = bytes.copyRtl(dst[2..], dst[0..3]);

    try testing.expectEqualStrings("ababc", &dst);
    try testing.expectEqual(3, n);
}

// count //

test "ntz.types.bytes.count" {
    try testing.expectEqual(1, bytes.count("asd", 'a'));
    try testing.expectEqual(1, bytes.count("asd", 's'));
    try testing.expectEqual(1, bytes.count("asd", 'd'));
    try testing.expectEqual(0, bytes.count("asd", 'f'));
    try testing.expectEqual(3, bytes.count("www", 'w'));

    try testing.expectEqual(0, bytes.countAt(1, "asd", 'a'));
    try testing.expectEqual(3, bytes.countAt(0, "www", 'w'));
    try testing.expectEqual(2, bytes.countAt(1, "www", 'w'));
    try testing.expectEqual(1, bytes.countAt(2, "www", 'w'));
}

// endsWith //

test "ntz.types.bytes.endsWith" {
    try testing.expect(bytes.endsWith("asd", "d"));
    try testing.expect(bytes.endsWith("asd", "sd"));
    try testing.expect(bytes.endsWith("asd", "asd"));
    try testing.expect(!bytes.endsWith("asd", ""));
    try testing.expect(!bytes.endsWith("asd", "q"));
    try testing.expect(!bytes.endsWith("asd", "qwer"));
}

// equal //

test "ntz.types.bytes.equal" {
    try testing.expect(bytes.equal("asd", "asd"));
    try testing.expect(!bytes.equal("qwe", "asd"));
    try testing.expect(!bytes.equal("qwe", "asdf"));
}

// equalAll //

test "ntz.types.bytes.equalAll" {
    try testing.expect(bytes.equalAll("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(!bytes.equalAll("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(!bytes.equalAll("asd", &.{ "asd", "qwe", "asd" }));
    try testing.expect(!bytes.equalAll("asd", &.{ "asd", "asd", "qwe" }));
}

// equalAny //

test "ntz.types.bytes.equalAny" {
    try testing.expect(bytes.equalAny("asd", &.{ "asd", "asd", "asd" }));
    try testing.expect(bytes.equalAny("asd", &.{ "qwe", "asd", "asd" }));
    try testing.expect(bytes.equalAny("asd", &.{ "qwe", "qwe", "asd" }));
    try testing.expect(!bytes.equalAny("asd", &.{ "qwe", "qwe", "qwe" }));
}

// find //

test "ntz.types.bytes.find" {
    try testing.expectEqual(0, bytes.find("asd", 'a'));
    try testing.expectEqual(1, bytes.find("asd", 's'));
    try testing.expectEqual(2, bytes.find("asd", 'd'));
    try testing.expectEqual(null, bytes.find("asd", 'f'));

    try testing.expectEqual(null, bytes.findAt(1, "asd", 'a'));
    try testing.expectEqual(null, bytes.findAt(3, "asd", 'd'));
    try testing.expectEqual(null, bytes.findAt(0, "asd", 'f'));
    try testing.expectEqual(null, bytes.findAt(3, "asd", 'f'));
}

// findAny //

test "ntz.types.bytes.findAny" {
    try testing.expectEqualDeep(
        bytes.FindAnyResult{ .index = 0, .value = 'a' },
        bytes.findAny("asd", &.{ 'a', 's', 'd' }),
    );

    try testing.expectEqual(null, bytes.findAny("asd", &.{}));
    try testing.expectEqual(null, bytes.findAny("asd", &.{'f'}));
    try testing.expectEqual(null, bytes.findAny("asd", &.{ 'f', 'g' }));

    try testing.expectEqualDeep(
        bytes.FindAnyResult{ .index = 1, .value = 's' },
        bytes.findAnyAt(1, "asd", &.{ 'a', 's' }),
    );

    try testing.expectEqual(null, bytes.findAnyAt(2, "asd", &.{ 'a', 's' }));
}

// findSeq //

test "ntz.types.bytes.findSeq" {
    try testing.expectEqual(0, bytes.findSeq("asd", "a"));
    try testing.expectEqual(0, bytes.findSeq("asd", "as"));
    try testing.expectEqual(0, bytes.findSeq("asd", "asd"));
    try testing.expectEqual(1, bytes.findSeq("asd", "s"));
    try testing.expectEqual(1, bytes.findSeq("asd", "sd"));
    try testing.expectEqual(2, bytes.findSeq("asd", "d"));
    try testing.expectEqual(null, bytes.findSeq("asd", "f"));

    try testing.expectEqual(null, bytes.findSeqAt(1, "asd", "a"));
    try testing.expectEqual(null, bytes.findSeqAt(1, "asd", "as"));
    try testing.expectEqual(null, bytes.findSeqAt(3, "asd", "d"));
    try testing.expectEqual(null, bytes.findSeqAt(0, "asd", "f"));
    try testing.expectEqual(null, bytes.findSeqAt(3, "asd", "f"));
}

// is //

test "ntz.types.bytes.is" {
    // Slices.

    var s: []const u8 = "";
    try testing.expect(bytes.is(s));

    s = "hello, world";
    try testing.expect(bytes.is(s));

    var ss: [:0]const u8 = "";
    try testing.expect(bytes.is(ss));

    ss = "hello, world";
    try testing.expect(bytes.is(ss));

    const s32: []const u32 = &.{ 1, 2, 3 };
    try testing.expect(!bytes.is(s32));

    // Arrays.

    var arr = bytes.mut("qwerry");
    arr[4] = 't';
    try testing.expect(bytes.is(arr));

    const arr32 = [_]u32{ 1, 2, 3 };
    try testing.expect(!bytes.is(arr32));

    // Pointers.

    try testing.expect(bytes.is(&arr));
    try testing.expect(!bytes.is(&arr32));

    const n = 42;
    try testing.expect(!bytes.is(&n));

    const mps: [*:0]const u8 = "hello, world";
    try testing.expect(bytes.is(mps));

    const mps32: [*:0]const u32 = &.{ 1, 2, 3, 0 };
    try testing.expect(!bytes.is(mps32));

    const mp: [*]const u8 = "hello, world";
    try testing.expect(!bytes.is(mp));

    const mp32: [*]const u32 = &.{ 1, 2, 3 };
    try testing.expect(!bytes.is(mp32));

    const cp: [*c]const u8 = "hello, world";
    try testing.expect(!bytes.is(cp));
}

// mut //

test "ntz.types.bytes.mut" {
    var in = bytes.mut("hello. world!");
    in[5] = ',';
    const want = "hello, world!";
    try testing.expectEqualStrings(want, &in);
}

// split //

test "ntz.types.bytes.split" {
    var first, var rest = bytes.split("asd", 'a');
    try testing.expectEqualStrings("", first);
    try testing.expectEqualStrings("sd", rest);

    first, rest = bytes.split("asd", 's');
    try testing.expectEqualStrings("a", first);
    try testing.expectEqualStrings("d", rest);

    first, rest = bytes.split("asd", 'd');
    try testing.expectEqualStrings("as", first);
    try testing.expectEqualStrings("", rest);

    first, rest = bytes.split("asd", 'f');
    try testing.expectEqualStrings("asd", first);
    try testing.expectEqualStrings("", rest);

    first, rest = bytes.splitAt(1, "asd", 'a');
    try testing.expectEqualStrings("sd", first);
    try testing.expectEqualStrings("", rest);

    first, rest = bytes.splitAt(2, "asd", 'd');
    try testing.expectEqualStrings("", first);
    try testing.expectEqualStrings("", rest);

    first, rest = bytes.splitAt(0, "asd", 'f');
    try testing.expectEqualStrings("asd", first);
    try testing.expectEqualStrings("", rest);
}

// splitCount //

test "ntz.types.bytes.splitCount" {
    try testing.expectEqual(2, bytes.splitCount("asd", 'a'));
    try testing.expectEqual(2, bytes.splitCount("asd", 's'));
    try testing.expectEqual(2, bytes.splitCount("asd", 'd'));
    try testing.expectEqual(1, bytes.splitCount("asd", 'f'));
}

// splitIterator //

test "ntz.types.bytes.splitIterator" {
    var it = bytes.splitIterator("asd", 'a');
    try testing.expectEqualStrings("", it.next().?);
    try testing.expectEqualStrings("sd", it.next().?);
    try testing.expectEqual(null, it.next());

    it = bytes.splitIterator("asd", 's');
    try testing.expectEqualStrings("a", it.next().?);
    try testing.expectEqualStrings("d", it.next().?);
    try testing.expectEqual(null, it.next());

    it = bytes.splitIterator("asd", 'd');
    try testing.expectEqualStrings("as", it.next().?);
    try testing.expectEqualStrings("", it.next().?);
    try testing.expectEqual(null, it.next());

    it = bytes.splitIterator("asd", 'f');
    try testing.expectEqualStrings("asd", it.next().?);
    try testing.expectEqual(null, it.next());
}

// splitn //

test "ntz.types.bytes.splitn" {
    var out: [4][]const u8 = undefined;

    var got = try bytes.splitn(1, &out, "asd", 'a');
    var want: []const []const u8 = &.{ "", "sd" };
    for (0..want.len) |i| try testing.expectEqualStrings(want[i], got[i]);
    try testing.expectEqual(2, got.len);

    got = try bytes.splitn(1, &out, "asd", 's');
    want = &.{ "a", "d" };
    for (0..want.len) |i| try testing.expectEqualStrings(want[i], got[i]);
    try testing.expectEqual(2, got.len);

    got = try bytes.splitn(1, &out, "asd", 'd');
    want = &.{ "as", "" };
    for (0..want.len) |i| try testing.expectEqualStrings(want[i], got[i]);
    try testing.expectEqual(2, got.len);
}

// startsWith //

test "ntz.types.bytes.startsWith" {
    try testing.expect(bytes.startsWith("asd", "a"));
    try testing.expect(bytes.startsWith("asd", "as"));
    try testing.expect(bytes.startsWith("asd", "asd"));
    try testing.expect(!bytes.startsWith("asd", ""));
    try testing.expect(!bytes.startsWith("asd", "q"));
    try testing.expect(!bytes.startsWith("asd", "qwer"));
}

// /////////
// Buffer //
// /////////

test "ntz.types.bytes.Buffer" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();

    var n = try buf.write("hello, world");
    try testing.expectEqualStrings("hello, world", buf.bytes());
    try testing.expectEqual(12, n);

    n = try buf.write("!");
    try testing.expectEqualStrings("hello, world!", buf.bytes());
    try testing.expectEqual(1, n);

    n = try buf.write(" and bye..");
    try testing.expectEqual(10, n);
    try testing.expectEqualStrings("hello, world! and bye..", buf.bytes());

    buf.clear();
    try testing.expectEqualStrings("", buf.bytes());
}

test "ntz.types.bytes.BufferFixed" {
    var data: [24]u8 = undefined;
    var buf = bytes.fixedBuffer(&data);

    var n = try buf.write("hello, world");
    try testing.expectEqualStrings("hello, world", buf.bytes());
    try testing.expectEqual(12, n);

    n = try buf.write("!");
    try testing.expectEqualStrings("hello, world!", buf.bytes());
    try testing.expectEqual(1, n);

    n = try buf.write(" and bye..");
    try testing.expectEqual(10, n);
    try testing.expectEqualStrings("hello, world! and bye..", buf.bytes());

    try testing.expectError(
        bytes.BufferFixed.WriteError.OutOfMemory,
        buf.write("full"),
    );

    buf.clear();
    try testing.expectEqualStrings("", buf.bytes());
}
