// Copyright 2025 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const iterators = ntz.types.iterators;

test "ntz.types.iterators" {}

// ///////////
// Iterator //
// ///////////

fn bytesIteratorNextIndex(_: *[]const u8, index: usize) usize {
    return index +| 1;
}

fn bytesIteratorGetItem(slc: *[]const u8, index: usize) ?u8 {
    return if (index < slc.len) slc.*[index] else null;
}

fn bytesIterator(slc: []const u8) iterators.Iterator(
    []const u8,
    usize,
    u8,
    null,
    bytesIteratorNextIndex,
    bytesIteratorGetItem,
) {
    return .{ .ctx = slc, .index = 0 };
}

test "ntz.types.iterators.Iterator" {
    var it = bytesIterator("hello, world!");
    try testing.expectEqual('h', it.peek());
    try testing.expectEqual('h', it.next());
    try testing.expectEqual('e', it.peek());
    try testing.expectEqual('l', it.peekN(2));
    try testing.expectEqual('l', it.peekN(3));
    it.skip();
    try testing.expectEqual('l', it.peek());
    try testing.expectEqual('l', it.peekN(2));
    try testing.expectEqual('o', it.peekN(3));
    it.skipN(10);
    try testing.expectEqual('!', it.peek());
    try testing.expectEqual('!', it.next());
    try testing.expectEqual(null, it.peek());
    try testing.expectEqual(null, it.peekN(2));
    try testing.expectEqual(null, it.peekN(3));

    it.index = 0;
    try testing.expectEqual('!', it.peekN(13));
    it.skipN(13);
    try testing.expectEqual(null, it.peek());
    try testing.expectEqual(null, it.next());

    try testing.expectEqual('h', it.get(0));
    try testing.expectEqual(',', it.get(5));
    try testing.expectEqual('!', it.get(12));
}

test "ntz.types.iterators.Iterator.Result" {
    var it = bytesIterator("hello, world!");
    const Result = @TypeOf(it).Result;

    try testing.expectEqual(
        Result{ .index = 0, .item = 'h' },
        it.peekResult(),
    );

    try testing.expectEqual(
        Result{ .index = 0, .item = 'h' },
        it.nextResult(),
    );

    try testing.expectEqual(
        Result{ .index = 1, .item = 'e' },
        it.peekResult(),
    );

    try testing.expectEqual(
        Result{ .index = 2, .item = 'l' },
        it.peekResultN(2),
    );

    try testing.expectEqual(
        Result{ .index = 3, .item = 'l' },
        it.peekResultN(3),
    );

    it.skip();

    try testing.expectEqual(
        Result{ .index = 2, .item = 'l' },
        it.peekResult(),
    );

    try testing.expectEqual(
        Result{ .index = 3, .item = 'l' },
        it.peekResultN(2),
    );

    try testing.expectEqual(
        Result{ .index = 4, .item = 'o' },
        it.peekResultN(3),
    );

    it.skipN(10);

    try testing.expectEqual(
        Result{ .index = 12, .item = '!' },
        it.peekResult(),
    );

    try testing.expectEqual(
        Result{ .index = 12, .item = '!' },
        it.nextResult(),
    );

    try testing.expectEqual(
        Result{ .index = 13, .item = null },
        it.peekResult(),
    );

    try testing.expectEqual(
        Result{ .index = 14, .item = null },
        it.peekResultN(2),
    );

    try testing.expectEqual(
        Result{ .index = 15, .item = null },
        it.peekResultN(3),
    );

    it.index = 0;

    try testing.expectEqual(
        Result{ .index = 12, .item = '!' },
        it.peekResultN(13),
    );

    it.skipN(13);

    try testing.expectEqual(
        Result{ .index = 13, .item = null },
        it.peekResult(),
    );

    try testing.expectEqual(
        Result{ .index = 13, .item = null },
        it.nextResult(),
    );
}
