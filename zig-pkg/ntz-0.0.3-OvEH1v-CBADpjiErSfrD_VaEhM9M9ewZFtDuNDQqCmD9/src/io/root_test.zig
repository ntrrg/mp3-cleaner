// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;
const errors = types.errors;

const io_utils = ntz.io;

test "ntz.io" {
    // Readers.
    //_ = @import("counting_reader_test.zig");

    // Writers.
    //_ = @import("DynWriter_test.zig");
    _ = @import("writer_test.zig");
    _ = @import("buffered_writer_test.zig");
    _ = @import("counting_writer_test.zig");
    _ = @import("delimited_writer_test.zig");
    _ = @import("limited_writer_test.zig");
}

// //////////
// Writers //
// //////////

fn SingleByteWriter(comptime T: type, comptime WriteError: type) type {
    return struct {
        const Self = @This();
        pub const Error = WriteError;

        writer: T,

        pub fn write(sbw: Self, data: []const u8) Error!usize {
            if (data.len == 0) return 0;
            return sbw.writer.write(data[0..1]);
        }
    };
}

pub fn singleByteWriter(writer: anytype) SingleByteWriter(
    @TypeOf(writer),
    errors.From(@TypeOf(writer)),
) {
    return .{ .writer = writer };
}

test "ntz.io.writeAll" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    const buf_writer = buf.writer();
    var cw = io_utils.countingWriter(buf_writer);

    const sbw = singleByteWriter(&cw);

    const in = "hello, world!";
    try io_utils.writeAll(sbw, in);
    try testing.expectEqualStrings(in, buf.bytes());
    try testing.expectEqual(13, cw.write_count);
    try testing.expectEqual(13, cw.byte_count);
}
