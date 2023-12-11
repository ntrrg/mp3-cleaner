// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const errors = @import("../types/errors.zig");

/// Creates a writer that implements the standard library writer interface.
pub fn init(writer: anytype) std.io.Writer(
    StdWriter(@TypeOf(writer)),
    StdWriter(@TypeOf(writer)).Error,
    StdWriter(@TypeOf(writer)).write,
) {
    return .{ .context = .{ .writer = writer } };
}

fn StdWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();
        pub const Error = errors.From(WriterType);

        writer: WriterType,

        pub fn write(std_w: Self, data: []const u8) Error!usize {
            _ = try std_w.writer.write(data);
            return data.len;
        }
    };
}
