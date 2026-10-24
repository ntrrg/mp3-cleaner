// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! A dynamic dispatch interface for writable streams.

const Self = @This();

ctx: *anyopaque,

vtable: *const struct {
    write: *const fn (ctx: *anyopaque, data: []const u8) anyerror!usize,
},

/// Creates a writable stream from the given implementation.
///
/// - `pub fn write(_: Self, data: []const u8) !usize`:
///
///   Must return the number of bytes processed, not the number of bytes
///   written. For example, a compression writer should return the number of
///   bytes it used from `data` during compression, not the resulting number of
///   bytes after compression.
pub fn init(writer: anytype) Self {
    const Writer = @TypeOf(writer);

    const impl = struct {
        fn write(ctx: *anyopaque, data: []const u8) !usize {
            const w: Writer = @ptrCast(@alignCast(ctx));
            return w.write(data);
        }
    };

    return .{
        .ctx = writer,

        .vtable = &.{
            .write = impl.write,
        },
    };
}

/// Writes the given data into the writable stream. Returns the number of
/// processed bytes, not the number of bytes written.
pub fn write(w: Self, data: []const u8) !usize {
    return w.vtable.write(w.ctx, data);
}
