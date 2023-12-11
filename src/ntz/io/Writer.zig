// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! An interface that allows one to write bytes into.
//!
//! This interface is intended only for cases where dynamic dispatching is
//! required, for most cases, prefer static dispatching with anytype.

const Writer = @This();

ptr: *anyopaque,

vtable: *const struct {
    write: *const fn (ptr: *anyopaque, bytes: []const u8) anyerror!usize,
},

pub fn init(writer: anytype) Writer {
    const Type = @TypeOf(writer);

    comptime {
        const info = @typeInfo(Type);

        if (info != .Pointer)
            @compileError("writer must be a pointer");

        const info_ptr = info.Pointer;

        if (info_ptr.size != .One)
            @compileError("writer must be a single item pointer");

        if (info_ptr.is_const)
            @compileError("writer cannot be const, use var");
    }

    const impl = struct {
        fn write(ptr: *anyopaque, bytes: []const u8) !usize {
            const w: Type = @ptrCast(@alignCast(ptr));
            return try w.write(bytes);
        }
    };

    return .{
        .ptr = writer,

        .vtable = &.{
            .write = impl.write,
        },
    };
}

pub fn write(w: Writer, bytes: []const u8) !usize {
    return w.vtable.write(w.ptr, bytes);
}
