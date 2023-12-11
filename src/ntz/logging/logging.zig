// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.logging`
//!
//! A logging API with support for contextual logging, record severity and
//! scoping.

const std = @import("std");

pub const Level = @import("level.zig").Level;

const logger = @import("logger.zig");
pub const Logger = logger.Logger;
pub const Mode = logger.Mode;

pub const encode = @import("encoding.zig").encode;

/// Creates a comptime logger. Since this uses `@compileError`, it will
/// terminate compilation when it logs its first record.
pub fn comptimeLog(comptime buf_size: usize) Logger(
    "",
    void,
    buf_size,
    Mode.no_defaults(),
) {
    return .{ .writer = void{} };
}

/// Creates a logger using the standard error as log writer.
pub fn init(comptime buf_size: usize, comptime mode: Mode) Logger(
    "",
    std.fs.File,
    buf_size,
    mode,
) {
    return withWriter(
        std.io.getStdErr(),
        std.debug.getStderrMutex(),
        buf_size,
        mode,
    );
}

/// Creates a logger that logs nothing.
pub fn noop() Logger("", void, 0, Mode.noop()) {
    return .{ .writer = void{} };
}

/// Creates a logger using the given writer as log writer.
pub fn withWriter(
    writer: anytype,
    mutex: ?*std.Thread.Mutex,
    comptime buf_size: usize,
    comptime mode: Mode,
) Logger("", @TypeOf(writer), buf_size, mode) {
    return .{ .writer = writer, .mutex = mutex };
}
