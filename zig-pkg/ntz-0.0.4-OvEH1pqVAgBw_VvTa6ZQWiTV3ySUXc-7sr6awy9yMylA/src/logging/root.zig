// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.logging`
//!
//! A logging API with support for multiple encoding formats, severity level,
//! scoping and type safety.

const std = @import("std");

const io_utils = @import("../io/root.zig");
const types = @import("../types/root.zig");
const bytes = types.bytes;

/// Represents the severity of a logging record.
pub const Level = enum {
    const Self = @This();

    /// Records intended to be read by developers.
    debug,

    /// Verbose records about the state of the program.
    info,

    /// Problems that doesn't interrupt the procedure execution.
    warn,

    /// Problems that interrupt the procedure execution.
    @"error",

    /// Problems that interrupt the program execution.
    fatal,

    /// Used to disable logging.
    disabled,

    pub fn key(lvl: Self) []const u8 {
        return switch (lvl) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .@"error" => "ERROR",
            .fatal => "FATAL",
            .disabled => "",
        };
    }

    pub const FromKeyError = error{
        InvalidSeverity,
    };

    pub fn fromKey(key_text: []const u8) FromKeyError!Self {
        if (bytes.equalAny(key_text, &.{ "debug", "DEBUG" })) return .debug;
        if (bytes.equalAny(key_text, &.{ "info", "INFO" })) return .info;
        if (bytes.equalAny(key_text, &.{ "warn", "WARN" })) return .warn;
        if (bytes.equalAny(key_text, &.{ "error", "ERROR" })) return .@"error";
        if (bytes.equalAny(key_text, &.{ "fatal", "FATAL" })) return .fatal;
        if (bytes.equalAny(key_text, &.{ "disabled", "DISABLED" })) return .disabled;
        return error.InvalidSeverity;
    }
};

pub const Logger = @import("logger.zig").Logger;
pub const logger = @import("logger.zig").init;

// /////////////////
// Default logger //
// /////////////////

/// Creates a simple logger using stderr as output.
pub fn init() DefaultLogger {
    return .{
        .w = defaultWriter,
        .e = .{},
    };
}

/// Creates a simple logger using the given writer as output.
pub fn initWith(writer: *std.Io.Writer) DefaultLogger {
    return .{
        .w = writer,
        .e = .{},
    };
}

pub const DefaultContext = struct {
    level: []const u8,
    msg: []const u8,
    @"error": ?anyerror,
};

pub const DefaultEncoder = struct {
    const Self = @This();

    pub fn encode(_: Self, writer: *std.Io.Writer, value: DefaultContext) !void {
        try writer.writeAll("[");
        try writer.writeAll(value.level);
        try writer.writeAll("] ");
        try writer.writeAll(value.msg);

        if (value.@"error") |err| {
            try writer.writeAll(": ");
            try writer.writeAll(@errorName(err));
        }
    }
};

pub const DefaultLogger = Logger(DefaultEncoder, DefaultContext, "");

pub const DefaultWriter = struct {
    const Self = @This();

    pub const Error = std.Io.Writer.Error;

    pub fn write(_: Self, data: []const u8) Error!usize {
        const stderr = std.debug.lockStderr(&.{});
        defer std.debug.unlockStderr();

        var w = &stderr.file_writer.interface;

        try w.writeAll(data);
        return data.len;
    }

    pub fn writer(_: Self) io_utils.Writer(Self, Error, write) {
        return .{ .writer = .{} };
    }
};

var _defaultWriter = (DefaultWriter{}).writer().toStd(&.{});
pub const defaultWriter = &_defaultWriter.interface;
