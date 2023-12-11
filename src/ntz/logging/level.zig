// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const types = @import("../types/types.zig");
const strings = types.strings;

/// Represents the severity of a logging record.
pub const Level = enum {
    const Error = error{
        UnkownValue,
    };

    /// Records intended to be read by developers.
    debug,

    /// Verbose records about the state of the program.
    info,

    /// Problems that doesn't interrupt the procedure execution.
    warn,

    /// Problems that interrupt the procedure execution.
    err,

    /// Problems that interrupt the program execution.
    fatal,

    /// Returns a string representation of the given level as it would be
    /// written in logging records.
    pub fn asKey(lvl: Level) []const u8 {
        return switch (lvl) {
            .debug => "DBG",
            .info => "INF",
            .warn => "WRN",
            .err => "ERR",
            .fatal => "FTL",
        };
    }

    // ///////////////////
    // Logging encoding //
    // ///////////////////

    pub fn asLog(lvl: Level, log: anytype, comptime key: []const u8) void {
        log.write(key ++ "=\"");
        log.write(lvl.asKey());
        log.write("\"");
    }

    // //////////////////
    // String encoding //
    // //////////////////

    /// Returns a string literal of the given level in full text form.
    pub fn asString(lvl: Level) []const u8 {
        return switch (lvl) {
            .debug => "debug",
            .info => "info",
            .warn => "warning",
            .err => "error",
            .fatal => "fatal",
        };
    }

    /// Returns an equivalent logging level from given string.
    pub fn fromString(txt: []const u8) !Level {
        if (strings.eqlAny(txt, &.{ "DBG", "debug", "dbg" }))
            return .debug;

        if (strings.eqlAny(txt, &.{ "INF", "info", "inf", "information" }))
            return .info;

        if (strings.eqlAny(txt, &.{ "WRN", "warning", "warn", "wrn" }))
            return .warn;

        if (strings.eqlAny(txt, &.{ "ERR", "error", "err" }))
            return .err;

        if (strings.eqlAny(txt, &.{ "FTL", "fatal", "ftl" }))
            return .fatal;

        return Error.UnkownValue;
    }
};
