// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const ntz = @import("ntz");
const testing = ntz.testing;

const Level = ntz.logging.Level;

test "ntz.logging.Level.asKey" {
    try testing.expectEqlStrs(Level.fatal.asKey(), "FTL");
    try testing.expectEqlStrs(Level.err.asKey(), "ERR");
    try testing.expectEqlStrs(Level.warn.asKey(), "WRN");
    try testing.expectEqlStrs(Level.info.asKey(), "INF");
    try testing.expectEqlStrs(Level.debug.asKey(), "DBG");
}

test "ntz.logging.Level.asString" {
    try testing.expectEqlStrs(Level.fatal.asString(), "fatal");
    try testing.expectEqlStrs(Level.err.asString(), "error");
    try testing.expectEqlStrs(Level.warn.asString(), "warning");
    try testing.expectEqlStrs(Level.info.asString(), "info");
    try testing.expectEqlStrs(Level.debug.asString(), "debug");
}

test "ntz.logging.Level.fromString" {
    try testing.expectEql(try Level.fromString("FTL"), .fatal);
    try testing.expectEql(try Level.fromString("fatal"), .fatal);
    try testing.expectEql(try Level.fromString("ftl"), .fatal);

    try testing.expectEql(try Level.fromString("ERR"), .err);
    try testing.expectEql(try Level.fromString("error"), .err);
    try testing.expectEql(try Level.fromString("err"), .err);

    try testing.expectEql(try Level.fromString("WRN"), .warn);
    try testing.expectEql(try Level.fromString("warning"), .warn);
    try testing.expectEql(try Level.fromString("warn"), .warn);
    try testing.expectEql(try Level.fromString("wrn"), .warn);

    try testing.expectEql(try Level.fromString("INF"), .info);
    try testing.expectEql(try Level.fromString("info"), .info);
    try testing.expectEql(try Level.fromString("information"), .info);
    try testing.expectEql(try Level.fromString("inf"), .info);

    try testing.expectEql(try Level.fromString("DBG"), .debug);
    try testing.expectEql(try Level.fromString("debug"), .debug);
    try testing.expectEql(try Level.fromString("dbg"), .debug);
}
