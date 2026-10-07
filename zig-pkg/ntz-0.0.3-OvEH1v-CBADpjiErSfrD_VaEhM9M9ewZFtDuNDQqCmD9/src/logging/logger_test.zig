// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const encoding = ntz.encoding;
const ctxlog = encoding.ctxlog;
const types = ntz.types;
const bytes = types.bytes;

const logging = ntz.logging;

test "ntz.logging.Logger" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var buf_writer = buf.writer().toStd(&.{});
    var w = &buf_writer.interface;
    _ = &w;

    var field_name_buf: [32]u8 = undefined;
    const e = ctxlog.Encoder.init(&field_name_buf);

    const log = logging.logger(w, e, struct {
        level: []const u8,

        http: ?struct {
            request: ?struct {
                method: []const u8,
                url: []const u8,
            },

            response: ?struct {
                status: u10,
            },
        },

        msg: []const u8,
        @"error": ?anyerror,
    }).withSeverity(.info);

    buf.clear();
    log.info("hello, world!");

    try testing.expectEqualStrings(
        "level=\"INFO\" msg=\"hello, world!\"\n",
        buf.bytes(),
    );

    // Severity.

    buf.clear();
    const warn_log = log.withSeverity(.warn);
    warn_log.info("hello, world!");

    try testing.expectEqualStrings("", buf.bytes());

    // Scoping

    buf.clear();
    const http_log = log.withScope("http");

    http_log
        .with("request.method", "GET")
        .with("request.url", "http://localhost/")
        .with("response.status", 200)
        .info("hello, request!");

    try testing.expectEqualStrings(
        "level=\"INFO\" http.request.method=\"GET\" http.request.url=\"http://localhost/\" http.response.status=200 msg=\"hello, request!\"\n",
        buf.bytes(),
    );

    // Non-generic methods.

    buf.clear();

    var ng_ctx = log.ctx;

    ng_ctx.http = .{
        .request = .{
            .method = "GET",
            .url = "http://localhost/",
        },

        .response = .{
            .status = 200,
        },
    };

    log.set(ng_ctx).info("hello, request!");

    try testing.expectEqualStrings(
        "level=\"INFO\" http.request.method=\"GET\" http.request.url=\"http://localhost/\" http.response.status=200 msg=\"hello, request!\"\n",
        buf.bytes(),
    );

    // onLog method.

    const timed_log = logging.logger(w, e, struct {
        const Self = @This();

        time: u64,
        level: []const u8,
        msg: []const u8,
        @"error": ?anyerror,

        pub fn onLog(ctx: Self) Self {
            var _ctx = ctx;
            _ctx.time = 42;
            return _ctx;
        }
    });

    buf.clear();
    timed_log.err("hello, timed log!");

    try testing.expectEqualStrings(
        "time=42 level=\"ERROR\" msg=\"hello, timed log!\"\n",
        buf.bytes(),
    );
}
