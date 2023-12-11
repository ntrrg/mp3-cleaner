// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const builtin = @import("builtin");
const std = @import("std");

const ntz = @import("ntz");
const io_utils = ntz.io;
const logging = ntz.logging;

const Options = @import("Options.zig");
const cleaner = @import("cleaner/root.zig");

pub var global_status = ntz.Status{ .io = std.Options.debug_io };
pub const global_log = logging.init();

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const allocator = init.gpa;

    // ////////////////////
    // State propagation //
    // ////////////////////

    global_status.io = io;

    const status = global_status.sub(allocator) catch |err| {
        const msg = "cannot setup status propagation";
        global_log.withError(err).err(msg);
        return err;
    };

    defer global_status.deinit(allocator);

    // /////////////
    // OS Signals //
    // /////////////

    if (comptime builtin.target.os.tag != .windows) {
        var sa: std.posix.Sigaction = .{
            .handler = .{ .sigaction = signalHandler },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };

        std.posix.sigaction(std.posix.SIG.INT, &sa, null);
        std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
    }

    // //////
    // CLI //
    // //////

    const opts = blk: {
        var arena_allocator = std.heap.ArenaAllocator.init(allocator);
        defer arena_allocator.deinit();
        const arena = arena_allocator.allocator();

        var cmd = try Options.command(io, arena, status, global_log);
        //defer allocator.destroy(cmd);
        //defer cmd.deinit();

        var opts = Options{};

        _ = cmd.fromInit(arena, &opts, init) catch |err| {
            const msg = "cannot load option entries from the OS";
            global_log.withError(err).err(msg);
            return err;
        };

        break :blk opts.clone(allocator) catch |err| {
            const msg = "cannot finish reading options";
            global_log.withError(err).err(msg);
            return err;
        };
    };

    defer opts.deinit(allocator);

    // //////////
    // Logging //
    // //////////

    // File //

    const log_file: std.Io.File = blk: {
        if (opts.log.file.len == 0) break :blk std.Io.File.stderr();

        const name = opts.log.file;
        const cwd = std.Io.Dir.cwd();

        const file = cwd.openFile(io, name, .{ .mode = .write_only }) catch |err| file_blk: {
            if (err != std.Io.File.OpenError.FileNotFound) {
                const msg = "cannot open log file '{s}'";
                global_log.withError(err).errf(allocator, msg, .{name});
                return err;
            }

            break :file_blk cwd.createFile(io, name, .{}) catch |create_err| {
                const msg = "cannot create log file '{s}'";
                global_log.withError(create_err).errf(allocator, msg, .{name});
                return create_err;
            };
        };

        break :blk file;
    };

    defer log_file.close(io);

    // Writer //

    const log_file_size = log_file.length(io) catch |err| {
        const msg = "cannot get log file size";
        global_log.withError(err).err(msg);
        return err;
    };

    var log_file_writer = log_file.writer(io, &.{});
    defer log_file_writer.flush() catch {};

    log_file_writer.seekTo(log_file_size) catch |err| {
        const msg = "cannot go to the end of the log file";
        global_log.withError(err).err(msg);
        return err;
    };

    //var log_writer = &log_file_writer.interface;
    //_ = &log_writer;

    var log_writer_ln = io_utils.delimitedWriter(
        &log_file_writer.interface,
        allocator,
        "\n",
    );

    defer log_writer_ln.deinit();
    defer log_writer_ln.flush() catch {};

    var log_writer_ln_writer = log_writer_ln.writer().toStd(&.{});
    var log_writer = &log_writer_ln_writer.interface;
    _ = &log_writer;

    // Mutex //

    var log_mutex: std.Io.Mutex = .init;

    // Encoder //

    var log_field_name_buf: [32]u8 = undefined;

    const log_encoder = Options.LogEncoder{
        .format = opts.log.format,
        .ctxlog_enc = .init(&log_field_name_buf),
        .json_enc = .{},
    };

    // Logger //

    const log = blk: {
        var log = logging.logger(log_writer, log_encoder, Options.LogContext);
        if (!builtin.single_threaded) log.mux = &log_mutex;
        break :blk log.withSeverity(opts.log.level);
    };

    // ////////////////////////////////////////////////////////////////////////

    cleaner.cleanSeq(
        io,
        allocator,
        status,
        log,
        opts.bit_rate,
        opts.destination,
        opts.sources,
    ) catch |err| {
        log.withError(err).err("cannot clean files");
        return err;
    };

    return 0;
}

// /////////////
// OS Signals //
// /////////////

fn signalHandler(
    sig: std.posix.SIG,
    _: *const std.posix.siginfo_t,
    _: ?*anyopaque,
) callconv(.c) void {
    switch (sig) {
        std.posix.SIG.INT, std.posix.SIG.TERM => {
            const exit_code: u8 = 128 +| @as(u8, @intCast(@backingInt(sig)));

            if (global_status.isDone()) {
                std.process.exit(exit_code);
            } else {
                const msg = "terminating program... try again to force exit";
                global_log.warn(msg);
                global_status.done();
            }
        },

        else => {},
    }
}
