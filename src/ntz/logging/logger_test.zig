// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");

const ntz = @import("ntz");
const testing = ntz.testing;

const logging = ntz.logging;

test "ntz.logging.Logger" {
    const ally = testing.allocator;

    var buf = std.ArrayList(u8).init(ally);
    defer buf.deinit();
    const w = buf.writer();
    var mutex: std.Thread.Mutex = .{};

    const Logger = logging.Logger("", @TypeOf(w), 1024, .{ .with_time = false });
    const logger: Logger = .{ .writer = w, .mutex = &mutex };
    const log = logger.withLevel(.debug);

    // ////////
    // Basic //
    // ////////

    buf.clearRetainingCapacity();

    // Check run-time known formatting args.
    var lvl = "debug";
    _ = &lvl;

    log.info("hello, world from: {s}!", .{lvl});

    try testing.expectEqlStrs(
        buf.items,
        "level=\"INF\" msg=\"hello, world from: debug!\"\n",
    );

    // ////////
    // No-op //
    // ////////

    buf.clearRetainingCapacity();

    const noop_log = log.noop();
    noop_log.fatal("hello from quiet logger", .{});
    try testing.expectEqlStrs(buf.items, "");

    // ////////////
    // Formating //
    // ////////////

    buf.clearRetainingCapacity();

    const person: Person = .{
        .name = "Miguel Angel",
        .height = 190,
        .skills = &.{
            .{ .name = "Zig", .prof = .beginner },
            .{ .name = "Go", .prof = .average },
            .{ .name = "Breathing", .prof = .pro },
            .{ .name = "Eating", .prof = .god },
        },
    };

    const numbers = [_]u8{ 'a', 'b', 'c' };

    log
        .with(Point, "encoder", .{ .x = 10, .y = 11 })
        .with(Person, "struct", person)
        .with(Proficiency, "enum", .beginner)
        .with(Vehicle, "union_void", .bike)
        .with(Vehicle, "union_number", .{ .car = 4 })
        .with(Vehicle, "union_struct", .{ .plane = .{ .name = "Airplane", .prof = .average } })
        .with([]const u8, "str", "hello")
        .withGroup("primitives")
        .with(bool, "bool", true)
        .with(i8, "i8", (1 << 7) - 1)
        .with(u8, "u8", (1 << 7) - 1)
        .with(i32, "i32", (1 << 31) - 1)
        .with(u32, "u32", (1 << 31) - 1)
        .with(f64, "f64", 0.12345)
        .with([]const u8, "str", "world")
        .with([]u8, "slice", @constCast(&numbers))
        .with(?u8, "optional", 11)
        .with(?u8, "null", null)
        .with(anyerror!u8, "error_union_value", 11)
        .with(anyerror!u8, "error_union_error", LoggerTestingError.SomeError)
        .with(void, "void", void{})
        .with(LoggerTestingError, "error", LoggerTestingError.SomeError)
        .with(anyerror, "anyerror", LoggerTestingError.SomeError)
        .with(type, "type", u8)
        .debug("hello, world!", .{});

    try testing.expectEqlStrs(
        buf.items,
        "encoder=\"{ x: 10 y: 11 }\" struct.name=\"Miguel Angel\" struct.height=190 struct.skills=[.name=\"Zig\" .prof=\"beginner\", .name=\"Go\" .prof=\"average\", .name=\"Breathing\" .prof=\"pro\", .name=\"Eating\" .prof=\"god\"] enum=\"beginner\" union_void=void union_number=4 union_struct.name=\"Airplane\" union_struct.prof=\"average\" str=\"hello\" primitives.bool=true primitives.i8=127 primitives.u8=127 primitives.i32=2147483647 primitives.u32=2147483647 primitives.f64=0.12345 primitives.str=\"world\" primitives.slice=[97, 98, 99] primitives.optional=11 primitives.null=null primitives.error_union_value=11 primitives.error_union_error=\"SomeError\" primitives.void=void primitives.error=\"SomeError\" primitives.anyerror=\"SomeError\" primitives.type=\"u8\" level=\"DBG\" msg=\"hello, world!\"\n",
    );
}

const LoggerTestingError = error{
    SomeError,
};

const Person = struct {
    name: []const u8,
    height: u8,
    skills: []const Skill,
};

const Point = struct {
    const Self = @This();

    x: u8,
    y: u8,

    pub fn asLog(p: Self, log: anytype, comptime key: []const u8) void {
        log.write(key ++ "=\"{");
        log.write(" x: ");
        logging.encode(log, "", p.x);
        log.write(" y: ");
        logging.encode(log, "", p.y);
        log.write(" }\"");
    }
};

const Proficiency = enum {
    beginner,
    average,
    pro,
    god,
};

const Skill = struct {
    name: []const u8,
    prof: Proficiency,
};

const Vehicle = union(enum) {
    bike: void,
    car: u8,
    plane: Skill,
    ship: []const u8,
};
