const std = @import("std");

const logging = @import("logging.zig");

pub fn main() !void {
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

    logging.init(1024, .{})
        .withLevel(.debug)
        .with(Point, "encoder", .{ .x = 10, .y = 11 })
        .withGroup("types")
        .with(bool, "bool", true)
        .with(i8, "i8", (1 << 7) - 1)
        .with(u8, "u8", (1 << 7) - 1)
        .with(i32, "i32", (1 << 31) - 1)
        .with(u32, "u32", (1 << 31) - 1)
        .with(f64, "f64", 0.12345)
        .with(?u8, "optional", 11)
        .with(?u8, "null", null)
        .with(anyerror!u8, "error_union_value", 11)
        .with(anyerror!u8, "error_union_error", LoggerTestingError.SomeError)
        .with(*const Person, "pointer", &person)
        .with(void, "void", void{})
        .with(LoggerTestingError, "error", LoggerTestingError.SomeError)
        .with(anyerror, "anyerror", LoggerTestingError.SomeError)
        .with(type, "type", u8)
        .withGroup("containers")
        .with(Person, "struct", person)
        .with(Proficiency, "enum", .beginner)
        .with(Vehicle, "union_void", .bike)
        .with(Vehicle, "union_number", .{ .car = 4 })
        .with(Vehicle, "union_struct", .{ .plane = .{ .name = "Airplane", .prof = .average } })
        .with([]const u8, "str", "hello")
        .with([]const u8, "str", "world")
        .with([]u8, "slice", @constCast(&numbers))
        .log(.debug, "hello from: {s}", .{"debug"});
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

    pub fn encodeLog(p: Self, log: anytype, comptime key: []const u8) void {
        log.write(key ++ "=\"{");
        log.write(" x: ");
        log.encode("", p.x);
        log.write(" y: ");
        log.encode("", p.y);
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
