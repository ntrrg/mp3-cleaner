// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

const std = @import("std");
const testing = std.testing;

const ntz = @import("ntz");
const types = ntz.types;
const bytes = types.bytes;

const ctxlog = ntz.encoding.ctxlog;

test "ntz.encoding.ctxlog" {
    const ally = testing.allocator;

    var buf = bytes.buffer(ally);
    defer buf.deinit();
    var buf_writer = buf.writer().toStd(&.{});
    var w = &buf_writer.interface;
    _ = &w;

    var field_name_buf: [32]u8 = undefined;
    var e = ctxlog.Encoder.init(&field_name_buf);

    // Booleans.

    try e.encode(w, true);
    try testing.expectEqualStrings("true", buf.bytes());
    buf.clear();

    try e.encode(w, false);
    try testing.expectEqualStrings("false", buf.bytes());
    buf.clear();

    // Numbers.

    try e.encode(w, 42);
    try testing.expectEqualStrings("42", buf.bytes());
    buf.clear();

    try e.encode(w, 42.42);
    try testing.expectEqualStrings("42.42", buf.bytes());
    buf.clear();

    // Enums.

    const Proficiency = enum {
        beginner,
        average,
        pro,
        god,
    };

    try e.encode(w, Proficiency.pro);
    try testing.expectEqualStrings("\"pro\"", buf.bytes());
    buf.clear();

    try e.encode(w, .other_proficiency);
    try testing.expectEqualStrings("\"other_proficiency\"", buf.bytes());
    buf.clear();

    // Strings, arrays, vectors and pointers.

    try e.encode(w, "");
    try testing.expectEqualStrings("\"\"", buf.bytes());
    buf.clear();

    try e.encode(w, "hello, world!");
    try testing.expectEqualStrings("\"hello, world!\"", buf.bytes());
    buf.clear();

    try e.encode(w, "\"double quotes\" and 'single quotes'");
    try testing.expectEqualStrings("\"\\\"double quotes\\\" and 'single quotes'\"", buf.bytes());
    buf.clear();

    try e.encode(w, "new\nline");
    try testing.expectEqualStrings("\"new\\nline\"", buf.bytes());
    buf.clear();

    try e.encode(w, "\"double quotes\"\n'single quotes'");
    try testing.expectEqualStrings("\"\\\"double quotes\\\"\\n'single quotes'\"", buf.bytes());
    buf.clear();

    try e.encode(w, "\xF0\xFF\xFF\xFF");
    try testing.expectEqualStrings("[240, 255, 255, 255]", buf.bytes());
    buf.clear();

    try e.encode(w, [_]u8{});
    try testing.expectEqualStrings("\"\"", buf.bytes());
    buf.clear();

    try e.encode(w, [_]u8{ 'a', 'b', 'c' });
    try testing.expectEqualStrings("\"abc\"", buf.bytes());
    buf.clear();

    try e.encode(w, [_]u32{ 1, 2, 3 });
    try testing.expectEqualStrings("[1, 2, 3]", buf.bytes());
    buf.clear();

    try e.encode(w, @Vector(3, u8){ 'a', 'b', 'c' });
    try testing.expectEqualStrings("\"abc\"", buf.bytes());
    buf.clear();

    try e.encode(w, @Vector(3, u32){ 1, 2, 3 });
    try testing.expectEqualStrings("[1, 2, 3]", buf.bytes());
    buf.clear();

    const mpz: [*:0]const u8 = "hello, world!";
    try e.encode(w, mpz);
    try testing.expectEqualStrings("\"hello, world!\"", buf.bytes());
    buf.clear();

    const mpz32: [*:0]const u32 = &.{ 1, 2, 3, 0 };
    try e.encode(w, mpz32);
    try testing.expectEqualStrings("[1, 2, 3]", buf.bytes());
    buf.clear();

    var n: usize = 42;
    try e.encode(w, &n);
    try testing.expectEqualStrings("42", buf.bytes());
    buf.clear();

    const mp: [*]const u8 = "hello, world!";

    try testing.expectError(
        ctxlog.Encoder.Error.UnboundedPointer,
        e.encode(w, mp),
    );

    buf.clear();

    const cp: [*c]const u8 = "hello, world!";

    try testing.expectError(
        ctxlog.Encoder.Error.UnboundedPointer,
        e.encode(w, cp),
    );

    buf.clear();

    // Structs.

    const Skill = struct {
        name: []const u8,
        prof: Proficiency,
    };

    const Pet = struct {
        const Kind = enum {
            dog,
            cat,
        };

        name: []const u8,
        kind: Kind,
    };

    const Person = struct {
        name: []const u8,
        height: u8,
        skills: []const Skill = &.{},
        pet: ?Pet = null,
    };

    const skills: []const Skill = &.{
        .{ .name = "Zig", .prof = .beginner },
        .{ .name = "Go", .prof = .average },
        .{ .name = "Breathing", .prof = .pro },
        .{ .name = "Eating", .prof = .god },
    };

    var person: Person = .{
        .name = "Miguel Angel",
        .height = 187,
        .skills = skills,
    };

    try e.encode(w, person);
    try testing.expectEqualStrings("name=\"Miguel Angel\" height=187 skills=[name=\"Zig\" prof=\"beginner\", name=\"Go\" prof=\"average\", name=\"Breathing\" prof=\"pro\", name=\"Eating\" prof=\"god\"]", buf.bytes());
    buf.clear();

    e.options.omit_empty = false;
    e.options.omit_null = false;
    person.skills = &.{};
    try e.encode(w, person);
    try testing.expectEqualStrings("name=\"Miguel Angel\" height=187 skills=[] pet=null", buf.bytes());
    buf.clear();
    e.options.omit_empty = true;
    e.options.omit_null = true;
    person.skills = skills;

    person.pet = .{ .name = "Draka", .kind = .dog };

    try e.encode(w, person);
    try testing.expectEqualStrings("name=\"Miguel Angel\" height=187 skills=[name=\"Zig\" prof=\"beginner\", name=\"Go\" prof=\"average\", name=\"Breathing\" prof=\"pro\", name=\"Eating\" prof=\"god\"] pet.name=\"Draka\" pet.kind=\"dog\"", buf.bytes());
    buf.clear();

    person.pet.?.name = "";
    try e.encode(w, person);
    try testing.expectEqualStrings("name=\"Miguel Angel\" height=187 skills=[name=\"Zig\" prof=\"beginner\", name=\"Go\" prof=\"average\", name=\"Breathing\" prof=\"pro\", name=\"Eating\" prof=\"god\"] pet.kind=\"dog\"", buf.bytes());
    buf.clear();

    person.pet = null;
    person.skills = &.{};
    try e.encode(w, person);
    try testing.expectEqualStrings("name=\"Miguel Angel\" height=187", buf.bytes());
    buf.clear();

    // Unions.

    const Plane = struct {
        name: []const u8,
        altitude_max: u64,
    };

    const Vehicle = union(enum) {
        bike: void,
        car: u8,
        plane: Plane,
        ship: []const u8,
    };

    try e.encode(w, Vehicle.bike);
    try testing.expectEqualStrings("\"bike\"", buf.bytes());
    buf.clear();

    try e.encode(w, Vehicle{ .car = 42 });
    try testing.expectEqualStrings("42", buf.bytes());
    buf.clear();

    try e.encode(w, Vehicle{ .plane = .{ .name = "Some name", .altitude_max = 5000 } });
    try testing.expectEqualStrings("name=\"Some name\" altitude_max=5000", buf.bytes());
    buf.clear();

    const Driver = struct {
        person: Person,
        vehicle: Vehicle,
    };

    try e.encode(w, Driver{ .person = person, .vehicle = .bike });
    try testing.expectEqualStrings("person.name=\"Miguel Angel\" person.height=187 vehicle=\"bike\"", buf.bytes());
    buf.clear();

    try e.encode(w, Driver{ .person = person, .vehicle = .{ .car = 42 } });
    try testing.expectEqualStrings("person.name=\"Miguel Angel\" person.height=187 vehicle=42", buf.bytes());
    buf.clear();

    try e.encode(w, Driver{ .person = person, .vehicle = .{ .plane = .{ .name = "Some name", .altitude_max = 5000 } } });
    try testing.expectEqualStrings("person.name=\"Miguel Angel\" person.height=187 vehicle.name=\"Some name\" vehicle.altitude_max=5000", buf.bytes());
    buf.clear();

    person.skills = skills;
    person.pet = .{ .name = "Draka", .kind = .dog };
    try e.encode(w, Driver{ .person = person, .vehicle = .bike });
    try testing.expectEqualStrings("person.name=\"Miguel Angel\" person.height=187 person.skills=[name=\"Zig\" prof=\"beginner\", name=\"Go\" prof=\"average\", name=\"Breathing\" prof=\"pro\", name=\"Eating\" prof=\"god\"] person.pet.name=\"Draka\" person.pet.kind=\"dog\" vehicle=\"bike\"", buf.bytes());
    buf.clear();

    // Optionals.

    var optional: ?bool = null;

    try e.encode(w, optional);
    try testing.expectEqualStrings("null", buf.bytes());
    buf.clear();

    optional = true;

    try e.encode(w, optional);
    try testing.expectEqualStrings("true", buf.bytes());
    buf.clear();

    // Errors.

    const CtxlogTestingError = error{
        SomeError,
    };

    try e.encode(w, error.SomeError);
    try testing.expectEqualStrings("\"SomeError\"", buf.bytes());
    buf.clear();

    try e.encode(w, CtxlogTestingError.SomeError);
    try testing.expectEqualStrings("\"SomeError\"", buf.bytes());
    buf.clear();

    var may_err: CtxlogTestingError!bool = error.SomeError;

    try e.encode(w, may_err);
    try testing.expectEqualStrings("\"SomeError\"", buf.bytes());
    buf.clear();

    may_err = true;

    try e.encode(w, may_err);
    try testing.expectEqualStrings("true", buf.bytes());
    buf.clear();

    // Void.

    try e.encode(w, {});
    try testing.expectEqualStrings("null", buf.bytes());
    buf.clear();

    // Types.

    try e.encode(w, bool);
    try testing.expectEqualStrings("\"bool\"", buf.bytes());
    buf.clear();

    // Custom encoding.

    const Point = struct {
        const Self = @This();

        x: u8,
        y: u8,

        pub fn asCtxlog(
            p: Self,
            writer: *std.Io.Writer,
            enc: ctxlog.Encoder,
        ) !void {
            if (enc.options.field_name.len > 0) {
                _ = try writer.write(enc.options.field_name.items());
                _ = try writer.write("=");
            }

            _ = try writer.write("\"{");
            _ = try writer.write(" x: ");
            try enc.encode(writer, p.x);
            _ = try writer.write(", y: ");
            try enc.encode(writer, p.y);
            _ = try writer.write(" }\"");
        }
    };

    try e.encode(w, Point{ .x = 10, .y = 11 });
    try testing.expectEqualStrings("\"{ x: 10, y: 11 }\"", buf.bytes());
    buf.clear();

    const Line = struct {
        p1: Point,
        p2: Point,
    };

    try e.encode(w, Line{ .p1 = .{ .x = 10, .y = 11 }, .p2 = .{ .x = 20, .y = 21 } });
    try testing.expectEqualStrings("p1=\"{ x: 10, y: 11 }\" p2=\"{ x: 20, y: 21 }\"", buf.bytes());
    buf.clear();
}
