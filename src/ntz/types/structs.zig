// Copyright 2023 Miguel Angel Rivera Notararigo. All rights reserved.
// This source code was released under the MIT license.

//! # `ntz.types.structs`
//!
//! Utilities for working with structs.

const std = @import("std");

const bytes = @import("bytes.zig");

pub const Empty = struct {};

pub const Struct = std.builtin.Type.Struct;
pub const Layout = std.builtin.Type.ContainerLayout;
pub const Field = std.builtin.Type.StructField;
pub const Declaration = std.builtin.Type.Declaration;

/// Allows to create structs programmatically.
///
/// Use with caution, creating too many types is not a good for performance.
pub const Builder = struct {
    const Self = @This();

    layout: Layout = .Auto,
    is_tuple: bool = false,
    fields: []Field = undefined,
    fields_count: usize = 0,

    pub fn init(comptime capacity: []Field) Self {
        return .{ .fields = capacity };
    }

    pub fn initWith(comptime Base: type, comptime capacity: []Field) Self {
        const base_ti = @typeInfo(Base);

        if (base_ti != .Struct)
            @compileError("Base must be a struct, got `" ++ @typeName(Base) ++ "`");

        const struct_ti = base_ti.Struct;

        if (struct_ti.fields.len > capacity.len)
            @compileError("builder has not enough capacity for storing fields from `" ++ @typeName(Base) ++ "`");

        @memcpy(capacity[0..struct_ti.fields.len], struct_ti.fields);

        return .{
            .layout = struct_ti.layout,
            .is_tuple = struct_ti.is_tuple,
            .fields = capacity,
            .fields_count = struct_ti.fields.len,
        };
    }

    pub fn addField(comptime b: *Self, comptime field: anytype) void {
        if (b.fields_count >= b.fields.len)
            @compileError("builder has not enough capacity for storing new field");

        b.fields[b.fields_count] = toField(field);
        b.fields_count += 1;
    }

    pub fn addFields(comptime b: *Self, comptime fields: anytype) void {
        const new_fields = toFields(fields);

        if (b.fields_count + new_fields.len > b.fields.len)
            @compileError("builder has not enough capacity for storing new fields");

        inline for (0..new_fields.len) |i|
            b.fields[b.fields_count + i] = new_fields[i];

        b.fields_count += new_fields.len;
    }

    pub fn addFieldsFrom(comptime b: *Self, comptime T: type) void {
        const t_ti = @typeInfo(T);

        if (t_ti != .Struct)
            @compileError("T must be a struct, got `" ++ @typeName(T) ++ "`");

        const struct_ti = t_ti.Struct;
        const new_fields = struct_ti.fields;

        if (b.fields_count + new_fields.len > b.fields.len)
            @compileError("builder has not enough capacity for storing new fields from `" ++ @typeName(T) ++ "`");

        @memcpy(
            b.fields[b.fields_count .. b.fields_count + new_fields.len],
            new_fields,
        );

        b.fields_count += new_fields.len;
    }

    pub fn Type(comptime b: Self) type {
        return @Type(.{
            .Struct = .{
                .layout = b.layout,
                .fields = b.fields[0..b.fields_count],
                .decls = &.{},
                .is_tuple = b.is_tuple,
            },
        });
    }
};

/// Creates a new struct from `Base` with an extra field.
pub fn WithField(
    comptime Base: type,
    comptime name: []const u8,
    comptime T: type,
) type {
    const base_ti = @typeInfo(Base);

    if (base_ti != .Struct)
        @compileError("Base must be a struct, got `" ++ @typeName(Base) ++ "`");

    const struct_ti = base_ti.Struct;
    var cap: [struct_ti.fields.len + 1]Field = undefined;
    var b = Builder.initWith(Base, &cap);
    b.addField(.{ .name = name, .type = T });

    return b.Type();
}

/// Creates a new struct from `Base` with an extra field at the given field
/// path.
///
/// A field path is a list of fields separated by periods (`.`). All elements in
/// the field path must be structs.
pub fn WithFieldAt(
    comptime Base: type,
    comptime at: []const u8,
    comptime name: []const u8,
    comptime T: type,
) type {
    if (at.len == 0)
        return WithField(Base, name, T);

    var Type = Base;
    var base_ti = @typeInfo(Type);

    if (base_ti != .Struct)
        @compileError("Base must be a struct, got `" ++ @typeName(Base) ++ "`");

    var at_it = std.mem.splitScalar(u8, at, '.');
    const at_field = at_it.first();

    if (!@hasField(Type, at_field)) {
        Type = WithField(Type, at_field, Empty);
        base_ti = @typeInfo(Type);
    }

    const struct_ti = base_ti.Struct;
    const old_fields = struct_ti.fields;
    var new_fields: [old_fields.len]Field = undefined;

    inline for (old_fields, 0..) |field, i| {
        if (!bytes.eql(at_field, field.name)) {
            new_fields[i] = field;
            continue;
        }

        if (@typeInfo(field.type) != .Struct)
            @compileError("field `" ++ at_field ++ "` must be a struct, got `" ++ @typeName(field.type) ++ "`");

        new_fields[i] = .{
            .name = field.name,
            .type = WithFieldAt(field.type, at_it.rest(), name, T),
            .is_comptime = field.is_comptime,
            .alignment = field.alignment,
            .default_value = field.default_value,
        };
    }

    return @Type(.{
        .Struct = .{
            .layout = struct_ti.layout,
            .fields = new_fields[0..],
            .decls = struct_ti.decls,
            .is_tuple = struct_ti.is_tuple,
        },
    });
}

/// Creates a new struct from `Base` with an extra fields.
pub fn WithFields(comptime Base: type, comptime fields: anytype) type {
    const base_ti = @typeInfo(Base);

    if (base_ti != .Struct)
        @compileError("Base must be a struct, got `" ++ @typeName(Base) ++ "`");

    const struct_ti = base_ti.Struct;
    const new_fields = toFields(fields);
    var cap: [struct_ti.fields.len + new_fields.len]Field = undefined;
    var b = Builder.initWith(Base, &cap);
    b.addFields(new_fields);

    return b.Type();
}

/// Creates a value of `T` with all its values set to their zero value.
pub fn init(comptime T: type) T {
    return std.mem.zeroes(T);
}

/// Creates a value of `T` reusing values from matching fields in `values`.
///
/// If no matching field is found in `values`, their zero value will be used.
pub fn initWith(comptime T: type, values: anytype) T {
    return std.mem.zeroInit(T, values);
}

/// Sets the value of a field to a new value. This is equivalent to `x.a.b = X`,
/// but it cannot be done when the struct is generated programmatically.
///
/// A field path is a list of fields separated by periods (`.`). All elements in
/// the field path must be structs, except for the last one, which must be of a
/// type that can store `value`.
pub fn setField(
    orig: anytype,
    comptime at: []const u8,
    value: anytype,
) void {
    const T = @TypeOf(orig);
    const orig_ti = @typeInfo(T);

    if (orig_ti != .Pointer or @typeInfo(orig_ti.Pointer.child) != .Struct)
        @compileError("orig must be a pointer to a struct, got `" ++ @typeName(T) ++ "`");

    if (at.len == 0)
        @compileError("at cannot be empty");

    var new = orig.*;
    comptime var at_it = std.mem.splitScalar(u8, at, '.');
    const at_field = comptime at_it.first();

    if (comptime at_it.rest().len > 0) {
        setField(
            &@field(new, at_field),
            comptime at_it.rest(),
            value,
        );

        orig.* = new;
        return;
    }

    @field(new, at_field) = value;
    orig.* = new;
}

/// Converts a value into a proper `Field`. `value` has the following
/// constraints:
///
/// - `.name` must be of type `[]const u8` or any type that coerces to it.
/// - `.type` must be of type `type`.
/// - `.is_comptime` must be of type `bool`. (Optional)
/// - `.alignment` must be of type `comptime_int`. (Optional)
/// - `.default_value` must be of type `?*const anyopaque`. (Optional)
fn toField(comptime value: anytype) Field {
    const Value = @TypeOf(value);

    if (Value == Field)
        return value;

    const value_ti = @typeInfo(Value);

    if (value_ti != .Struct)
        @compileError("value must be a struct, got `" ++ @typeName(Value) ++ "`");

    return .{
        .name = value.name,
        .type = value.type,

        .is_comptime = if (@hasField(Value, "is_comptime"))
            value.is_comptime
        else
            false,

        .alignment = if (@hasField(Value, "alignment"))
            value.alignment
        else
            0,

        .default_value = if (@hasField(Value, "default_value"))
            value.default_value
        else
            null,
    };
}

/// Converts a series of values into a proper list of `Field`.
///
/// See `toField` function for more information about individual value rules.
fn toFields(comptime values: anytype) [values.len]Field {
    const Values = @TypeOf(values);
    const values_ti = @typeInfo(Values);

    // Check if it is already a valid list of `Field`.
    {
        if (values_ti == .Pointer)
            if (values_ti.Pointer.size == .Slice)
                if (values_ti.Pointer.child == Field)
                    return values.*;

        if (values_ti == .Array)
            if (values_ti.Array.child == Field)
                return values;
    }

    if (values_ti == .Struct and !values_ti.Struct.is_tuple)
        if (values_ti != .Array)
            if (values_ti == .Pointer and values_ti.Pointer.size != .Slice)
                @compileError("value must be a tuple, an array or a slice, got `" ++ @typeName(Values) ++ "`");

    var new_fields: [values.len]Field = undefined;
    inline for (0..values.len) |i| new_fields[i] = toField(values[i]);

    return new_fields;
}
