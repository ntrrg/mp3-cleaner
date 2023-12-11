/// If `val` has a method `.asLog`, it will be used instead of default
/// encoding. This method must be of the following type:
///
/// ```zig
/// pub fn asLog(_: T, log: anytype, comptime key: []const u8) void
/// ```
pub fn encode(log: anytype, comptime key: []const u8, val: anytype) void {
    const T = @TypeOf(val);

    if (comptime funcs.hasFn(T, "asLog")) {
        val.asLog(log, key);
        return;
    }

    const value_ti = @typeInfo(T);

    if (key.len > 0 and value_ti != .Struct and value_ti != .Union)
        log.write(key ++ "=");

    const w = log.stdWriter();

    switch (value_ti) {
        .Bool => {
            log.write(if (val) "true" else "false");
        },

        .Int, .ComptimeInt, .Float, .ComptimeFloat => {
            std.fmt.format(w, "{d:.4}", .{val}) catch unreachable;
        },

        .Enum, .EnumLiteral => {
            log.write("\"");
            log.write(@tagName(val));
            log.write("\"");
        },

        .Struct => |struct_ti| {
            inline for (struct_ti.fields, 0..) |field, i| {
                if (i > 0) log.write(" ");

                encode(
                    log,
                    key ++ "." ++ field.name,
                    @field(val, field.name),
                );
            }
        },

        .Union => |union_ti| {
            if (union_ti.tag_type) |_| {
                switch (val) {
                    inline else => |v| {
                        encode(log, key, v);
                    },
                }
            } else {
                std.fmt.format(w, "\"{any}\"", .{val}) catch unreachable;
            }
        },

        .Pointer => |ptr_ti| {
            if (ptr_ti.size == .Slice) {
                if (ptr_ti.is_const and ptr_ti.child == u8 and std.unicode.utf8ValidateSlice(val)) {
                    log.write("\"");
                    log.write(val);
                    log.write("\"");
                } else {
                    log.write("[");

                    for (val, 0..) |item, i| {
                        if (i > 0) log.write(", ");
                        encode(log, "", item);
                    }

                    log.write("]");
                }
            } else {
                std.fmt.format(w, "\"{*}\"", .{val}) catch unreachable;
            }
        },

        .Optional => {
            if (val) |v| {
                encode(log, "", v);
            } else {
                log.write("null");
            }
        },

        .ErrorUnion => {
            if (val) |v| {
                encode(log, "", v);
            } else |e| {
                encode(log, "", e);
            }
        },

        .ErrorSet => {
            log.write("\"");
            log.write(@errorName(val));
            log.write("\"");
        },

        .Void => {
            log.write("void");
        },

        .Type => {
            log.write("\"");
            log.write(@typeName(val));
            log.write("\"");
        },

        else => {
            std.fmt.format(w, "\"{any}\"", .{val}) catch unreachable;
        },
    }
}
