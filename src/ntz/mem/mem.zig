fn dupeDeep(comptime T: type, ally: mem.Allocator, m: T) !T {
    return switch (@typeInfo(T)) {
        .Pointer => |t| blk: {
            switch (t.size) {
                .Slice => {
                    const new = ally.alloc(T, m.len) catch |err| {
                        log.err("cannot allocate new slice: {}", .{err});
                        return err;
                    };

                    errdefer ally.free(new);

                    const is_pointer = switch (@typeInfo(t.child)) {
                        .Pointer => true,
                        else => false,
                    };

                    for (0..m.len) |i| {
                        new[i] = dupeDeep(t.child, ally, m[i]) catch |err| {
                            if (is_pointer and i > 0)
                                for (0..i) |j| ally.free(new[j]);

                            const msg = "cannot duplicate item {d} '{any}': {}";
                            log.err(msg, .{ i, m[i], err });
                            return err;
                        };
                    }

                    errdefer if (is_pointer) for (new) |item| ally.free(item);

                    break :blk new;
                },

                else => @compileError("not implemented"),
            }
        },

        .Array, .ErrorUnion, .Optional, .Struct, .Union => @compileError("not implemented"),
        else => m,
    };
}
